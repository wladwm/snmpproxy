use crate::config::Config;
use crate::hostdata::*;
use anyhow::Result;
use bytes::Bytes;
use futures::StreamExt;

use snmp::{asn1, AsnReader, SnmpMessageType};
use std::collections::HashMap;

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio_util::sync::CancellationToken;

pub struct SNMPProxyDispatcher {
    pub cfg: Arc<Config>,
    pub cancel: CancellationToken,
    pub send_socket: crate::spoof_socket::SpoofSocket,
    pub hosts: parking_lot::RwLock<
        HashMap<
            HostKey,
            (
                Arc<parking_lot::RwLock<HostStore>>,
                UnboundedSender<Query>,
                tokio::task::JoinHandle<Result<()>>,
                CancellationToken,
            ),
        >,
    >,
    pub blacklist: parking_lot::RwLock<HashMap<HostKey, Instant>>,
    pub socket: snmp::tokio_socket::SNMPSocket,
}

impl SNMPProxyDispatcher {
    pub async fn new(cfg: Arc<Config>, cancel: CancellationToken) -> Result<SNMPProxyDispatcher> {
        let send_socket = crate::spoof_socket::SpoofSocket::bind(&cfg.response).await?;
        //todo!("handle cfg.query");
        let socket = snmp::tokio_socket::SNMPSocket::new().await?;
        Ok(SNMPProxyDispatcher {
            cfg,
            cancel,
            send_socket,
            hosts: parking_lot::RwLock::new(HashMap::new()),
            blacklist: parking_lot::RwLock::new(HashMap::new()),
            socket,
        })
    }

    pub async fn process_packet(
        self: Arc<Self>,
        buf: bytes::Bytes,
        host_from: SocketAddrV4,
        host_to: SocketAddrV4,
    ) -> Result<()> {
        let seq = AsnReader::from_bytes(&buf).read_raw(asn1::TYPE_SEQUENCE)?;
        let mut rdr = AsnReader::from_bytes(seq);
        let version = rdr.read_asn_integer()?;
        if !(0..=1).contains(&version) {
            warn!(
                "Unsupported version {} from {} to {}",
                version, host_from, host_to
            );
            return Ok(());
        }
        let community = rdr.read_asn_octetstring()?;
        let ident = rdr.peek_byte()?;
        let message_type = snmp::SnmpMessageType::from_ident(ident)?;
        if message_type != SnmpMessageType::GetRequest
            && message_type != SnmpMessageType::GetNextRequest
            && message_type != SnmpMessageType::GetBulkRequest
        {
            warn!(
                "Unsupported message type {:?} from {} to {}",
                message_type, host_from, host_to
            );
            return Ok(());
        }

        let mut pack_pdu = AsnReader::from_bytes(rdr.read_raw(ident)?);
        let req_id = pack_pdu.read_asn_integer()?;
        if req_id < i32::min_value() as i64 || req_id > i32::max_value() as i64 {
            return Err(snmp::SnmpError::ValueOutOfRange.into());
        }

        let error_status = pack_pdu.read_asn_integer()?;
        if error_status < 0 || error_status > i32::max_value() as i64 {
            return Err(snmp::SnmpError::ValueOutOfRange.into());
        }

        let error_index = pack_pdu.read_asn_integer()?;
        if error_index < 0 || error_index > i32::max_value() as i64 {
            return Err(snmp::SnmpError::ValueOutOfRange.into());
        }

        if error_status != 0 || error_index != 0 {
            warn!(
                "Error status={} index={} from {} to {}",
                error_status, error_index, host_from, host_to
            );
            return Ok(());
        }
        let now = Instant::now();
        let hkey = HostKey::new(host_to, Bytes::copy_from_slice(community));

        if let Some(blk) = self.blacklist.read().get(&hkey).cloned() {
            if (now - blk) < self.cfg.blacklist_duration.dur() {
                return Ok(());
            }
        }
        if let Some(hostrec) = self.hosts.read().get(&hkey) {
            hostrec.1.send(Query::new(host_from, now, ident, buf))?;
            return Ok(());
        }
        let mut grd = self.hosts.write();
        match grd.get(&hkey) {
            Some(hostrec) => hostrec.1.send(Query::new(host_from, now, ident, buf))?,
            None => {
                let hst = Arc::new(parking_lot::RwLock::new(HostStore::new(hkey.clone())));
                let host = hst.clone();
                let (tx, rx) = unbounded_channel::<Query>();
                let slf = self.clone();
                let c_global = self.cancel.clone();
                let cnc = CancellationToken::new();
                let c_local = cnc.clone();
                let jh =
                    tokio::spawn(
                        async move { slf.process_host(rx, host, c_global, c_local).await },
                    );
                tx.send(Query::new(host_from, now, ident, buf))?;
                let res = (hst, tx, jh, cnc);
                grd.insert(hkey, res);
            }
        };
        Ok(())
    }
    fn blacklist_host(&self, hkey: HostKey) {
        if let Some(hst) = self.hosts.write().remove(&hkey) {
            hst.3.cancel();
        }
        self.blacklist.write().insert(hkey, Instant::now());
    }
    async fn process_query(
        self: Arc<Self>,
        host: Arc<parking_lot::RwLock<HostStore>>,
        session: Arc<tokio::sync::Mutex<snmp::tokio_socket::SNMPSession>>,
        global: CancellationToken,
        local: CancellationToken,
        query: Query,
    ) -> Result<()> {
        let seq = AsnReader::from_bytes(&query.body).read_raw(asn1::TYPE_SEQUENCE)?;
        let mut rdr = AsnReader::from_bytes(seq);
        let version = rdr.read_asn_integer()?;
        if !(0..=1).contains(&version) {
            return Ok(());
        }
        let community = rdr.read_asn_octetstring()?;
        let ident = rdr.peek_byte()?;
        let message_type = snmp::SnmpMessageType::from_ident(ident)?;
        if message_type != SnmpMessageType::GetRequest
            && message_type != SnmpMessageType::GetNextRequest
            && message_type != SnmpMessageType::GetBulkRequest
        {
            return Ok(());
        }

        let mut pack_pdu = AsnReader::from_bytes(rdr.read_raw(ident)?);
        let req_id = pack_pdu.read_asn_integer()?;
        if req_id < i32::min_value() as i64 || req_id > i32::max_value() as i64 {
            return Ok(());
        }

        let host_to = host.read().key.hostsocket;
        let mut nmb = [0u32; 128];

        let old = Instant::now() - self.cfg.cache_value_lifetime.dur();

        if message_type == SnmpMessageType::GetRequest {
            let error_status = pack_pdu.read_asn_integer()?;
            if error_status < 0 || error_status > i32::max_value() as i64 {
                return Ok(());
            }

            let error_index = pack_pdu.read_asn_integer()?;
            if error_index < 0 || error_index > i32::max_value() as i64 {
                return Ok(());
            }

            if error_status != 0 || error_index != 0 {
                return Ok(());
            }

            let varbind_bytes = pack_pdu.read_raw(asn1::TYPE_SEQUENCE)?;
            let vbs = snmp::Varbinds::from_bytes(varbind_bytes);
            let mut reply = Vec::<(Vec<u32>, snmp::Value)>::new();
            //session.getmulti(names, repeat, timeout)
            let mut to_query = Vec::<Vec<u32>>::new();
            for q in vbs {
                let oid = q.0.read_name(&mut nmb)?.to_vec();
                if let Some(v) = host.read().cache.get(&oid) {
                    if v.when < old {
                        to_query.push(oid);
                    }
                } else {
                    to_query.push(oid);
                }
            }
            if !to_query.is_empty() {
                debug!(
                    "Requesting get {} varbinds from {}",
                    to_query.len(),
                    host_to
                );
                let mut sguard = tokio::select! {
                    sg = session.lock() => sg,
                    _ = global.cancelled() => {
                        return Ok(())
                    },
                    _ = local.cancelled() => {
                        return Ok(())
                    }
                };
                // re-check after session lock
                let old = Instant::now() - self.cfg.cache_value_lifetime.dur();
                to_query.clear();
                for q in snmp::Varbinds::from_bytes(varbind_bytes) {
                    let oid = q.0.read_name(&mut nmb)?.to_vec();
                    if let Some(v) = host.read().cache.get(&oid) {
                        if v.when < old {
                            to_query.push(oid);
                        }
                    } else {
                        to_query.push(oid);
                    }
                }
                if !to_query.is_empty() {
                    match tokio::select! {
                            r = sguard
                            .getmulti(&to_query, self.cfg.snmp_repeat, self.cfg.snmp_timeout.dur()) => r,
                            _ = global.cancelled() => {
                                return Ok(())
                            },
                            _ = local.cancelled() => {
                                return Ok(())
                            }
                    } {
                        Err(e) => {
                            warn!("host {} snmp error {:?}", host_to, e);
                            if host.read().cache.is_empty() {
                                warn!("Blacklist host {}", host_to);
                                self.blacklist_host(host.read().key.clone());
                                return Ok(());
                            }
                        }
                        Ok(v) => {
                            if v.error_index == 0 && v.error_status == 0 {
                                host.write().write_varbinds(Instant::now(), v.varbinds());
                            }
                        }
                    }
                }
            }
            let mut rbuf = snmp::pdu::Buf::default();
            {
                let rgrg = host.read();
                let mut cnt = 0;
                for q in snmp::Varbinds::from_bytes(varbind_bytes) {
                    let oid = q.0.read_name(&mut nmb)?.to_vec();
                    if let Some(vl) = rgrg.cache.get(&oid) {
                        cnt += 1;
                        reply.push((oid, (&vl.value).into()));
                    } else {
                        reply.push((oid, snmp::Value::NoSuchObject));
                    }
                }
                debug!(
                    "use {} cached varbinds for reply from {} to {}",
                    cnt, host_to, query.src
                );
                snmp::pdu::build_response(
                    community,
                    req_id as i32,
                    &reply,
                    &mut rbuf,
                    (version + 1) as i32,
                );
            }
            let bf = bytes::Bytes::copy_from_slice(&rbuf);
            debug!("Send reply {} from {} to {}", bf.len(), host_to, query.src);
            if let Err(e) = self.send_socket.sendfromto(&host_to, &query.src, &bf).await {
                error!(
                    "Error sending reply from {} to {} - {:?}",
                    host_to, query.src, e
                );
            }
            return Ok(());
        }
        if message_type == SnmpMessageType::GetNextRequest {
            let error_status = pack_pdu.read_asn_integer()?;
            if error_status < 0 || error_status > i32::max_value() as i64 {
                return Ok(());
            }

            let error_index = pack_pdu.read_asn_integer()?;
            if error_index < 0 || error_index > i32::max_value() as i64 {
                return Ok(());
            }

            if error_status != 0 || error_index != 0 {
                return Ok(());
            }

            let varbind_bytes = pack_pdu.read_raw(asn1::TYPE_SEQUENCE)?;
            let mut vbs = snmp::Varbinds::from_bytes(varbind_bytes);
            let q = match vbs.next() {
                None => {
                    debug!("Empty getnext request from {} to {}", host_to, query.src);
                    return Ok(());
                }
                Some(v) => v,
            };
            let oid = q.0.read_name(&mut nmb)?.to_vec();
            if host
                .read()
                .cache
                .range((
                    std::ops::Bound::Excluded(oid.clone()),
                    std::ops::Bound::Unbounded,
                ))
                .next()
                .filter(|x| x.1.when > old)
                .is_none()
            {
                let mut sguard = tokio::select! {
                    r =session.lock() => r,
                    _ = global.cancelled() => {
                        return Ok(())
                    },
                    _ = local.cancelled() => {
                        return Ok(())
                    }
                };
                // re-check after session lock
                if host
                    .read()
                    .cache
                    .range((
                        std::ops::Bound::Excluded(oid.clone()),
                        std::ops::Bound::Unbounded,
                    ))
                    .next()
                    .filter(|x| x.1.when > old)
                    .is_none()
                {
                    debug!(
                        "Requesting getnext {:?} varbinds from {} reqid {}",
                        oid,
                        host_to,
                        sguard.last_req_id()
                    );
                    match tokio::select! {
                            r = sguard
                            .getnext(&oid, self.cfg.snmp_repeat, self.cfg.snmp_timeout.dur()) => r,
                            _ = global.cancelled() => {
                            return Ok(())
                        },
                        _ = local.cancelled() => {
                            return Ok(())
                        }
                    } {
                        Err(e) => {
                            warn!("host {} snmp error {:?}", host_to, e);
                            if host.read().cache.is_empty() {
                                warn!("Blacklist host {}", host_to);
                                self.blacklist_host(host.read().key.clone());
                                return Ok(());
                            }
                        }
                        Ok(v) => {
                            if v.error_index == 0 && v.error_status == 0 {
                                host.write().write_varbinds(Instant::now(), v.varbinds());
                            }
                        }
                    }
                }
            }
            let mut rbuf = snmp::pdu::Buf::default();
            {
                let mut reply = Vec::<(Vec<u32>, snmp::Value)>::new();
                let rd = host.read();
                if let Some((k, v)) = rd
                    .cache
                    .range((
                        std::ops::Bound::Excluded(oid.clone()),
                        std::ops::Bound::Unbounded,
                    ))
                    .next()
                {
                    debug!(
                        "Cached getnext {:?} - {:?} varbinds from {}",
                        oid, k, host_to
                    );
                    reply.push((k.clone(), (&v.value).into()));
                } else {
                    reply.push((oid.to_vec(), snmp::Value::EndOfMibView));
                };
                snmp::pdu::build_response(
                    community,
                    req_id as i32,
                    &reply,
                    &mut rbuf,
                    (version + 1) as i32,
                );
            }
            let bf = bytes::Bytes::copy_from_slice(&rbuf);
            debug!(
                "Send getnext reply {} from {} to {}",
                bf.len(),
                host_to,
                query.src
            );
            if let Err(e) = self.send_socket.sendfromto(&host_to, &query.src, &bf).await {
                error!(
                    "Error sending getnext reply from {} to {} - {:?}",
                    host_to, query.src, e
                );
            }
            return Ok(());
        }
        if message_type == SnmpMessageType::GetBulkRequest {
            let non_repeaters = pack_pdu.read_asn_integer()? as usize;
            let max_repetitions = pack_pdu.read_asn_integer()? as usize;
            let varbind_bytes = pack_pdu.read_raw(asn1::TYPE_SEQUENCE)?;
            let mut to_query_nr = Vec::<Vec<u32>>::new();
            let mut to_query_r = Vec::<Vec<u32>>::new();

            let vbs = snmp::Varbinds::from_bytes(varbind_bytes);
            for (n, q) in vbs.enumerate() {
                let oid = q.0.read_name(&mut nmb)?.to_vec();
                if n < non_repeaters {
                    if host.read().cache.get(&oid).is_none() {
                        to_query_nr.push(oid);
                    }
                } else if let Some((_, v)) = host
                    .read()
                    .cache
                    .range((
                        std::ops::Bound::Included(oid.clone()),
                        std::ops::Bound::Unbounded,
                    ))
                    .next()
                    .filter(|x| x.1.when > old)
                {
                    if v.repeaters < max_repetitions {
                        to_query_r.push(oid);
                    }
                } else {
                    to_query_r.push(oid);
                }
            }
            if !to_query_nr.is_empty() || !to_query_r.is_empty() {
                let mut sguard = tokio::select! {
                    r = session.lock() => r,
                    _ = global.cancelled() => {
                        return Ok(())
                    },
                    _ = local.cancelled() => {
                        return Ok(())
                    }
                };
                // re-check after session lock
                let old = Instant::now() - self.cfg.cache_value_lifetime.dur();
                to_query_nr.clear();
                to_query_r.clear();
                let vbs = snmp::Varbinds::from_bytes(varbind_bytes);
                for (n, q) in vbs.enumerate() {
                    let oid = q.0.read_name(&mut nmb)?.to_vec();
                    if n < non_repeaters {
                        if host.read().cache.get(&oid).is_none() {
                            to_query_nr.push(oid);
                        }
                    } else if let Some((_, v)) = host
                        .read()
                        .cache
                        .range((
                            std::ops::Bound::Included(oid.clone()),
                            std::ops::Bound::Unbounded,
                        ))
                        .next()
                        .filter(|x| x.1.when > old)
                    {
                        if v.repeaters < max_repetitions {
                            to_query_r.push(oid);
                        }
                    } else {
                        to_query_r.push(oid);
                    }
                }
                if !to_query_nr.is_empty() || !to_query_r.is_empty() {
                    let mut repeaters = to_query_r
                        .iter()
                        .cloned()
                        .zip(std::iter::repeat(max_repetitions))
                        .collect::<std::collections::BTreeMap<Vec<u32>, usize>>();
                    to_query_nr.append(&mut to_query_r);
                    match tokio::select! {
                        r = sguard
                        .getbulk(
                            &to_query_nr,
                            non_repeaters as u32,
                            max_repetitions as u32,
                            self.cfg.snmp_repeat,
                            self.cfg.snmp_timeout.dur(),
                        ) => r,
                        _ = global.cancelled() => {
                            return Ok(())
                        },
                        _ = local.cancelled() => {
                            return Ok(())
                        }
                    } {
                        Err(e) => {
                            warn!("host {} snmp error {:?}", host_to, e);
                            if host.read().cache.is_empty() {
                                warn!("Blacklist host {}", host_to);
                                self.blacklist_host(host.read().key.clone());
                                return Ok(());
                            }
                        }
                        Ok(v) => {
                            if v.error_index == 0 && v.error_status == 0 {
                                let when = Instant::now();
                                let mut hwr = host.write();
                                for q in v.varbinds() {
                                    let oid = match q.0.read_name(&mut nmb) {
                                        Err(e) => {
                                            warn!("Unable to read oid - {:?}", e);
                                            continue;
                                        }
                                        Ok(v) => v,
                                    };
                                    let value = match crate::value::Value::try_from(&q.1) {
                                        Ok(v) => v,
                                        Err(e) => {
                                            warn!(
                                                "Unable to convert value for oid {:?} - {:?}",
                                                oid, e
                                            );
                                            continue;
                                        }
                                    };
                                    let mut vl = CachedValue::new(value, when);
                                    match repeaters.get_mut(oid) {
                                        None => {}
                                        Some(v) => {
                                            vl.repeaters = *v;
                                            if *v > 0 {
                                                *v -= 1;
                                            }
                                        }
                                    }
                                    hwr.cache.insert(oid.to_vec(), vl);
                                }
                            }
                        }
                    };
                }
            }
            let mut rbuf = snmp::pdu::Buf::default();
            {
                let mut reply = Vec::<(Vec<u32>, snmp::Value)>::new();
                let rhost = host.read();
                let vbs = snmp::Varbinds::from_bytes(varbind_bytes);
                for (n, q) in vbs.enumerate() {
                    let oid = q.0.read_name(&mut nmb)?.to_vec();
                    if n < non_repeaters {
                        if let Some((k, v)) = rhost
                            .cache
                            .range((
                                std::ops::Bound::Included(oid.clone()),
                                std::ops::Bound::Unbounded,
                            ))
                            .next()
                        {
                            reply.push((k.clone(), (&v.value).into()));
                        }
                    } else {
                        for (k, v) in rhost
                            .cache
                            .range((
                                std::ops::Bound::Included(oid.clone()),
                                std::ops::Bound::Unbounded,
                            ))
                            .take(max_repetitions)
                        {
                            reply.push((k.clone(), (&v.value).into()));
                        }
                    }
                }
                snmp::pdu::build_response(
                    community,
                    req_id as i32,
                    &reply,
                    &mut rbuf,
                    (version + 1) as i32,
                );
            }
            let bf = bytes::Bytes::copy_from_slice(&rbuf);
            debug!(
                "Send getbulk reply {} from {} to {}",
                bf.len(),
                host_to,
                query.src
            );
            if let Err(e) = self.send_socket.sendfromto(&host_to, &query.src, &bf).await {
                error!(
                    "Error sending getbulk reply from {} to {} - {:?}",
                    host_to, query.src, e
                );
            }
            return Ok(());
        }
        Ok(())
    }
    async fn process_host(
        self: Arc<Self>,
        mut rx: UnboundedReceiver<Query>,
        host: Arc<parking_lot::RwLock<HostStore>>,
        global: CancellationToken,
        local: CancellationToken,
    ) -> Result<()> {
        let (host_to, community) = {
            let rhost = host.read();
            (rhost.key.hostsocket, rhost.key.community.clone())
        };
        let session = Arc::new(tokio::sync::Mutex::new(
            self.socket
                .session(hto /* host_to */, &community, 10, 2)
                .await?,
        ));
        let active_queries = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        while let Some(query) = tokio::select! {
            q = rx.recv() => q,
            _ = global.cancelled() => None,
            _ = local.cancelled() => None
        } {
            if active_queries.load(std::sync::atomic::Ordering::Relaxed)
                >= self.cfg.max_parallel_queries_per_host
            {
                warn!("Throttling for host {}", host_to);
                continue;
            }
            let c_host = host.clone();
            let c_session = session.clone();
            let c_global = global.clone();
            let c_local = local.clone();
            let slf = self.clone();
            active_queries.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let c_aq = active_queries.clone();
            tokio::spawn(async move {
                if let Err(e) = slf
                    .process_query(c_host, c_session, c_global, c_local, query)
                    .await
                {
                    warn!("Process host {} query error: {:?}", host_to, e);
                }
                c_aq.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            });
        }
        Ok(())
    }
}
