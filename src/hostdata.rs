use bytes::Bytes;
use std::collections::BTreeMap;
use std::net::SocketAddrV4;
use std::time::Instant;

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct HostKey {
    pub hostsocket: SocketAddrV4,
    pub community: Bytes,
}
impl HostKey {
    pub fn new(hostsocket: SocketAddrV4, community: Bytes) -> HostKey {
        HostKey {
            hostsocket,
            community,
        }
    }
}

pub struct Query {
    pub src: SocketAddrV4,
    pub when: Instant,
    pub ident: u8,
    pub body: Bytes,
}
impl Query {
    pub fn new(src: SocketAddrV4, when: Instant, ident: u8, body: Bytes) -> Query {
        Query {
            src,
            when,
            ident,
            body,
        }
    }
}

pub struct CachedValue {
    pub when: Instant,
    pub value: crate::value::Value,
    pub repeaters: usize,
}
impl CachedValue {
    pub fn new(value: crate::value::Value, when: Instant) -> CachedValue {
        CachedValue {
            when,
            value,
            repeaters: 0,
        }
    }
}
pub struct HostStore {
    pub key: HostKey,
    pub cache: BTreeMap<Vec<u32>, CachedValue>,
}
impl HostStore {
    pub fn new(key: HostKey) -> HostStore {
        HostStore {
            key,
            cache: BTreeMap::new(),
        }
    }
    pub fn write_varbinds(&mut self, when: Instant, varbinds: snmp::Varbinds<'_>) {
        let mut nmb = [0u32; 128];
        for q in varbinds {
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
                    warn!("Unable to convert value for oid {:?} - {:?}", oid, e);
                    continue;
                }
            };
            self.cache
                .insert(oid.to_vec(), CachedValue::new(value, when));
        }
    }
}
