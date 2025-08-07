use anyhow::{Context, Result};
use socket2::{Domain, Socket, Type};
use std::net::{Ipv4Addr, SocketAddrV4};
#[cfg(unix)]
use std::os::unix::io::{FromRawFd, IntoRawFd};
#[cfg(windows)]
use std::os::windows::io::{FromRawSocket, IntoRawSocket};
use tokio::net::UdpSocket;

pub struct SpoofSocket {
    socket: UdpSocket,
    ident: std::sync::atomic::AtomicU16,
    mtu: u16,
}
#[repr(C, packed(1))]
struct UdpHdr {
    iph_ver: u8, //0x45
    iph_tos: u8,
    iph_len: u16,
    iph_ident: u16,
    iph_offset_flags: u16,
    iph_ttl: u8,
    iph_protocol: u8,
    iph_chksum: u16,
    iph_sourceip: u32,
    iph_destip: u32,
    udph_srcport: u16,
    udph_dstport: u16,
    udph_len: u16,
    udph_cksum: u16,
}
#[repr(C, packed(1))]
struct UdpPsdHdr {
    iph_sourceip: u32,
    iph_destip: u32,
    ph_res0: u8,
    ph_proto: u8,
    ph_len: u16,
}

#[derive(Default)]
struct Checksum16 {
    sum: u32,
    leftover: Option<u8>,
}

impl Checksum16 {
    fn append(&mut self, buf: &[u8]) {
        let mut b16 = buf.as_ptr() as *const u16;
        for _ in 0..(buf.len() / 2) {
            unsafe {
                self.sum += *b16 as u32;
                b16 = b16.offset(1);
            }
        }
        if (buf.len() & 1) == 1 {
            self.leftover = Some(buf[buf.len() - 1]);
        }
    }
    fn done(&mut self) -> u16 {
        if let Some(l) = self.leftover.take() {
            self.sum += l as u32;
        }
        let mut sum = (self.sum >> 16) + (self.sum & 0xFFFF);
        sum += sum >> 16;
        !(sum as u16)
    }
}
impl UdpHdr {
    fn to_pseudo_header(&self, phdr: &mut UdpPsdHdr) {
        phdr.iph_sourceip = self.iph_sourceip;
        phdr.iph_destip = self.iph_destip;
        phdr.ph_res0 = 0;
        phdr.ph_proto = self.iph_protocol;
    }
    fn calc_ipchecksum(&mut self, packet: &[u8]) {
        self.iph_chksum = 0;
        let mut cks = Checksum16::default();
        cks.append(&packet[0..20]);
        self.iph_chksum = cks.done();
    }
}
fn cut8(a: usize) -> usize {
    if a <= 8 {
        a
    } else {
        a & 0xfffffff8
    }
}
impl SpoofSocket {
    pub async fn bind(cfg: &crate::config::SocketConfig) -> Result<SpoofSocket> {
        let mut sock2 = Socket::new(Domain::IPV4, Type::RAW, Some(socket2::Protocol::UDP))
            .context("SpoofSocket::bind")?;
        sock2.set_header_included_v4(true)?;
        sock2.set_nonblocking(true)?;
        #[cfg(target_os = "linux")]
        if let Some(dv) = cfg.bind_device.as_ref() {
            sock2.bind_device(Some(dv.as_bytes()))?;
        }
        #[cfg(target_os = "freebsd")]
        if let Some(fib) = cfg.fib {
            sock2.set_fib(fib)?;
        }
        let sraw;
        #[cfg(windows)]
        {
            sraw = sock2.into_raw_socket();
        }
        #[cfg(unix)]
        {
            sraw = sock2.into_raw_fd();
        }
        #[cfg(unix)]
        unsafe {
            let v = 1u32;
            let scko = libc::setsockopt(
                sraw,
                libc::IPPROTO_IP,
                libc::IP_NODEFRAG,
                (&v as *const u32).cast(),
                std::mem::size_of_val(&v) as libc::socklen_t,
            );
            if scko != 0 {
                warn!("setsockopt IP_NODEFRAG error");
            }
        }
        if cfg.bind_port != 0 || cfg.bind_address != Ipv4Addr::UNSPECIFIED {
            #[cfg(windows)]
            {
                sock2 = unsafe { socket2::Socket::from_raw_socket(sraw) };
            }
            #[cfg(unix)]
            {
                sock2 = unsafe { socket2::Socket::from_raw_fd(sraw) };
            }
            let addr = socket2::SockAddr::from(SocketAddrV4::new(cfg.bind_address, cfg.bind_port));
            sock2.bind(&addr)?;
            #[cfg(windows)]
            {
                _ = sock2.into_raw_socket();
            }
            #[cfg(unix)]
            {
                _ = sock2.into_raw_fd();
            }
        }
        let socket;
        #[cfg(windows)]
        {
            socket = unsafe { std::net::UdpSocket::from_raw_socket(sraw) };
        }
        #[cfg(unix)]
        {
            socket = unsafe { std::net::UdpSocket::from_raw_fd(sraw) };
        }
        Ok(SpoofSocket {
            socket: UdpSocket::from_std(socket)?,
            ident: std::sync::atomic::AtomicU16::new(1),
            mtu: 1500,
        })
    }
    pub async fn sendfromto(
        &self,
        from: &SocketAddrV4,
        to: &SocketAddrV4,
        buf: &[u8],
    ) -> Result<()> {
        if buf.len() > 65535 {
            return Err(anyhow!("Too big packet size {}", buf.len()));
        }
        let mut pbuf = Vec::<u8>::with_capacity(self.mtu as usize);
        pbuf.resize(self.mtu as usize, 0);
        let hdr = unsafe { &mut *(pbuf.as_mut_ptr() as *mut UdpHdr) };
        hdr.iph_ver = 0x45;
        hdr.iph_tos = 0;
        //hdr.iph_len = ((std::mem::size_of::<UdpHdr>() + buf.len()) as u16).to_be();
        hdr.iph_ident = self
            .ident
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            .to_be();
        hdr.iph_offset_flags = 0;
        hdr.iph_ttl = 255;
        hdr.iph_protocol = 17;
        hdr.iph_chksum = 0;
        hdr.iph_sourceip = u32::from_le_bytes(from.ip().octets());
        hdr.iph_destip = u32::from_le_bytes(to.ip().octets());
        hdr.udph_srcport = from.port().to_be();
        hdr.udph_dstport = to.port().to_be();
        hdr.udph_len = ((buf.len() + 8) as u16).to_be(); //(std::cmp::min(buf.len() + 8, (self.mtu as usize) - 28) as u16).to_be();
        hdr.udph_cksum = 0;
        let mut phd = [0u8; std::mem::size_of::<UdpPsdHdr>()];
        let phdr = unsafe { &mut *(phd.as_mut_ptr() as *mut UdpPsdHdr) };
        hdr.to_pseudo_header(phdr);
        phdr.ph_len = hdr.udph_len;
        let mut cks = Checksum16::default();
        cks.append(&phd);
        cks.append(&pbuf[20..28]);
        cks.append(buf);
        hdr.udph_cksum = cks.done();
        let fragsize = cut8((self.mtu as usize) - std::mem::size_of::<UdpHdr>());
        let mut pos = 0usize;
        while pos < buf.len() {
            let chunk_len = std::cmp::min(buf.len() - pos, fragsize);
            pbuf.as_mut_slice()
                [std::mem::size_of::<UdpHdr>()..(std::mem::size_of::<UdpHdr>() + chunk_len)]
                .clone_from_slice(&buf[pos..(pos + chunk_len)]);
            let totlen = std::mem::size_of::<UdpHdr>() + chunk_len;
            hdr.iph_offset_flags = (((pos >> 3) as u16)
                | if (pos + chunk_len) < buf.len() {
                    0x2000
                } else {
                    0
                })
            .to_be();
            hdr.iph_len = (totlen as u16).to_be();
            hdr.calc_ipchecksum(&pbuf);
            let n = self
                .socket
                .send_to(&pbuf.as_slice()[0..totlen], *to)
                .await?;
            if n != totlen {
                warn!("send_to sent {}<{}", n, totlen);
            }
            pos += chunk_len;
        }
        Ok(())
    }
}
