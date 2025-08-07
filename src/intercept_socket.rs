use crate::config;
use mio::{Events, Interest, Poll, Token};
use socket2::{Domain, Socket, Type};
use std::io::{Error, ErrorKind};
use std::net::{Ipv4Addr, SocketAddrV4};
#[cfg(unix)]
use std::os::unix::io::{FromRawFd, IntoRawFd};
#[cfg(windows)]
use std::os::windows::io::{FromRawSocket, IntoRawSocket};
#[cfg(windows)]
use std::ptr::null_mut;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::WSAIoctl;

pub struct IUdpSocket {
    socket: Option<mio::net::UdpSocket>,
    bound: SocketAddrV4,
    #[cfg(unix)]
    socket_raw: i32,
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    socket_raw: u64,
    #[cfg(all(target_os = "windows", target_arch = "x86"))]
    socket_raw: u32,
    #[cfg(windows)]
    wsarecvmsg: windows_sys::Win32::Networking::WinSock::LPFN_WSARECVMSG,
}
#[cfg(unix)]
pub(crate) fn sys_errno() -> libc::c_int {
    let errno = unsafe {
        let ptr;
        #[cfg(target_os = "linux")]
        {
            ptr = libc::__errno_location();
        }
        #[cfg(target_os = "freebsd")]
        {
            ptr = libc::__error();
        }
        if ptr.is_null() {
            return -1;
        }
        *ptr
    };
    errno
}
impl Default for IUdpSocket {
    fn default() -> Self {
        Self::new()
    }
}

impl IUdpSocket {
    pub fn new() -> Self {
        Self {
            socket: None,
            bound: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
            socket_raw: 0,
            #[cfg(windows)]
            wsarecvmsg: None,
        }
    }
    pub fn create(&mut self) -> std::io::Result<()> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(socket2::Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        #[cfg(unix)]
        socket.set_reuse_port(true)?;
        socket.set_broadcast(true)?;
        socket.set_multicast_loop_v4(true)?;
        socket.set_nonblocking(true)?;
        #[cfg(windows)]
        {
            self.socket_raw = socket.into_raw_socket();
        }
        #[cfg(unix)]
        {
            self.socket_raw = socket.into_raw_fd();
        }
        #[cfg(unix)]
        unsafe {
            let v = 1u32;
            let scko = libc::setsockopt(
                self.socket_raw,
                libc::IPPROTO_IP,
                libc::IP_TRANSPARENT,
                (&v as *const u32).cast(),
                std::mem::size_of_val(&v) as libc::socklen_t,
            );
            if scko != 0 {
                let errno = sys_errno();
                warn!(
                    "setsockopt IP_TRANSPARENT error {:?}",
                    std::io::Error::from_raw_os_error(errno)
                );
            }
        }
        #[cfg(unix)]
        unsafe {
            let v = 1u32;
            let scko = libc::setsockopt(
                self.socket_raw,
                libc::IPPROTO_IP,
                libc::IP_RECVORIGDSTADDR,
                (&v as *const u32).cast(),
                std::mem::size_of_val(&v) as libc::socklen_t,
            );
            if scko != 0 {
                let errno = sys_errno();
                warn!(
                    "setsockopt IP_RECVORIGDSTADDR error {:?}",
                    std::io::Error::from_raw_os_error(errno)
                );
            }
        }
        let scko: i32;
        #[cfg(windows)]
        unsafe {
            let v = 1u32;
            scko = winapi::um::winsock2::setsockopt(
                self.socket_raw as usize,
                windows_sys::Win32::Networking::WinSock::IPPROTO_IP,
                windows_sys::Win32::Networking::WinSock::IP_PKTINFO,
                &v as *const u32 as *const i8,
                std::mem::size_of::<u32>() as i32,
            );
        }
        #[cfg(target_os = "linux")]
        unsafe {
            let v = 0u32;
            scko = libc::setsockopt(
                self.socket_raw,
                libc::IPPROTO_IP,
                libc::IP_PKTINFO,
                (&v as *const u32).cast(),
                std::mem::size_of_val(&v) as libc::socklen_t,
            );
        }
        #[cfg(target_os = "freebsd")]
        {
            scko = 0;
        }
        if scko != 0 {
            // cleanup
            self.socket = None;
            #[cfg(windows)]
            {
                let _ = unsafe { socket2::Socket::from_raw_socket(self.socket_raw) };
            }
            #[cfg(unix)]
            {
                let _ = unsafe { socket2::Socket::from_raw_fd(self.socket_raw) };
            }
            return Err(Error::new(ErrorKind::Other, "Unable to set IP_PKTINFO"));
        }
        #[cfg(windows)]
        unsafe {
            let mut fnc: winapi::shared::minwindef::FARPROC = null_mut();
            let mut bret: winapi::shared::minwindef::DWORD = 0;
            let rt = WSAIoctl(
                self.socket_raw as winapi::um::winsock2::SOCKET,
                winapi::shared::ws2def::SIO_GET_EXTENSION_FUNCTION_POINTER,
                (&winapi::um::mswsock::WSAID_WSARECVMSG as *const winapi::shared::guiddef::GUID)
                    .cast(),
                std::mem::size_of::<winapi::shared::guiddef::GUID>() as u32,
                (&mut fnc as *mut winapi::shared::minwindef::FARPROC) as *mut std::ffi::c_void,
                std::mem::size_of::<*mut std::ffi::c_void>() as u32,
                &mut bret,
                null_mut(),
                None,
            );
            if rt != 0 {
                let _ = socket2::Socket::from_raw_socket(self.socket_raw);
                self.socket = None;
                self.socket_raw = 0;
                //return Err(anyhow!("WSAIoctl returned: {}", rt));
                return Err(Error::new(ErrorKind::Other, "unable to get WSARECVMSG"));
            }
            self.wsarecvmsg = Some(std::mem::transmute(fnc));
        }

        #[cfg(windows)]
        {
            self.socket = unsafe { Some(mio::net::UdpSocket::from_raw_socket(self.socket_raw)) };
        }
        #[cfg(unix)]
        {
            self.socket = unsafe { Some(mio::net::UdpSocket::from_raw_fd(self.socket_raw)) };
        }

        Ok(())
    }
    pub fn bind(&mut self, bind_sa: SocketAddrV4) -> std::io::Result<()> {
        #[cfg(windows)]
        {
            let socket = unsafe { socket2::Socket::from_raw_socket(self.socket_raw) };
            socket.bind(&socket2::SockAddr::from(bind_sa))?;
            let _ = socket.into_raw_socket();
        }
        #[cfg(unix)]
        {
            let socket = unsafe { socket2::Socket::from_raw_fd(self.socket_raw) };
            socket.bind(&socket2::SockAddr::from(bind_sa))?;
            let _ = socket.into_raw_fd();
        }
        self.bound = bind_sa;
        Ok(())
    }
    pub fn recvfromto(
        &self,
        readbuf: &mut [u8],
    ) -> std::io::Result<(usize, std::net::SocketAddrV4, std::net::SocketAddrV4)> {
        #[cfg(unix)]
        {
            let mut from_addr = unsafe { std::mem::zeroed::<libc::sockaddr_in>() };
            let mut to_addr = unsafe { std::mem::zeroed::<libc::sockaddr_in>() };
            let mut iov = libc::iovec {
                iov_base: readbuf as *mut [u8] as *mut libc::c_void,
                iov_len: readbuf.len(),
            };
            let mut ctrl = unsafe { std::mem::zeroed::<in_pktinfo>() };
            let mut ctrlbuf = [0u8; 256];
            let mut msgh = libc::msghdr {
                msg_name: &mut from_addr as *mut libc::sockaddr_in as *mut libc::c_void,
                msg_namelen: std::mem::size_of_val(&from_addr) as libc::socklen_t,
                msg_iov: &mut iov as *mut libc::iovec,
                msg_iovlen: 1,
                msg_control: ctrlbuf.as_mut_ptr() as *mut libc::c_void, //&mut ctrl as *mut in_pktinfo as *mut libc::c_void,
                #[cfg(target_os = "linux")]
                msg_controllen: std::mem::size_of_val(&ctrlbuf) as usize,
                #[cfg(target_os = "freebsd")]
                msg_controllen: std::mem::size_of_val(&ctrlbuf) as libc::socklen_t,
                msg_flags: 0,
            };
            let ssz = unsafe { libc::recvmsg(self.socket_raw, &mut msgh as *mut libc::msghdr, 0) };
            if ssz < 1 {
                let errno = sys_errno();
                return Err(std::io::Error::from_raw_os_error(errno));
            }
            let mut ofs = 0;
            let mut phdr = ctrlbuf.as_mut_ptr() as *mut libc::c_void as *mut libc::cmsghdr;
            while ofs < msgh.msg_controllen {
                unsafe {
                    let msglen = (*phdr).cmsg_len;

                    if (*phdr).cmsg_level == libc::IPPROTO_IP
                        && (*phdr).cmsg_type == libc::IP_ORIGDSTADDR
                    {
                        to_addr = *((phdr as *mut libc::c_void as *mut u8)
                            .offset(std::mem::size_of::<libc::sockaddr_in>().try_into().unwrap())
                            as *mut libc::sockaddr_in);
                    } else {
                        trace!("found cmsghdr {} {}", (*phdr).cmsg_level, (*phdr).cmsg_type);
                    }
                    ofs += msglen;
                    phdr = (phdr as *mut libc::c_void as *mut u8).offset(msglen.try_into().unwrap())
                        as *mut libc::cmsghdr;
                }
            }
            let mut trg = ipfrominaddr(&ctrl.ipi_addr);
            return Ok((
                ssz as usize,
                SocketAddrV4::new(
                    ipfrominaddr(&from_addr.sin_addr),
                    u16::from_be(from_addr.sin_port),
                ),
                SocketAddrV4::new(
                    ipfrominaddr(&to_addr.sin_addr),
                    u16::from_be(to_addr.sin_port),
                ),
            ));
        }
        #[cfg(windows)]
        {
            let mut sa_from = windows_sys::Win32::Networking::WinSock::SOCKADDR_IN {
                sin_family: 0,
                sin_port: 0,
                sin_addr: windows_sys::Win32::Networking::WinSock::IN_ADDR {
                    S_un: windows_sys::Win32::Networking::WinSock::IN_ADDR_0 {
                        S_un_b: windows_sys::Win32::Networking::WinSock::IN_ADDR_0_0 {
                            s_b1: 0,
                            s_b2: 0,
                            s_b3: 0,
                            s_b4: 0,
                        },
                    },
                },
                sin_zero: [0i8; 8],
            };
            let mut pinfo = IN_PKTINFO::default();
            let mut wsabufs = windows_sys::Win32::Networking::WinSock::WSABUF {
                len: readbuf.len() as u32,
                buf: readbuf.as_mut_ptr(),
            };
            let mut wsamsg = windows_sys::Win32::Networking::WinSock::WSAMSG {
                name: (&mut sa_from as *mut windows_sys::Win32::Networking::WinSock::SOCKADDR_IN)
                    as *mut windows_sys::Win32::Networking::WinSock::SOCKADDR,
                namelen: std::mem::size_of::<windows_sys::Win32::Networking::WinSock::SOCKADDR_IN>()
                    as i32,
                lpBuffers: &mut wsabufs,
                dwBufferCount: 1,
                Control: windows_sys::Win32::Networking::WinSock::WSABUF {
                    len: std::mem::size_of::<IN_PKTINFO>() as u32,
                    buf: (&mut pinfo as *mut IN_PKTINFO as *mut u8),
                },
                dwFlags: 0,
            };

            if let Some(fnc) = self.wsarecvmsg.as_ref() {
                let mut rcvd = 0u32;
                let rt = unsafe {
                    fnc(
                        self.socket_raw as usize,
                        &mut wsamsg as *mut windows_sys::Win32::Networking::WinSock::WSAMSG,
                        &mut rcvd as *mut u32,
                        null_mut(),
                        None,
                    )
                };
                if rt < 0 {
                    let wsaerr = unsafe { winapi::um::winsock2::WSAGetLastError() };
                    if wsaerr == 10035 {
                        return Err(Error::new(ErrorKind::WouldBlock, "Non-blocking mode"));
                    }
                    return Err(std::io::Error::from_raw_os_error(wsaerr));
                }
                let pck_from =
                    SocketAddrV4::new(ipfromwin(&sa_from.sin_addr), u16::from_be(sa_from.sin_port));
                let pck_to = ipfromwin(&pinfo.dstip);
                Ok((
                    rcvd as usize,
                    pck_from,
                    SocketAddrV4::new(pck_to, self.bound.port()),
                ))
            } else {
                Err(Error::new(ErrorKind::Other, "No WSARecvMsg"))
            }
        }
    }
}

impl mio::event::Source for IUdpSocket {
    fn register(
        &mut self,
        registry: &mio::Registry,
        token: Token,
        interests: Interest,
    ) -> std::io::Result<()> {
        // Delegate the `register` call to `socket`
        match &mut self.socket {
            None => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No socket",
            )),
            Some(s) => s.register(registry, token, interests),
        }
    }

    fn reregister(
        &mut self,
        registry: &mio::Registry,
        token: Token,
        interests: Interest,
    ) -> std::io::Result<()> {
        // Delegate the `reregister` call to `socket`
        match &mut self.socket {
            None => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No socket",
            )),
            Some(s) => s.reregister(registry, token, interests),
        }
    }

    fn deregister(&mut self, registry: &mio::Registry) -> std::io::Result<()> {
        // Delegate the `deregister` call to `socket`
        match &mut self.socket {
            None => Ok(()),
            Some(s) => s.deregister(registry),
        }
    }
}

#[cfg(windows)]
#[repr(C)]
struct IN_PKTINFO {
    pub len: winapi::vc::vcruntime::size_t,
    pub unk0: winapi::shared::minwindef::ULONG,
    pub unk1: winapi::shared::minwindef::ULONG,
    pub dstip: windows_sys::Win32::Networking::WinSock::IN_ADDR,
    pub unk2: winapi::shared::minwindef::ULONG,
}
#[cfg(windows)]
impl std::default::Default for IN_PKTINFO {
    fn default() -> IN_PKTINFO {
        IN_PKTINFO {
            len: 24,
            unk0: 0,
            unk1: 0,
            dstip: windows_sys::Win32::Networking::WinSock::IN_ADDR {
                S_un: windows_sys::Win32::Networking::WinSock::IN_ADDR_0 {
                    S_un_b: windows_sys::Win32::Networking::WinSock::IN_ADDR_0_0 {
                        s_b1: 0,
                        s_b2: 0,
                        s_b3: 0,
                        s_b4: 0,
                    },
                },
            },
            unk2: 0,
        }
    }
}

#[cfg(windows)]
fn ipfromwin(ina: &windows_sys::Win32::Networking::WinSock::IN_ADDR) -> std::net::Ipv4Addr {
    unsafe {
        std::net::Ipv4Addr::new(
            ina.S_un.S_un_b.s_b1,
            ina.S_un.S_un_b.s_b2,
            ina.S_un.S_un_b.s_b3,
            ina.S_un.S_un_b.s_b4,
        )
    }
}

#[cfg(unix)]
#[repr(C)]
struct in_pktinfo {
    pub len: u32,
    pub unk0: u32,
    pub unk1: u32,
    pub unk2: u32,
    pub unk3: u32,
    pub ipi_addr: libc::in_addr,
}

#[cfg(unix)]
fn ipfrominaddr(ina: &libc::in_addr) -> std::net::Ipv4Addr {
    Ipv4Addr::from(u32::from_be(ina.s_addr))
}

pub struct Packet {
    pub body: bytes::Bytes,
    pub from: SocketAddrV4,
    pub to: SocketAddrV4,
}

pub fn recv_loop(
    cancel: tokio_util::sync::CancellationToken,
    chn: tokio::sync::mpsc::Sender<Packet>,
    sockcfg: &config::SocketConfig,
) -> anyhow::Result<()> {
    let mut sock = IUdpSocket::new();
    sock.create()?;
    sock.bind(SocketAddrV4::new(sockcfg.bind_address, sockcfg.bind_port))?;
    let mut buf = [0u8; 1500];
    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(1);
    let polltimeout = std::time::Duration::from_millis(1000);
    poll.registry()
        .register(&mut sock, Token(0), Interest::READABLE)?;
    while !cancel.is_cancelled() {
        match sock.recvfromto(&mut buf) {
            Ok(rs) => {
                chn.blocking_send(Packet {
                    body: bytes::Bytes::copy_from_slice(&buf[0..rs.0]),
                    from: rs.1,
                    to: rs.2,
                })?;
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::WouldBlock {
                    return Err(e.into());
                }
                if let Err(err) = poll.poll(&mut events, Some(polltimeout)) {
                    if err.kind() == ErrorKind::TimedOut {
                        trace!("poll timeout");
                        continue;
                    }
                    return Err(err.into());
                }
            }
        }
    }
    Ok(())
}
