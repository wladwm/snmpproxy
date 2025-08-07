use clap::Parser;

use std::net::Ipv4Addr;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dur(Duration);

impl Dur {
    const DUR_1D: Duration = Duration::new(86400, 0);
    const DUR_1H: Duration = Duration::new(3600, 0);
    const DUR_1MIN: Duration = Duration::new(60, 0);
    pub const fn dur(&self) -> std::time::Duration {
        self.0
    }
    pub const fn from_secs(s: u64) -> Dur {
        Dur(Duration::new(s, 0))
    }
    fn fromstr(s: &str) -> Result<Dur, std::num::ParseFloatError> {
        let mut d = std::time::Duration::new(0, 0);
        let mut n = 0u64;
        for c in s.chars() {
            if let Some(q) = c.to_digit(10) {
                n = n * 10 + (q as u64);
                continue;
            }
            match c {
                'd' => {
                    d += Self::DUR_1D * (n as u32);
                    n = 0;
                }
                'h' => {
                    d += Self::DUR_1H * (n as u32);
                    n = 0;
                }
                'm' => {
                    d += Self::DUR_1MIN * (n as u32);
                    n = 0;
                }
                's' => {
                    d += Duration::new(n, 0);
                    n = 0;
                }
                ' ' => {}
                _ => return Ok(Dur(Duration::from_secs_f64(s.parse()?))),
            }
        }
        if n > 0 {
            d += Duration::new(n, 0);
        }
        Ok(Dur(d))
    }
}
impl std::str::FromStr for Dur {
    type Err = std::num::ParseFloatError;

    fn from_str(s: &str) -> Result<Dur, Self::Err> {
        match s.parse() {
            Ok(n) => Ok(Dur(std::time::Duration::from_secs_f64(n))),
            Err(_) => Dur::fromstr(s),
        }
    }
}
impl std::convert::From<std::time::Duration> for Dur {
    fn from(t: std::time::Duration) -> Self {
        Dur(t)
    }
}
impl std::convert::Into<std::time::Duration> for Dur {
    fn into(self) -> std::time::Duration {
        self.0
    }
}
impl std::fmt::Display for Dur {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut msc = self.0.as_millis();
        let mut fw = false;
        if msc >= 86400000 {
            let d = msc / 86400000;
            msc -= d * 86400000;
            write!(f, "{}d", d)?;
            fw = true;
        };
        if msc >= 3600000 {
            let h = msc / 3600000;
            msc -= h * 3600000;
            write!(f, "{}h", h)?;
            fw = true;
        };
        if msc >= 60000 {
            let m = msc / 60000;
            msc -= m * 60000;
            write!(f, "{}m", m)?;
            fw = true;
        };
        if msc >= 1000 {
            let s = msc / 1000;
            msc -= s * 1000;
            write!(f, "{}s", s)?;
            fw = true;
        };
        if !fw || msc != 0 {
            write!(f, "{}ms", msc)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone)]
pub struct SocketConfig {
    pub bind_address: Ipv4Addr,
    pub bind_port: u16,
    #[cfg(target_os = "linux")]
    pub bind_device: Option<String>,
    #[cfg(target_os = "freebsd")]
    pub fib: Option<u32>,
}
impl SocketConfig {
    fn get_addr(&mut self, s: &str) -> Result<(), std::net::AddrParseError> {
        match s.parse::<std::net::SocketAddrV4>() {
            Ok(sa) => {
                self.bind_address = *sa.ip();
                self.bind_port = sa.port();
            }
            Err(_) => match s.parse::<std::net::Ipv4Addr>() {
                Ok(a) => {
                    self.bind_address = a;
                }
                Err(e) => return Err(e),
            },
        }
        Ok(())
    }
}
impl std::default::Default for SocketConfig {
    fn default() -> Self {
        SocketConfig {
            bind_address: Ipv4Addr::UNSPECIFIED,
            bind_port: 0,
            #[cfg(target_os = "linux")]
            bind_device: None,
            #[cfg(target_os = "freebsd")]
            fib: None,
        }
    }
}
impl std::str::FromStr for SocketConfig {
    type Err = std::net::AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut ret = SocketConfig::default();
        if s.is_empty() {
            return Ok(ret);
        }
        if s.contains('@') {
            let p = s.splitn(3, '@').collect::<Vec<_>>();
            if !p[0].is_empty() {
                ret.get_addr(p[0])?;
            };
            if !p[1].is_empty() {
                #[cfg(target_os = "linux")]
                {
                    ret.bind_device = Some(p[1].to_string());
                }
                #[cfg(target_os = "freebsd")]
                {
                    ret.fib = p[1].parse().ok();
                }
            }
        } else {
            ret.get_addr(s)?;
        }
        Ok(ret)
    }
}

#[derive(Parser)]
#[command(author ="Vladimir Melnikov <wlad.w.m@gmail.com>", version = "0.1.0", about = "It is a transparent caching proxy that intercepts requests to network devices and responds to monitoring systems instead of them", long_about = None)]
pub struct Config {
    #[arg(
        long,
        help = "Intercept socket configuration, [ip[:port]][@device/fibno]",
        default_value = "0.0.0.0:161"
    )]
    pub intercept: SocketConfig,
    #[arg(
        long,
        help = "Response spoofed socket configuration, [ip[:port]][@device/fibno]",
        default_value = ""
    )]
    pub response: SocketConfig,
    #[arg(
        long,
        help = "Device query socket configuration, [ip[:port]][@device/fibno]",
        default_value = ""
    )]
    pub query: SocketConfig,
    #[arg(long, help = "Cached values life time", default_value = "5m")]
    pub cache_value_lifetime: Dur,
    #[arg(long, help = "Host auto-ignore duration", default_value = "15m")]
    pub blacklist_duration: Dur,
    #[arg(long, help = "SNMP query to device timeout", default_value = "30s")]
    pub snmp_timeout: Dur,
    #[arg(long, help = "SNMP retries count", default_value_t = 3)]
    pub snmp_repeat: u32,
    #[arg(
        long,
        help = "Maximum parallel queries per host",
        default_value_t = 100
    )]
    pub max_parallel_queries_per_host: usize,
}
impl std::default::Default for Config {
    fn default() -> Self {
        Config {
            intercept: SocketConfig {
                bind_port: 161,
                ..Default::default()
            },
            response: Default::default(),
            query: Default::default(),
            cache_value_lifetime: Dur::from_secs(600),
            blacklist_duration: Dur::from_secs(3600),
            snmp_timeout: Dur::from_secs(10),
            snmp_repeat: 3,
            max_parallel_queries_per_host: 100,
        }
    }
}
