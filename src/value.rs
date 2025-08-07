use std::convert::Infallible;

#[derive(Clone)]
pub enum Octets<const N: usize> {
    Short { len: usize, short: [u8; N] },
    Long { len: usize, rest: Box<[u8]> },
}
impl<const N: usize> std::default::Default for Octets<N> {
    fn default() -> Octets<N> {
        Octets::Short {
            len: 0,
            short: [0u8; N],
        }
    }
}
impl<const N: usize> Octets<N> {
    pub fn new(src: &[u8]) -> Octets<N> {
        if src.len() <= N {
            let mut short = [0u8; N];
            short[0..src.len()].clone_from_slice(src);
            Octets::Short {
                len: src.len(),
                short,
            }
        } else {
            let mut rest = Vec::with_capacity(src.len());
            rest.resize(src.len(), 0);
            rest.copy_from_slice(src);
            Octets::Long {
                len: src.len(),
                rest: rest.into_boxed_slice(),
            }
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Octets::Short { len, short } => &short[0..*len],
            Octets::Long { len, rest } => &rest[0..*len],
        }
    }
}
impl<const N: usize> std::ops::Deref for Octets<N> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        match self {
            Octets::Short { len, short } => &short[0..*len],
            Octets::Long { len, rest } => &rest[0..*len],
        }
    }
}

#[derive(Clone)]
pub enum Value {
    Boolean(bool),
    Null,
    Integer(i64),
    OctetString(Octets<16>),
    ObjectIdentifier(Octets<16>),
    //Sequence(AsnReader<'a>),
    //Set(AsnReader<'a>),
    //Constructed(u8, AsnReader<'a>),
    IpAddress([u8; 4]),
    Counter32(u32),
    Unsigned32(u32),
    Timeticks(u32),
    Opaque(Octets<16>),
    Counter64(u64),

    EndOfMibView,
    NoSuchObject,
    NoSuchInstance,
}

impl std::convert::TryFrom<&snmp::Value<'_>> for Value {
    type Error = Infallible;
    fn try_from(value: &snmp::Value<'_>) -> Result<Self, Self::Error> {
        use snmp::Value::*;
        match value {
            Boolean(b) => Ok(Value::Boolean(*b)),
            Null => Ok(Value::Null),
            Integer(i) => Ok(Value::Integer(*i)),
            OctetString(ostr) => Ok(Value::OctetString(Octets::new(ostr))),
            ObjectIdentifier(ref objid) => Ok(Value::ObjectIdentifier(Octets::new(objid.raw()))),
            IpAddress(ref ip) => Ok(Value::IpAddress(*ip)),
            Counter32(i) => Ok(Value::Counter32(*i)),
            Unsigned32(i) => Ok(Value::Unsigned32(*i)),
            Timeticks(tt) => Ok(Value::Timeticks(*tt)),
            Opaque(bytes) => Ok(Value::Opaque(Octets::new(bytes))),
            Counter64(i) => Ok(Value::Counter64(*i)),
            EndOfMibView => Ok(Value::EndOfMibView),
            NoSuchObject => Ok(Value::NoSuchObject),
            NoSuchInstance => Ok(Value::NoSuchInstance),
            _ => unimplemented!(),
        }
    }
}
impl<'a> std::convert::From<&'a Value> for snmp::Value<'a> {
    fn from(val: &'a Value) -> Self {
        use Value::*;
        match val {
            Boolean(b) => snmp::Value::Boolean(*b),
            Null => snmp::Value::Null,
            Integer(i) => snmp::Value::Integer(*i),
            OctetString(o) => snmp::Value::OctetString(o.as_bytes()),
            ObjectIdentifier(v) => {
                snmp::Value::ObjectIdentifier(snmp::ObjectIdentifier::from_bytes(v.as_bytes()))
            }
            IpAddress(ip) => snmp::Value::IpAddress(*ip),
            Counter32(i) => snmp::Value::Counter32(*i),
            Unsigned32(i) => snmp::Value::Unsigned32(*i),
            Timeticks(i) => snmp::Value::Timeticks(*i),
            Opaque(o) => snmp::Value::Opaque(o.as_bytes()),
            Counter64(i) => snmp::Value::Counter64(*i),
            EndOfMibView => snmp::Value::EndOfMibView,
            NoSuchObject => snmp::Value::NoSuchObject,
            NoSuchInstance => snmp::Value::NoSuchInstance,
        }
    }
}
