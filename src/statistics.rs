use serde::Serialize;
use std::sync::atomic::AtomicUsize;

#[derive(Serialize)]
pub struct Stats {
    pub packets_intercepted: AtomicUsize,
    pub packets_in_get: AtomicUsize,
    pub packets_in_getnext: AtomicUsize,
    pub packets_in_getbulk: AtomicUsize,
    pub packets_in_others: AtomicUsize,
    pub varbinds_intercepted: AtomicUsize,
    pub packets_sent_get: AtomicUsize,
    pub packets_sent_getnext: AtomicUsize,
    pub packets_sent_getbulk: AtomicUsize,
    pub varbinds_sent: AtomicUsize,
    pub replies_sent_get: AtomicUsize,
    pub replies_sent_getnext: AtomicUsize,
    pub replies_sent_getbulk: AtomicUsize,
    pub varbinds_replied: AtomicUsize,
}
impl std::default::Default for Stats {
    fn default() -> Self {
        Stats {
            packets_intercepted: AtomicUsize::new(0),
            packets_in_get: AtomicUsize::new(0),
            packets_in_getnext: AtomicUsize::new(0),
            packets_in_getbulk: AtomicUsize::new(0),
            packets_in_others: AtomicUsize::new(0),
            varbinds_intercepted: AtomicUsize::new(0),
            packets_sent_get: AtomicUsize::new(0),
            packets_sent_getnext: AtomicUsize::new(0),
            packets_sent_getbulk: AtomicUsize::new(0),
            varbinds_sent: AtomicUsize::new(0),
            replies_sent_get: AtomicUsize::new(0),
            replies_sent_getnext: AtomicUsize::new(0),
            replies_sent_getbulk: AtomicUsize::new(0),
            varbinds_replied: AtomicUsize::new(0),
        }
    }
}
