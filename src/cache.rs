use lru_cache::LruCache;
use std::net::IpAddr;
use std::time::{Duration, Instant};


/// https://tools.ietf.org/html/rfc2181,
pub const MAX_TTL: u64 = 86400_u64;


#[derive(Debug)]
struct LruValue {
    // this is None in case of an NX
    ipaddr: Option<IpAddr>,
    valid_until: Instant,
}

impl LruValue {
    fn is_current(&self, now: Instant) -> bool {
        now <= self.valid_until
    }
}

pub struct TtlConfig {
    pub positive_min_ttl: Duration,
    pub negative_min_ttl: Duration,
    pub positive_max_ttl: Duration,
    pub negative_max_ttl: Duration,
}

impl Default for TtlConfig {
    fn default() -> TtlConfig {
        TtlConfig {
            positive_min_ttl: Duration::from_secs(0),
            negative_min_ttl: Duration::from_secs(0),
            positive_max_ttl: Duration::from_secs(MAX_TTL),
            negative_max_ttl: Duration::from_secs(MAX_TTL),
        }
    }
}

pub struct DnsCache {
    cache: LruCache<String, LruValue>,
    positive_min_ttl: Duration,
    negative_min_ttl: Duration,
    positive_max_ttl: Duration,
    negative_max_ttl: Duration,
}

impl DnsCache {
    pub fn new(capacity: usize, ttl: TtlConfig) -> DnsCache {
        let cache = LruCache::new(capacity);
        DnsCache {
            cache,
            positive_min_ttl: ttl.positive_min_ttl,
            negative_min_ttl: ttl.negative_min_ttl,
            positive_max_ttl: ttl.positive_max_ttl,
            negative_max_ttl: ttl.negative_max_ttl,
        }
    }

    pub fn insert(&mut self, query: String, ipaddr: Option<IpAddr>, mut ttl: Duration, now: Instant) {
        if ipaddr.is_some() {
            if ttl < self.positive_min_ttl {
                ttl = self.positive_min_ttl.clone();
            } else if ttl > self.positive_max_ttl {
                ttl = self.positive_max_ttl.clone();
            }
        } else {
            if ttl < self.negative_min_ttl {
                ttl = self.negative_min_ttl.clone();
            } else if ttl > self.negative_max_ttl {
                ttl = self.negative_max_ttl.clone();
            }
        }

        let valid_until = now + ttl;

        self.cache.insert(query, LruValue {
            ipaddr,
            valid_until,
        });
    }

    pub fn get(&mut self, query: &str, now: Instant) -> Option<Option<IpAddr>> {
        if let Some(ipaddr) = self.cache.get_mut(query) {
            if !ipaddr.is_current(now) {
                self.cache.remove(query);
                None
            } else {
                Some(ipaddr.ipaddr)
            }
        } else {
            None
        }
    }
}

impl Default for DnsCache {
    fn default() -> DnsCache {
        DnsCache::new(32, TtlConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn verify_insert() {
        let now = Instant::now();
        let mut cache = DnsCache::default();
        let ipaddr = "1.1.1.1".parse().unwrap();
        cache.insert("example.com".into(), Some(ipaddr), Duration::from_secs(1), now);
    }

    #[test]
    fn verify_get() {
        let now = Instant::now();
        let mut cache = DnsCache::default();
        let ipaddr = "1.1.1.1".parse().unwrap();
        cache.insert("example.com".into(), Some(ipaddr), Duration::from_secs(1), now);
        assert!(cache.get("example.com", now).is_some());
    }

    #[test]
    fn verify_expire() {
        let now = Instant::now();
        let mut cache = DnsCache::default();
        let ipaddr = "1.1.1.1".parse().unwrap();
        cache.insert("example.com".into(), Some(ipaddr), Duration::from_secs(1), now);
        let now = now + Duration::from_secs(2);
        assert!(cache.get("example.com", now).is_none());
    }
}
