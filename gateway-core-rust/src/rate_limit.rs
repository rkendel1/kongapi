use std::{
    collections::HashMap,
    sync::Mutex,
    time::Instant,
};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RateLimitConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_capacity")]
    pub capacity: u32,
    #[serde(default = "default_refill_per_second")]
    pub refill_per_second: u32,
}

fn default_capacity() -> u32 {
    100
}

fn default_refill_per_second() -> u32 {
    100
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            capacity: default_capacity(),
            refill_per_second: default_refill_per_second(),
        }
    }
}

#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

#[derive(Debug)]
pub struct RateLimiter {
    config: RateLimitConfig,
    buckets: Mutex<HashMap<String, TokenBucket>>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub fn check(&self, key: &str) -> bool {
        if !self.config.enabled {
            return true;
        }

        let now = Instant::now();
        let mut buckets = match self.buckets.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!("rate limiter lock poisoned; recovering with inner state");
                poisoned.into_inner()
            }
        };
        let bucket = buckets.entry(key.to_string()).or_insert_with(|| TokenBucket {
            tokens: self.config.capacity as f64,
            last_refill: now,
        });

        let elapsed = now.duration_since(bucket.last_refill);
        let refill_amount = elapsed.as_secs_f64() * self.config.refill_per_second as f64;
        bucket.tokens = (bucket.tokens + refill_amount).min(self.config.capacity as f64);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    #[cfg(test)]
    fn check_after_wait(&self, key: &str, wait: std::time::Duration) -> bool {
        std::thread::sleep(wait);
        self.check(key)
    }
}

#[cfg(test)]
mod tests {
    use super::{RateLimitConfig, RateLimiter};
    use std::time::Duration;

    #[test]
    fn enforces_capacity() {
        let limiter = RateLimiter::new(RateLimitConfig {
            enabled: true,
            capacity: 2,
            refill_per_second: 1,
        });

        assert!(limiter.check("client-a"));
        assert!(limiter.check("client-a"));
        assert!(!limiter.check("client-a"));
    }

    #[test]
    fn refills_tokens_over_time() {
        let limiter = RateLimiter::new(RateLimitConfig {
            enabled: true,
            capacity: 1,
            refill_per_second: 10,
        });

        assert!(limiter.check("client-a"));
        assert!(!limiter.check("client-a"));
        assert!(limiter.check_after_wait("client-a", Duration::from_millis(120)));
    }
}
