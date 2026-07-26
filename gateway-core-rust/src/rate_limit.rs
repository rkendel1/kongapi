use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
    time::{Duration, Instant},
};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitPolicy {
    TokenBucket,
    FixedWindow,
    SlidingWindow,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LimitScope {
    Route,
    Service,
    Consumer,
    Client,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ScopedLimitRule {
    pub scope: LimitScope,
    pub limit: u32,
    #[serde(default)]
    pub quota: Option<u64>,
    #[serde(default = "default_window_seconds")]
    pub window_seconds: u64,
    #[serde(default)]
    pub policy: Option<RateLimitPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RateLimitConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub policy: RateLimitPolicy,
    #[serde(default = "default_capacity")]
    pub capacity: u32,
    #[serde(default = "default_refill_per_second")]
    pub refill_per_second: u32,
    #[serde(default = "default_window_seconds")]
    pub fixed_window_seconds: u64,
    #[serde(default = "default_window_seconds")]
    pub sliding_window_seconds: u64,
    #[serde(default)]
    pub scoped_limits: Vec<ScopedLimitRule>,
}

#[derive(Debug, Clone, Default)]
struct LimitState {
    tokens: f64,
    last_refill: Option<Instant>,
    fixed_window_start: Option<Instant>,
    fixed_window_count: u64,
    sliding_hits: VecDeque<Instant>,
    accepted_total: u64,
}

#[derive(Debug)]
pub struct RateLimiter {
    config: RateLimitConfig,
    states: Mutex<HashMap<String, LimitState>>,
}

pub struct RateLimitContext<'a> {
    pub route: &'a str,
    pub service: &'a str,
    pub consumer: Option<&'a str>,
    pub client: &'a str,
}

fn default_capacity() -> u32 {
    100
}

fn default_refill_per_second() -> u32 {
    100
}

fn default_window_seconds() -> u64 {
    60
}

impl Default for RateLimitPolicy {
    fn default() -> Self {
        Self::TokenBucket
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            policy: RateLimitPolicy::TokenBucket,
            capacity: default_capacity(),
            refill_per_second: default_refill_per_second(),
            fixed_window_seconds: default_window_seconds(),
            sliding_window_seconds: default_window_seconds(),
            scoped_limits: vec![],
        }
    }
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            states: Mutex::new(HashMap::new()),
        }
    }

    pub fn check(&self, key: &str) -> bool {
        let ctx = RateLimitContext {
            route: "default-route",
            service: "default-service",
            consumer: None,
            client: key,
        };
        self.check_with_context(&ctx)
    }

    pub fn check_with_context(&self, ctx: &RateLimitContext<'_>) -> bool {
        if !self.config.enabled {
            return true;
        }

        let now = Instant::now();
        let mut states = match self.states.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!("rate limiter lock poisoned; recovering state and continuing request processing");
                poisoned.into_inner()
            }
        };

        if self.config.scoped_limits.is_empty() && self.config.policy == RateLimitPolicy::TokenBucket {
            let key = self.scope_key(&LimitScope::Client, ctx.client);
            let state = states.entry(key).or_default();
            return self.apply_legacy_token_bucket(state, now);
        }

        let rules = self.effective_rules_for_context(ctx);
        let mut staged: Vec<(String, LimitState)> = Vec::with_capacity(rules.len());

        for (rule, value_key) in rules {
            let state_key = self.scope_key(&rule.scope, &value_key);
            let current = states.get(&state_key).cloned().unwrap_or_default();
            let mut next = current;

            if let Some(quota) = rule.quota {
                if next.accepted_total >= quota {
                    return false;
                }
            }

            let policy = rule.policy.clone().unwrap_or_else(|| self.config.policy.clone());
            if !self.apply_policy(&policy, &rule, &mut next, now) {
                return false;
            }

            next.accepted_total += 1;
            staged.push((state_key, next));
        }

        for (state_key, state) in staged {
            states.insert(state_key, state);
        }

        true
    }

    fn apply_legacy_token_bucket(&self, state: &mut LimitState, now: Instant) -> bool {
        if state.last_refill.is_none() {
            state.tokens = self.config.capacity as f64;
            state.last_refill = Some(now);
        }

        if let Some(last_refill) = state.last_refill {
            let elapsed = now.duration_since(last_refill).as_secs_f64();
            let refill_amount = elapsed * self.config.refill_per_second as f64;
            state.tokens = (state.tokens + refill_amount).min(self.config.capacity as f64);
            state.last_refill = Some(now);
        }

        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn effective_rules_for_context(&self, ctx: &RateLimitContext<'_>) -> Vec<(ScopedLimitRule, String)> {
        if self.config.scoped_limits.is_empty() {
            return vec![(
                ScopedLimitRule {
                    scope: LimitScope::Client,
                    limit: self.config.capacity,
                    quota: None,
                    window_seconds: match self.config.policy {
                        RateLimitPolicy::TokenBucket => 1,
                        RateLimitPolicy::FixedWindow => self.config.fixed_window_seconds,
                        RateLimitPolicy::SlidingWindow => self.config.sliding_window_seconds,
                    },
                    policy: Some(self.config.policy.clone()),
                },
                ctx.client.to_string(),
            )];
        }

        self.config
            .scoped_limits
            .iter()
            .cloned()
            .map(|rule| {
                let key = match rule.scope {
                    LimitScope::Route => ctx.route.to_string(),
                    LimitScope::Service => ctx.service.to_string(),
                    LimitScope::Consumer => ctx.consumer.unwrap_or("anonymous").to_string(),
                    LimitScope::Client => ctx.client.to_string(),
                };
                (rule, key)
            })
            .collect()
    }

    fn scope_key(&self, scope: &LimitScope, value_key: &str) -> String {
        let scope_name = match scope {
            LimitScope::Route => "route",
            LimitScope::Service => "service",
            LimitScope::Consumer => "consumer",
            LimitScope::Client => "client",
        };
        format!("{scope_name}:{value_key}")
    }

    fn apply_policy(
        &self,
        policy: &RateLimitPolicy,
        rule: &ScopedLimitRule,
        state: &mut LimitState,
        now: Instant,
    ) -> bool {
        match policy {
            RateLimitPolicy::TokenBucket => {
                let window_secs = rule.window_seconds.max(1) as f64;
                let refill_per_second = rule.limit as f64 / window_secs;
                if state.last_refill.is_none() {
                    state.tokens = rule.limit as f64;
                    state.last_refill = Some(now);
                }

                if let Some(last_refill) = state.last_refill {
                    let elapsed = now.duration_since(last_refill).as_secs_f64();
                    state.tokens = (state.tokens + elapsed * refill_per_second).min(rule.limit as f64);
                    state.last_refill = Some(now);
                }

                if state.tokens >= 1.0 {
                    state.tokens -= 1.0;
                    true
                } else {
                    false
                }
            }
            RateLimitPolicy::FixedWindow => {
                let window = Duration::from_secs(rule.window_seconds.max(1));
                let window_start = state.fixed_window_start.unwrap_or(now);
                if now.duration_since(window_start) >= window {
                    state.fixed_window_start = Some(now);
                    state.fixed_window_count = 0;
                } else {
                    state.fixed_window_start = Some(window_start);
                }

                if state.fixed_window_count < rule.limit as u64 {
                    state.fixed_window_count += 1;
                    true
                } else {
                    false
                }
            }
            RateLimitPolicy::SlidingWindow => {
                let window = Duration::from_secs(rule.window_seconds.max(1));
                while let Some(front) = state.sliding_hits.front() {
                    if now.duration_since(*front) >= window {
                        state.sliding_hits.pop_front();
                    } else {
                        break;
                    }
                }

                if state.sliding_hits.len() < rule.limit as usize {
                    state.sliding_hits.push_back(now);
                    true
                } else {
                    false
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{LimitScope, RateLimitConfig, RateLimitContext, RateLimitPolicy, RateLimiter, ScopedLimitRule};
    use std::time::Duration;

    #[test]
    fn token_bucket_enforces_capacity() {
        let limiter = RateLimiter::new(RateLimitConfig {
            enabled: true,
            policy: RateLimitPolicy::TokenBucket,
            capacity: 2,
            refill_per_second: 1,
            fixed_window_seconds: 60,
            sliding_window_seconds: 60,
            scoped_limits: vec![],
        });

        assert!(limiter.check("client-a"));
        assert!(limiter.check("client-a"));
        assert!(!limiter.check("client-a"));
    }

    #[test]
    fn fixed_window_resets_after_window() {
        let limiter = RateLimiter::new(RateLimitConfig {
            enabled: true,
            policy: RateLimitPolicy::FixedWindow,
            capacity: 100,
            refill_per_second: 100,
            fixed_window_seconds: 1,
            sliding_window_seconds: 60,
            scoped_limits: vec![ScopedLimitRule {
                scope: LimitScope::Client,
                limit: 1,
                quota: None,
                window_seconds: 1,
                policy: Some(RateLimitPolicy::FixedWindow),
            }],
        });

        let ctx = RateLimitContext {
            route: "r",
            service: "s",
            consumer: None,
            client: "a",
        };

        assert!(limiter.check_with_context(&ctx));
        assert!(!limiter.check_with_context(&ctx));
        std::thread::sleep(Duration::from_millis(1100));
        assert!(limiter.check_with_context(&ctx));
    }

    #[test]
    fn scoped_consumer_quota_is_enforced() {
        let limiter = RateLimiter::new(RateLimitConfig {
            enabled: true,
            policy: RateLimitPolicy::SlidingWindow,
            capacity: 100,
            refill_per_second: 100,
            fixed_window_seconds: 60,
            sliding_window_seconds: 60,
            scoped_limits: vec![ScopedLimitRule {
                scope: LimitScope::Consumer,
                limit: 10,
                quota: Some(2),
                window_seconds: 60,
                policy: Some(RateLimitPolicy::SlidingWindow),
            }],
        });

        let ctx = RateLimitContext {
            route: "r",
            service: "s",
            consumer: Some("user-1"),
            client: "10.0.0.1",
        };

        assert!(limiter.check_with_context(&ctx));
        assert!(limiter.check_with_context(&ctx));
        assert!(!limiter.check_with_context(&ctx));
    }

    #[test]
    fn scoped_route_and_service_limits_are_combined() {
        let limiter = RateLimiter::new(RateLimitConfig {
            enabled: true,
            policy: RateLimitPolicy::SlidingWindow,
            capacity: 100,
            refill_per_second: 100,
            fixed_window_seconds: 60,
            sliding_window_seconds: 60,
            scoped_limits: vec![
                ScopedLimitRule {
                    scope: LimitScope::Route,
                    limit: 2,
                    quota: None,
                    window_seconds: 60,
                    policy: Some(RateLimitPolicy::SlidingWindow),
                },
                ScopedLimitRule {
                    scope: LimitScope::Service,
                    limit: 3,
                    quota: None,
                    window_seconds: 60,
                    policy: Some(RateLimitPolicy::SlidingWindow),
                },
            ],
        });

        let ctx = RateLimitContext {
            route: "users",
            service: "svc-users",
            consumer: None,
            client: "10.0.0.1",
        };

        assert!(limiter.check_with_context(&ctx));
        assert!(limiter.check_with_context(&ctx));
        assert!(!limiter.check_with_context(&ctx));
    }
}
