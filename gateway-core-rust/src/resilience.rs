use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use crate::config::{CircuitBreakerConfig, PassiveHealthCheckConfig};

#[derive(Debug, Clone)]
pub enum CircuitState {
    Closed,
    Open { opened_at: Instant },
    HalfOpen { remaining_attempts: u32 },
}

#[derive(Debug, Clone)]
struct TargetRuntime {
    active_healthy: bool,
    passive_healthy: bool,
    consecutive_failures: u32,
    consecutive_successes: u32,
    breaker_failures: u32,
    circuit_state: CircuitState,
}

impl Default for TargetRuntime {
    fn default() -> Self {
        Self {
            active_healthy: true,
            passive_healthy: true,
            consecutive_failures: 0,
            consecutive_successes: 0,
            breaker_failures: 0,
            circuit_state: CircuitState::Closed,
        }
    }
}

#[derive(Debug)]
pub struct RuntimeRegistry {
    passive_cfg: PassiveHealthCheckConfig,
    breaker_cfg: CircuitBreakerConfig,
    targets: Mutex<HashMap<String, TargetRuntime>>,
}

impl RuntimeRegistry {
    pub fn new(passive_cfg: PassiveHealthCheckConfig, breaker_cfg: CircuitBreakerConfig) -> Self {
        Self {
            passive_cfg,
            breaker_cfg,
            targets: Mutex::new(HashMap::new()),
        }
    }

    pub fn is_available(&self, key: &str) -> bool {
        let mut targets = self.lock_targets();
        let state = targets.entry(key.to_string()).or_default();

        if !state.active_healthy {
            return false;
        }

        match &mut state.circuit_state {
            CircuitState::Closed => state.passive_healthy,
            CircuitState::Open { opened_at } => {
                if opened_at.elapsed() >= Duration::from_millis(self.breaker_cfg.open_ms) {
                    state.circuit_state = CircuitState::HalfOpen {
                        remaining_attempts: self.breaker_cfg.half_open_max_requests,
                    };
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen { remaining_attempts } => {
                if *remaining_attempts == 0 {
                    false
                } else {
                    *remaining_attempts -= 1;
                    true
                }
            }
        }
    }

    pub fn set_active_health(&self, key: &str, healthy: bool) {
        let mut targets = self.lock_targets();
        let state = targets.entry(key.to_string()).or_default();
        state.active_healthy = healthy;
    }

    pub fn record_success(&self, key: &str) {
        let mut targets = self.lock_targets();
        let state = targets.entry(key.to_string()).or_default();
        state.consecutive_successes = state.consecutive_successes.saturating_add(1);
        state.consecutive_failures = 0;
        state.breaker_failures = 0;

        if state.consecutive_successes >= self.passive_cfg.success_threshold {
            state.passive_healthy = true;
        }

        state.circuit_state = CircuitState::Closed;
    }

    pub fn record_failure(&self, key: &str) {
        let mut targets = self.lock_targets();
        let state = targets.entry(key.to_string()).or_default();
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        state.consecutive_successes = 0;

        if state.consecutive_failures >= self.passive_cfg.failure_threshold {
            state.passive_healthy = false;
        }

        state.breaker_failures = state.breaker_failures.saturating_add(1);
        if state.breaker_failures >= self.breaker_cfg.failure_threshold {
            state.circuit_state = CircuitState::Open {
                opened_at: Instant::now(),
            };
        }
    }

    fn lock_targets(&self) -> std::sync::MutexGuard<'_, HashMap<String, TargetRuntime>> {
        match self.targets.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!("runtime registry lock poisoned; recovering state");
                poisoned.into_inner()
            }
        }
    }
}

pub fn target_key(upstream: &str, target_id: &str) -> String {
    format!("{upstream}:{target_id}")
}

pub fn should_retry_method(method: &http::Method, idempotent_only: bool, retry_unsafe_methods: bool) -> bool {
    if !idempotent_only {
        return true;
    }

    matches!(
        *method,
        http::Method::GET | http::Method::HEAD | http::Method::OPTIONS | http::Method::TRACE
    ) || (retry_unsafe_methods && matches!(*method, http::Method::PUT | http::Method::DELETE))
}

pub fn should_retry_status(status: reqwest::StatusCode) -> bool {
    status.as_u16() == 429 || status.as_u16() >= 500
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{target_key, RuntimeRegistry, should_retry_method};

    #[test]
    fn target_keys_are_stable() {
        assert_eq!(target_key("users", "a"), "users:a");
    }

    #[test]
    fn retry_policy_is_idempotent_aware() {
        assert!(should_retry_method(&http::Method::GET, true, false));
        assert!(!should_retry_method(&http::Method::PUT, true, false));
        assert!(should_retry_method(&http::Method::PUT, true, true));
        assert!(!should_retry_method(&http::Method::POST, true, false));
        assert!(should_retry_method(&http::Method::POST, false, false));
    }

    #[test]
    fn circuit_opens_and_recovers() {
        let registry = RuntimeRegistry::new(
            crate::config::PassiveHealthCheckConfig {
                failure_threshold: 1,
                success_threshold: 1,
            },
            crate::config::CircuitBreakerConfig {
                failure_threshold: 1,
                open_ms: 1,
                half_open_max_requests: 1,
            },
        );

        let key = "svc:a";
        registry.record_failure(key);
        assert!(!registry.is_available(key));

        std::thread::sleep(Duration::from_millis(2));
        assert!(registry.is_available(key));

        registry.record_success(key);
        assert!(registry.is_available(key));
    }
}
