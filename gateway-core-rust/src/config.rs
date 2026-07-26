use std::path::Path;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    balancer::{BalancingStrategy, UpstreamTarget},
    rate_limit::RateLimitConfig,
    router::Route,
    security::SecurityConfig,
};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GatewayConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub routes: Vec<Route>,
    #[serde(default)]
    pub upstreams: Vec<UpstreamConfig>,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub plugins: Vec<PluginConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ServerConfig {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    #[serde(default = "default_max_request_body_bytes")]
    pub max_request_body_bytes: usize,
    #[serde(default)]
    pub proxy: ProxyRuntimeConfig,
    #[serde(default)]
    pub shutdown: ShutdownConfig,
}

fn default_listen_addr() -> String {
    "127.0.0.1:3000".to_string()
}

fn default_max_request_body_bytes() -> usize {
    8 * 1024 * 1024
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            max_request_body_bytes: default_max_request_body_bytes(),
            proxy: ProxyRuntimeConfig::default(),
            shutdown: ShutdownConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProxyRuntimeConfig {
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_read_timeout_ms")]
    pub read_timeout_ms: u64,
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default = "default_max_idle_per_host")]
    pub max_idle_per_host: usize,
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default)]
    pub retries: RetryConfig,
}

fn default_connect_timeout_ms() -> u64 {
    1000
}

fn default_read_timeout_ms() -> u64 {
    5000
}

fn default_request_timeout_ms() -> u64 {
    7000
}

fn default_max_idle_per_host() -> usize {
    64
}

fn default_idle_timeout_secs() -> u64 {
    90
}

impl Default for ProxyRuntimeConfig {
    fn default() -> Self {
        Self {
            connect_timeout_ms: default_connect_timeout_ms(),
            read_timeout_ms: default_read_timeout_ms(),
            request_timeout_ms: default_request_timeout_ms(),
            max_idle_per_host: default_max_idle_per_host(),
            idle_timeout_secs: default_idle_timeout_secs(),
            retries: RetryConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RetryConfig {
    #[serde(default = "default_retry_max_attempts")]
    pub max_attempts: u8,
    #[serde(default = "default_retry_backoff_ms")]
    pub backoff_ms: u64,
    #[serde(default = "default_retry_idempotent_only")]
    pub idempotent_only: bool,
}

fn default_retry_max_attempts() -> u8 {
    3
}

fn default_retry_backoff_ms() -> u64 {
    50
}

fn default_retry_idempotent_only() -> bool {
    true
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: default_retry_max_attempts(),
            backoff_ms: default_retry_backoff_ms(),
            idempotent_only: default_retry_idempotent_only(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ShutdownConfig {
    #[serde(default = "default_drain_timeout_ms")]
    pub drain_timeout_ms: u64,
    #[serde(default = "default_drain_poll_ms")]
    pub drain_poll_ms: u64,
}

fn default_drain_timeout_ms() -> u64 {
    10_000
}

fn default_drain_poll_ms() -> u64 {
    50
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            drain_timeout_ms: default_drain_timeout_ms(),
            drain_poll_ms: default_drain_poll_ms(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct UpstreamConfig {
    pub name: String,
    pub strategy: BalancingStrategy,
    pub targets: Vec<UpstreamTarget>,
    #[serde(default)]
    pub health_checks: HealthCheckConfig,
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HealthCheckConfig {
    #[serde(default)]
    pub active: ActiveHealthCheckConfig,
    #[serde(default)]
    pub passive: PassiveHealthCheckConfig,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            active: ActiveHealthCheckConfig::default(),
            passive: PassiveHealthCheckConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ActiveHealthCheckConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_healthcheck_path")]
    pub path: String,
    #[serde(default = "default_healthcheck_interval_ms")]
    pub interval_ms: u64,
    #[serde(default = "default_healthcheck_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,
}

fn default_healthcheck_path() -> String {
    "/healthz".to_string()
}

fn default_healthcheck_interval_ms() -> u64 {
    5_000
}

fn default_healthcheck_timeout_ms() -> u64 {
    1_000
}

fn default_healthy_threshold() -> u32 {
    2
}

fn default_unhealthy_threshold() -> u32 {
    2
}

impl Default for ActiveHealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_healthcheck_path(),
            interval_ms: default_healthcheck_interval_ms(),
            timeout_ms: default_healthcheck_timeout_ms(),
            healthy_threshold: default_healthy_threshold(),
            unhealthy_threshold: default_unhealthy_threshold(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PassiveHealthCheckConfig {
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    #[serde(default = "default_success_threshold")]
    pub success_threshold: u32,
}

fn default_failure_threshold() -> u32 {
    3
}

fn default_success_threshold() -> u32 {
    1
}

impl Default for PassiveHealthCheckConfig {
    fn default() -> Self {
        Self {
            failure_threshold: default_failure_threshold(),
            success_threshold: default_success_threshold(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CircuitBreakerConfig {
    #[serde(default = "default_breaker_failure_threshold")]
    pub failure_threshold: u32,
    #[serde(default = "default_breaker_open_ms")]
    pub open_ms: u64,
    #[serde(default = "default_half_open_max")]
    pub half_open_max_requests: u32,
}

fn default_breaker_failure_threshold() -> u32 {
    5
}

fn default_breaker_open_ms() -> u64 {
    5_000
}

fn default_half_open_max() -> u32 {
    1
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: default_breaker_failure_threshold(),
            open_ms: default_breaker_open_ms(),
            half_open_max_requests: default_half_open_max(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PluginConfig {
    pub name: String,
    pub module: String,
    #[serde(default)]
    pub wasm_path: Option<String>,
}

impl GatewayConfig {
    pub fn load_from_path(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|err| format!("failed to read config {}: {err}", path))?;

        let parsed: Self = match Path::new(path).extension().and_then(|v| v.to_str()) {
            Some("json") => serde_json::from_str(&content)
                .map_err(|err| format!("invalid JSON config {}: {err}", path))?,
            _ => serde_yaml::from_str(&content)
                .map_err(|err| format!("invalid YAML config {}: {err}", path))?,
        };

        parsed.validate()?;
        Ok(parsed)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.routes.is_empty() {
            return Err("at least one route must be configured".to_string());
        }

        for route in &self.routes {
            if !self.upstreams.iter().any(|upstream| upstream.name == route.upstream) {
                return Err(format!(
                    "route '{}' references unknown upstream '{}'",
                    route.name, route.upstream
                ));
            }
        }

        for upstream in &self.upstreams {
            if upstream.targets.is_empty() {
                return Err(format!("upstream '{}' has no targets", upstream.name));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{GatewayConfig, ServerConfig};

    #[test]
    fn rejects_unknown_upstream_reference() {
        let cfg = GatewayConfig {
            server: ServerConfig::default(),
            routes: vec![crate::router::Route {
                name: "r1".to_string(),
                path_prefix: "/".to_string(),
                upstream: "missing".to_string(),
                protocols: vec![],
            }],
            upstreams: vec![],
            security: crate::security::SecurityConfig::default(),
            rate_limit: crate::rate_limit::RateLimitConfig::default(),
            plugins: vec![],
        };

        let err = cfg.validate().expect_err("validation should fail");
        assert!(err.contains("unknown upstream"));
    }
}
