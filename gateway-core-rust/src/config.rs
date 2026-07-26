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
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct UpstreamConfig {
    pub name: String,
    pub strategy: BalancingStrategy,
    pub targets: Vec<UpstreamTarget>,
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
