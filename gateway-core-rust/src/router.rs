use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Copy, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Http1,
    Http2,
    Grpc,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct Route {
    pub name: String,
    pub path_prefix: String,
    pub upstream: String,
    #[serde(default)]
    pub protocols: Vec<Protocol>,
    #[serde(default)]
    pub transform: TransformConfig,
    #[serde(default)]
    pub traffic_split: TrafficSplitConfig,
    #[serde(default)]
    pub fault_injection: FaultInjectionConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct TransformConfig {
    #[serde(default)]
    pub request: RequestTransform,
    #[serde(default)]
    pub response: ResponseTransform,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct RequestTransform {
    #[serde(default)]
    pub add_headers: HashMap<String, String>,
    #[serde(default)]
    pub set_headers: HashMap<String, String>,
    #[serde(default)]
    pub remove_headers: Vec<String>,
    #[serde(default)]
    pub path_prefix_rewrite: Option<String>,
    #[serde(default)]
    pub body_replace: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ResponseTransform {
    #[serde(default)]
    pub add_headers: HashMap<String, String>,
    #[serde(default)]
    pub set_headers: HashMap<String, String>,
    #[serde(default)]
    pub remove_headers: Vec<String>,
    #[serde(default)]
    pub body_replace: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct TrafficSplitConfig {
    #[serde(default)]
    pub canary_upstream: Option<String>,
    #[serde(default)]
    pub canary_percentage: u8,
    #[serde(default)]
    pub canary_header: Option<CanaryHeaderMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct CanaryHeaderMatch {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct FaultInjectionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_fault_probability")]
    pub probability_percent: u8,
    #[serde(default)]
    pub delay_ms: u64,
    #[serde(default)]
    pub jitter_ms: u64,
    #[serde(default)]
    pub abort_status: Option<u16>,
    #[serde(default)]
    pub abort_body: Option<String>,
}

fn default_fault_probability() -> u8 {
    100
}

pub fn match_route<'a>(routes: &'a [Route], path: &str, protocol: Protocol) -> Option<&'a Route> {
    routes
        .iter()
        .filter(|route| {
            (route.protocols.is_empty() || route.protocols.contains(&protocol))
                && path.starts_with(&route.path_prefix)
        })
        .max_by_key(|route| route.path_prefix.len())
}

#[cfg(test)]
mod tests {
    use super::{match_route, Protocol, Route, TrafficSplitConfig};

    #[test]
    fn matches_longest_path_prefix() {
        let routes = vec![
            Route {
                name: "api".to_string(),
                path_prefix: "/api".to_string(),
                upstream: "svc-a".to_string(),
                protocols: vec![Protocol::Http1],
                transform: Default::default(),
                traffic_split: Default::default(),
                fault_injection: Default::default(),
            },
            Route {
                name: "api-v1".to_string(),
                path_prefix: "/api/v1".to_string(),
                upstream: "svc-b".to_string(),
                protocols: vec![Protocol::Http1, Protocol::Http2],
                transform: Default::default(),
                traffic_split: Default::default(),
                fault_injection: Default::default(),
            },
        ];

        let route = match_route(&routes, "/api/v1/users", Protocol::Http1).expect("route should match");
        assert_eq!(route.name, "api-v1");
    }

    #[test]
    fn enforces_protocol() {
        let routes = vec![Route {
            name: "grpc".to_string(),
            path_prefix: "/".to_string(),
            upstream: "svc".to_string(),
            protocols: vec![Protocol::Grpc],
            transform: Default::default(),
            traffic_split: Default::default(),
            fault_injection: Default::default(),
        }];

        assert!(match_route(&routes, "/", Protocol::Http2).is_none());
    }

    #[test]
    fn traffic_split_defaults_to_disabled_canary() {
        let split = TrafficSplitConfig::default();
        assert!(split.canary_upstream.is_none());
        assert_eq!(split.canary_percentage, 0);
    }
}
