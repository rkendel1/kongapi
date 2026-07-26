use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
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
    use super::{match_route, Protocol, Route};

    #[test]
    fn matches_longest_path_prefix() {
        let routes = vec![
            Route {
                name: "api".to_string(),
                path_prefix: "/api".to_string(),
                upstream: "svc-a".to_string(),
                protocols: vec![Protocol::Http1],
            },
            Route {
                name: "api-v1".to_string(),
                path_prefix: "/api/v1".to_string(),
                upstream: "svc-b".to_string(),
                protocols: vec![Protocol::Http1, Protocol::Http2],
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
        }];

        assert!(match_route(&routes, "/", Protocol::Http2).is_none());
    }
}
