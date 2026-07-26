use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BalancingStrategy {
    RoundRobin,
    LeastConnections,
    Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct UpstreamTarget {
    pub id: String,
    pub address: String,
    #[serde(default)]
    pub active_connections: usize,
}

pub fn select_target<'a>(
    strategy: BalancingStrategy,
    targets: &'a [UpstreamTarget],
    request_key: Option<&str>,
    request_count: usize,
) -> Option<&'a UpstreamTarget> {
    match strategy {
        BalancingStrategy::RoundRobin => {
            let idx = request_count % targets.len();
            targets.get(idx)
        }
        BalancingStrategy::LeastConnections => {
            targets.iter().min_by_key(|target| target.active_connections)
        }
        BalancingStrategy::Hash => {
            use std::hash::{Hash, Hasher};

            let key = request_key?;
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            key.hash(&mut hasher);
            let idx = (hasher.finish() as usize) % targets.len();
            targets.get(idx)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{select_target, BalancingStrategy, UpstreamTarget};

    fn sample_targets() -> Vec<UpstreamTarget> {
        vec![
            UpstreamTarget {
                id: "a".to_string(),
                address: "10.0.0.1:8080".to_string(),
                active_connections: 4,
            },
            UpstreamTarget {
                id: "b".to_string(),
                address: "10.0.0.2:8080".to_string(),
                active_connections: 1,
            },
        ]
    }

    #[test]
    fn picks_least_connections() {
        let targets = sample_targets();
        let target = select_target(BalancingStrategy::LeastConnections, &targets, None, 0)
            .expect("a target should be selected");
        assert_eq!(target.id, "b");
    }

    #[test]
    fn picks_round_robin() {
        let targets = sample_targets();
        let target = select_target(BalancingStrategy::RoundRobin, &targets, None, 1)
            .expect("a target should be selected");
        assert_eq!(target.id, "b");
    }

    #[test]
    fn hash_requires_key() {
        let targets = sample_targets();
        let target = select_target(BalancingStrategy::Hash, &targets, None, 0);
        assert!(target.is_none());
    }
}
