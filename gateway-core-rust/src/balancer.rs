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
    #[serde(default = "default_target_weight")]
    pub weight: u32,
}

fn default_target_weight() -> u32 {
    1
}

pub fn select_target<'a>(
    strategy: BalancingStrategy,
    targets: &'a [UpstreamTarget],
    request_key: Option<&str>,
    request_count: usize,
) -> Option<&'a UpstreamTarget> {
    match strategy {
        BalancingStrategy::RoundRobin => pick_weighted_target(targets, request_count),
        BalancingStrategy::LeastConnections => targets
            .iter()
            .filter(|target| target.weight > 0)
            .min_by_key(|target| {
                let weight = target.weight as usize;
                if weight == 0 {
                    usize::MAX
                } else {
                    target.active_connections / weight
                }
            }),
        BalancingStrategy::Hash => {
            use std::hash::{Hash, Hasher};

            let key = request_key?;
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            key.hash(&mut hasher);
            pick_weighted_target(targets, hasher.finish() as usize)
        }
    }
}

fn pick_weighted_target<'a>(targets: &'a [UpstreamTarget], seed: usize) -> Option<&'a UpstreamTarget> {
    let total_weight: u32 = targets.iter().map(|target| target.weight).sum();
    if total_weight == 0 {
        return None;
    }

    let mut cursor = (seed as u32) % total_weight;
    for target in targets {
        if target.weight == 0 {
            continue;
        }

        if cursor < target.weight {
            return Some(target);
        }

        cursor -= target.weight;
    }

    None
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
                weight: 1,
            },
            UpstreamTarget {
                id: "b".to_string(),
                address: "10.0.0.2:8080".to_string(),
                active_connections: 1,
                weight: 3,
            },
        ]
    }

    #[test]
    fn picks_weighted_round_robin() {
        let targets = sample_targets();
        let t0 = select_target(BalancingStrategy::RoundRobin, &targets, None, 0).expect("target");
        let t1 = select_target(BalancingStrategy::RoundRobin, &targets, None, 1).expect("target");
        let t3 = select_target(BalancingStrategy::RoundRobin, &targets, None, 3).expect("target");
        assert_eq!(t0.id, "a");
        assert_eq!(t1.id, "b");
        assert_eq!(t3.id, "b");
    }

    #[test]
    fn picks_weighted_least_connections() {
        let targets = sample_targets();
        let target = select_target(BalancingStrategy::LeastConnections, &targets, None, 0)
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
