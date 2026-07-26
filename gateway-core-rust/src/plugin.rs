use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginContext {
    pub route: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginResult {
    pub allowed: bool,
    pub reason: Option<String>,
}

pub trait GatewayPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn init(&mut self) -> Result<(), String> {
        Ok(())
    }
    fn execute(&self, _ctx: &PluginContext) -> PluginResult;
    fn teardown(&mut self) -> Result<(), String> {
        Ok(())
    }
}

pub struct PluginManager {
    plugins: Vec<Box<dyn GatewayPlugin>>,
}

impl PluginManager {
    pub fn new() -> Self {
        Self { plugins: vec![] }
    }

    pub fn register(&mut self, mut plugin: Box<dyn GatewayPlugin>) -> Result<(), String> {
        plugin.init()?;
        self.plugins.push(plugin);
        Ok(())
    }

    pub fn run(&self, ctx: &PluginContext) -> PluginResult {
        for plugin in &self.plugins {
            let result = plugin.execute(ctx);
            if !result.allowed {
                return result;
            }
        }

        PluginResult {
            allowed: true,
            reason: None,
        }
    }
}

impl Drop for PluginManager {
    fn drop(&mut self) {
        for plugin in &mut self.plugins {
            let _ = plugin.teardown();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{GatewayPlugin, PluginContext, PluginManager, PluginResult};

    struct DenyPlugin;

    impl GatewayPlugin for DenyPlugin {
        fn name(&self) -> &str {
            "deny"
        }

        fn execute(&self, _ctx: &PluginContext) -> PluginResult {
            PluginResult {
                allowed: false,
                reason: Some("blocked".to_string()),
            }
        }
    }

    #[test]
    fn short_circuits_on_denied_plugin() {
        let mut manager = PluginManager::new();
        manager
            .register(Box::new(DenyPlugin))
            .expect("plugin registration should succeed");

        let result = manager.run(&PluginContext {
            route: "users".to_string(),
            path: "/users".to_string(),
        });

        assert_eq!(result.allowed, false);
        assert_eq!(result.reason.as_deref(), Some("blocked"));
    }
}
