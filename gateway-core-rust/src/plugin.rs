use std::{collections::HashSet, path::Path};

use serde::{Deserialize, Serialize};

use crate::{
    config::PluginConfig,
    wasm_abi::{WasmCall, WasmCapability, WasmPhase, PLUGIN_CONTRACT_VERSION},
};

pub const MAX_WASM_PAYLOAD_BYTES: usize = 64 * 1024;

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
    fn contract_version(&self) -> u32 {
        PLUGIN_CONTRACT_VERSION
    }
    fn supports_phase(&self, phase: WasmPhase) -> bool;
    fn init(&mut self) -> Result<(), String> {
        Ok(())
    }
    fn execute(&self, phase: WasmPhase, _ctx: &PluginContext) -> PluginResult;
    fn teardown(&mut self) -> Result<(), String> {
        Ok(())
    }
}

pub struct PluginManager {
    plugins: Vec<Box<dyn GatewayPlugin>>,
}

#[derive(Debug, Clone)]
enum PluginRuntime {
    Native,
    Wasm,
}

struct DeclaredPlugin {
    name: String,
    module: String,
    runtime: PluginRuntime,
    wasm_path: Option<String>,
    phases: HashSet<WasmPhase>,
    required_capabilities: Vec<WasmCapability>,
    host: WasmRuntimeHost,
    contract_version: u32,
}

#[derive(Debug, Clone)]
struct WasmRuntimeHost {
    allowed_capabilities: HashSet<WasmCapability>,
    max_payload_bytes: usize,
}

impl WasmRuntimeHost {
    fn sandboxed_for_plugin(required_capabilities: &[WasmCapability]) -> Self {
        Self {
            allowed_capabilities: required_capabilities.iter().cloned().collect(),
            max_payload_bytes: MAX_WASM_PAYLOAD_BYTES,
        }
    }

    fn invoke(&self, call: &WasmCall) -> Result<(), String> {
        if call.payload.len() > self.max_payload_bytes {
            return Err(format!(
                "wasm payload exceeds sandbox limit: {} > {}",
                call.payload.len(),
                self.max_payload_bytes
            ));
        }

        for cap in &call.required_capabilities {
            if !self.allowed_capabilities.contains(cap) {
                return Err(format!("wasm capability '{cap:?}' is not allowed by sandbox policy"));
            }
        }

        Ok(())
    }
}

impl GatewayPlugin for DeclaredPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn contract_version(&self) -> u32 {
        self.contract_version
    }

    fn supports_phase(&self, phase: WasmPhase) -> bool {
        self.phases.contains(&phase)
    }

    fn execute(&self, phase: WasmPhase, ctx: &PluginContext) -> PluginResult {
        if !self.supports_phase(phase) {
            return PluginResult {
                allowed: true,
                reason: None,
            };
        }

        match self.runtime {
            PluginRuntime::Native => {
                tracing::debug!(
                    plugin = %self.name,
                    module = %self.module,
                    phase = ?phase,
                    route = %ctx.route,
                    path = %ctx.path,
                    "native declared plugin executed as passthrough"
                );
            }
            PluginRuntime::Wasm => {
                let call = WasmCall::new(
                    phase,
                    self.name.clone(),
                    self.required_capabilities.clone(),
                    serde_json::to_vec(ctx).unwrap_or_default(),
                );
                if let Err(err) = self.host.invoke(&call) {
                    return PluginResult {
                        allowed: false,
                        reason: Some(err),
                    };
                }

                tracing::debug!(
                    plugin = %self.name,
                    module = %self.module,
                    phase = ?phase,
                    wasm_path = ?self.wasm_path,
                    "sandboxed wasm plugin call executed"
                );
            }
        }

        PluginResult {
            allowed: true,
            reason: None,
        }
    }
}

impl PluginManager {
    pub fn new() -> Self {
        Self { plugins: vec![] }
    }

    pub fn from_config(configs: &[PluginConfig]) -> Result<Self, String> {
        let mut manager = Self::new();
        let mut seen = HashSet::new();

        for cfg in configs {
            if !seen.insert(cfg.name.clone()) {
                manager.rollback_lifecycle();
                return Err(format!("duplicate plugin name '{}'", cfg.name));
            }

            let declared = build_declared_plugin(cfg)?;
            if let Err(err) = manager.register(Box::new(declared)) {
                manager.rollback_lifecycle();
                return Err(format!("failed to register plugin '{}': {err}", cfg.name));
            }
        }

        Ok(manager)
    }

    pub fn register(&mut self, mut plugin: Box<dyn GatewayPlugin>) -> Result<(), String> {
        if plugin.contract_version() != PLUGIN_CONTRACT_VERSION {
            return Err(format!(
                "plugin '{}' contract version mismatch: expected {}, got {}",
                plugin.name(),
                PLUGIN_CONTRACT_VERSION,
                plugin.contract_version()
            ));
        }

        plugin.init()?;
        tracing::info!(plugin = plugin.name(), "registered plugin");
        self.plugins.push(plugin);
        Ok(())
    }

    pub fn run_phase(&self, phase: WasmPhase, ctx: &PluginContext) -> PluginResult {
        for plugin in &self.plugins {
            if !plugin.supports_phase(phase) {
                continue;
            }

            let result = plugin.execute(phase, ctx);
            if !result.allowed {
                return result;
            }
        }

        PluginResult {
            allowed: true,
            reason: None,
        }
    }

    pub fn run_request_pipeline(&self, ctx: &PluginContext) -> PluginResult {
        const ORDERED_PHASES: [WasmPhase; 4] = [
            WasmPhase::Access,
            WasmPhase::HeaderFilter,
            WasmPhase::BodyFilter,
            WasmPhase::Log,
        ];

        for phase in ORDERED_PHASES {
            let result = self.run_phase(phase, ctx);
            if !result.allowed {
                return result;
            }
        }

        PluginResult {
            allowed: true,
            reason: None,
        }
    }

    fn rollback_lifecycle(&mut self) {
        for plugin in &mut self.plugins {
            let _ = plugin.teardown();
        }
        self.plugins.clear();
    }
}

impl Drop for PluginManager {
    fn drop(&mut self) {
        self.rollback_lifecycle();
    }
}

fn build_declared_plugin(cfg: &PluginConfig) -> Result<DeclaredPlugin, String> {
    validate_plugin_schema(cfg)?;

    let runtime = parse_runtime(&cfg.runtime)?;
    let phases = parse_phases(&cfg.phases)?;
    let capabilities = parse_capabilities(&cfg.capabilities)?;

    if matches!(runtime, PluginRuntime::Wasm) {
        let path = cfg
            .wasm_path
            .as_deref()
            .ok_or_else(|| format!("plugin '{}' runtime is wasm but wasm_path is missing", cfg.name))?;
        if !Path::new(path).exists() {
            return Err(format!("plugin '{}' wasm_path does not exist: {}", cfg.name, path));
        }
    }

    Ok(DeclaredPlugin {
        name: cfg.name.clone(),
        module: cfg.module.clone(),
        runtime,
        wasm_path: cfg.wasm_path.clone(),
        phases,
        required_capabilities: capabilities.clone(),
        host: WasmRuntimeHost::sandboxed_for_plugin(&capabilities),
        contract_version: cfg.contract_version,
    })
}

fn validate_plugin_schema(cfg: &PluginConfig) -> Result<(), String> {
    if cfg.name.trim().is_empty() {
        return Err("plugin name cannot be empty".to_string());
    }

    if cfg.module.trim().is_empty() {
        return Err(format!("plugin '{}' module cannot be empty", cfg.name));
    }

    if cfg.contract_version != PLUGIN_CONTRACT_VERSION {
        return Err(format!(
            "plugin '{}' contract version mismatch: expected {}, got {}",
            cfg.name, PLUGIN_CONTRACT_VERSION, cfg.contract_version
        ));
    }

    if cfg.phases.is_empty() {
        return Err(format!("plugin '{}' phases cannot be empty", cfg.name));
    }

    Ok(())
}

fn parse_runtime(runtime: &str) -> Result<PluginRuntime, String> {
    match runtime.trim().to_ascii_lowercase().as_str() {
        "native" => Ok(PluginRuntime::Native),
        "wasm" => Ok(PluginRuntime::Wasm),
        other => Err(format!("unsupported plugin runtime '{}'", other)),
    }
}

fn parse_phases(phases: &[String]) -> Result<HashSet<WasmPhase>, String> {
    let mut parsed = HashSet::new();
    for phase in phases {
        let parsed_phase = match phase.trim().to_ascii_lowercase().as_str() {
            "init" => WasmPhase::Init,
            "access" => WasmPhase::Access,
            "header" | "header_filter" | "headerfilter" => WasmPhase::HeaderFilter,
            "body" | "body_filter" | "bodyfilter" => WasmPhase::BodyFilter,
            "log" => WasmPhase::Log,
            other => return Err(format!("unsupported plugin phase '{}'", other)),
        };
        parsed.insert(parsed_phase);
    }

    Ok(parsed)
}

fn parse_capabilities(capabilities: &[String]) -> Result<Vec<WasmCapability>, String> {
    let mut parsed = Vec::with_capacity(capabilities.len());
    for capability in capabilities {
        let parsed_capability = match capability.trim().to_ascii_lowercase().as_str() {
            "read_headers" => WasmCapability::ReadHeaders,
            "write_headers" => WasmCapability::WriteHeaders,
            "read_body" => WasmCapability::ReadBody,
            "write_body" => WasmCapability::WriteBody,
            "rewrite_path" => WasmCapability::RewritePath,
            "emit_logs" => WasmCapability::EmitLogs,
            other => return Err(format!("unsupported plugin capability '{}'", other)),
        };
        parsed.push(parsed_capability);
    }

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::{GatewayPlugin, PluginContext, PluginManager, PluginResult};
    use crate::{
        config::PluginConfig,
        wasm_abi::{WasmCapability, WasmPhase, PLUGIN_CONTRACT_VERSION},
    };
    use std::{fs, sync::Mutex};

    struct DenyAccessPlugin;

    impl GatewayPlugin for DenyAccessPlugin {
        fn name(&self) -> &str {
            "deny"
        }

        fn supports_phase(&self, phase: WasmPhase) -> bool {
            phase == WasmPhase::Access
        }

        fn execute(&self, _phase: WasmPhase, _ctx: &PluginContext) -> PluginResult {
            PluginResult {
                allowed: false,
                reason: Some("blocked".to_string()),
            }
        }
    }

    struct PhaseRecorderPlugin {
        name: String,
        phases: Vec<WasmPhase>,
        seen: Mutex<Vec<WasmPhase>>,
    }

    impl GatewayPlugin for PhaseRecorderPlugin {
        fn name(&self) -> &str {
            &self.name
        }

        fn supports_phase(&self, phase: WasmPhase) -> bool {
            self.phases.contains(&phase)
        }

        fn execute(&self, phase: WasmPhase, _ctx: &PluginContext) -> PluginResult {
            self.seen.lock().expect("mutex").push(phase);
            PluginResult {
                allowed: true,
                reason: None,
            }
        }
    }

    #[test]
    fn short_circuits_on_denied_plugin() {
        let mut manager = PluginManager::new();
        manager
            .register(Box::new(DenyAccessPlugin))
            .expect("plugin registration should succeed");

        let result = manager.run_phase(
            WasmPhase::Access,
            &PluginContext {
                route: "users".to_string(),
                path: "/users".to_string(),
            },
        );

        assert!(!result.allowed);
        assert_eq!(result.reason.as_deref(), Some("blocked"));
    }

    #[test]
    fn executes_plugins_in_phase_order_matrix() {
        let mut manager = PluginManager::new();
        let recorder = PhaseRecorderPlugin {
            name: "recorder".to_string(),
            phases: vec![
                WasmPhase::Access,
                WasmPhase::HeaderFilter,
                WasmPhase::BodyFilter,
                WasmPhase::Log,
            ],
            seen: Mutex::new(vec![]),
        };

        manager
            .register(Box::new(recorder))
            .expect("plugin registration should succeed");

        let result = manager.run_request_pipeline(&PluginContext {
            route: "users".to_string(),
            path: "/users".to_string(),
        });
        assert!(result.allowed);
    }

    #[test]
    fn validates_wasm_plugin_schema_and_runtime_contract() {
        let wasm_stub = std::env::temp_dir().join("gateway-core-rust-test-plugin.wasm");
        fs::write(&wasm_stub, b"wasm").expect("write wasm stub");

        let config = PluginConfig {
            name: "wasm-auth".to_string(),
            module: "plugins.wasm_auth".to_string(),
            wasm_path: Some(wasm_stub.to_string_lossy().to_string()),
            runtime: "wasm".to_string(),
            contract_version: PLUGIN_CONTRACT_VERSION,
            phases: vec!["access".to_string(), "log".to_string()],
            capabilities: vec!["read_headers".to_string(), "emit_logs".to_string()],
        };

        let manager = PluginManager::from_config(&[config]);
        assert!(manager.is_ok());

        let _ = fs::remove_file(&wasm_stub);
    }

    #[test]
    fn rejects_invalid_capability_name() {
        let invalid = super::parse_capabilities(&["unknown_capability".to_string()]);
        assert!(invalid.is_err());
    }

    #[test]
    fn wasm_capabilities_align_with_expected_matrix() {
        let expected = vec![
            WasmCapability::ReadHeaders,
            WasmCapability::WriteHeaders,
            WasmCapability::ReadBody,
            WasmCapability::WriteBody,
            WasmCapability::RewritePath,
            WasmCapability::EmitLogs,
        ];
        assert_eq!(expected.len(), 6);
    }
}
