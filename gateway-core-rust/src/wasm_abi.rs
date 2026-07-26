use serde::{Deserialize, Serialize};

pub const ABI_VERSION: u32 = 1;
pub const PLUGIN_CONTRACT_VERSION: u32 = 1;

#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum WasmPhase {
    Init,
    Access,
    HeaderFilter,
    BodyFilter,
    Log,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum WasmCapability {
    ReadHeaders,
    WriteHeaders,
    ReadBody,
    WriteBody,
    RewritePath,
    EmitLogs,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WasmCall {
    pub abi_version: u32,
    pub plugin_contract_version: u32,
    pub phase: WasmPhase,
    pub plugin: String,
    pub required_capabilities: Vec<WasmCapability>,
    pub payload: Vec<u8>,
}

impl WasmCall {
    pub fn new(
        phase: WasmPhase,
        plugin: String,
        required_capabilities: Vec<WasmCapability>,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            abi_version: ABI_VERSION,
            plugin_contract_version: PLUGIN_CONTRACT_VERSION,
            phase,
            plugin,
            required_capabilities,
            payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{WasmCall, WasmCapability, WasmPhase, ABI_VERSION, PLUGIN_CONTRACT_VERSION};

    #[test]
    fn abi_version_is_set() {
        assert_eq!(ABI_VERSION, 1);
        assert_eq!(PLUGIN_CONTRACT_VERSION, 1);
    }

    #[test]
    fn serializes_wasm_call() {
        let call = WasmCall::new(
            WasmPhase::Access,
            "jwt_auth".to_string(),
            vec![WasmCapability::ReadHeaders],
            vec![1, 2, 3],
        );

        let json = serde_json::to_string(&call).expect("serialization should succeed");
        assert!(json.contains("jwt_auth"));
        assert!(json.contains("plugin_contract_version"));
    }
}
