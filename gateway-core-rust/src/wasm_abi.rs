use serde::{Deserialize, Serialize};

pub const ABI_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WasmPhase {
    Init,
    Access,
    HeaderFilter,
    BodyFilter,
    Log,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WasmCall {
    pub phase: WasmPhase,
    pub plugin: String,
    pub payload: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::{WasmCall, WasmPhase, ABI_VERSION};

    #[test]
    fn abi_version_is_set() {
        assert_eq!(ABI_VERSION, 1);
    }

    #[test]
    fn serializes_wasm_call() {
        let call = WasmCall {
            phase: WasmPhase::Access,
            plugin: "jwt_auth".to_string(),
            payload: vec![1, 2, 3],
        };

        let json = serde_json::to_string(&call).expect("serialization should succeed");
        assert!(json.contains("jwt_auth"));
    }
}
