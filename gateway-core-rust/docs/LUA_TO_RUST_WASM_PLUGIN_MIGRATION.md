# Lua to Rust/Wasm Plugin Migration Guide

## Goals
- Preserve plugin behavior while moving from Lua runtime hooks to Rust/Wasm runtime hooks.
- Keep contracts versioned with `contract_version: 1`.
- Restrict Wasm plugins to least-privilege capabilities.

## Step-by-step migration
1. Inventory Lua plugin phases and map them to Rust/Wasm phases (`init`, `access`, `header_filter`, `body_filter`, `log`).
2. Define plugin config with explicit `runtime`, `contract_version`, `phases`, and `capabilities`.
3. Start with native Rust plugin parity for behavior validation.
4. Move to Wasm runtime only for plugins that need sandbox isolation.
5. Validate route behavior, auth behavior, and traffic-control behavior under the compatibility matrix below.

## Compatibility test matrix
| Feature area | Native Rust | Wasm sandboxed |
|---|---|---|
| Init lifecycle | ✅ | ✅ |
| Access phase gating | ✅ | ✅ |
| Header filter phase | ✅ | ✅ |
| Body filter phase | ✅ | ✅ |
| Log phase | ✅ | ✅ |
| Contract version check | ✅ | ✅ |
| Capability policy enforcement | n/a | ✅ |
| Lifecycle rollback on init failure | ✅ | ✅ |

## Capability mapping
- `read_headers`: read inbound or outbound headers
- `write_headers`: mutate or append headers
- `read_body`: inspect body payloads
- `write_body`: mutate body payloads
- `rewrite_path`: perform path rewrite actions
- `emit_logs`: emit plugin-specific logs
