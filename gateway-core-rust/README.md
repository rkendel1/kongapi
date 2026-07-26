# gateway-core-rust

Minimal Rust scaffold for a Kong Gateway core rewrite effort.

Included modules:
- `router.rs` (reverse proxy route matching for HTTP/1.1, HTTP/2, gRPC)
- `balancer.rs` (round-robin, least-connections, hash balancing)
- `config.rs` (YAML/JSON declarative config + validation)
- `security.rs` (auth modes + route RBAC checks)
- `observability.rs` (tracing setup + in-process metrics counters)
- `plugin.rs` (trait-based plugin lifecycle + execution)
- `wasm_abi.rs` (portable Wasm ABI contract surface)

Run tests:

```bash
cargo test
```
