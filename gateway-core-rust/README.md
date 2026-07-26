# gateway-core-rust

First functional Rust replacement slice of a Kong-like gateway core.

Current slice includes:
- async HTTP gateway server (Tokio + Axum)
- route matching + upstream selection
- reverse proxy forwarding with hop-by-hop header filtering
- load balancing (round-robin, least-connections, hash)
- JWT auth verification + route RBAC checks
- in-memory token-bucket rate limiting
- plugin execution pipeline (declared plugin lifecycle)
- `/healthz` and `/metrics` endpoints with Prometheus text output

## Run

```bash
GATEWAY_CONFIG=examples/config.yaml cargo run
```

## Test

```bash
cargo test
```
