# gateway-core-rust

First functional Rust replacement slice of a Kong-like gateway core.

Current slice includes:
- async HTTP gateway server (Tokio + Axum)
- route matching + upstream selection
- reverse proxy forwarding with hop-by-hop header filtering
- load balancing (round-robin, least-connections, hash)
- JWT auth verification + route RBAC checks
- OAuth2/OIDC bearer-token verification + group RBAC checks
- mTLS identity extraction hooks with route subject policy checks
- in-memory token-bucket, fixed-window, and sliding-window rate limiting
- route/service/consumer-scoped limits with optional quotas
- request/response transformations (headers, body replacement, path-prefix rewrite)
- canary upstream traffic splitting + weighted target balancing
- fault-injection controls (probabilistic abort and delay+jitter)
- plugin execution pipeline (declared plugin lifecycle)
- bounded retries for idempotent requests
- active/passive upstream health gating + circuit breaker state
- configurable timeout and keep-alive runtime settings
- graceful shutdown with in-flight request draining
- `/healthz` and `/metrics` endpoints with Prometheus text output

## Run

```bash
GATEWAY_CONFIG=examples/config.yaml cargo run
```

## Test

```bash
cargo test
```
