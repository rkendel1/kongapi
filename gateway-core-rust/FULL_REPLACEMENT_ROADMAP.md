# Full Replacement Roadmap (PR-by-PR)

This roadmap defines an incremental path from the current Rust first slice to feature parity with Kong Gateway core behavior.

## PR1 (already delivered)
- Create `gateway-core-rust` service with:
  - async HTTP server
  - reverse proxy forwarding
  - route matching
  - upstream balancing strategies
  - JWT + RBAC auth checks
  - in-memory rate limiting
  - plugin lifecycle scaffolding and declared Wasm plugin contract surface
  - baseline metrics/tracing endpoints

## PR2 (completed) — Production proxy/runtime hardening
- Add connection pooling and upstream keep-alive policy tuning.
- Add request/response streaming proxy mode (avoid full-body buffering).
- Add retries with bounded policy and idempotency checks.
- Add active/passive upstream health checks.
- Add circuit breaker per upstream and per-target.
- Add configurable timeout budgets (connect/read/write/overall).
- Add graceful shutdown and draining for in-flight requests.
- Add conformance/perf tests for concurrent load and backpressure.

## PR3 (completed) — Full protocol parity layer
- Complete HTTP/2 and gRPC routing semantics parity.
- Add TLS termination and upstream TLS/mTLS support.
- Add SNI/certificate selection and rotation hooks.
- Add L4 proxy mode planning and L7/L4 boundary interfaces.
- Add compatibility test suite against representative Kong route cases.

## PR4 (completed) — Security parity expansion
- Add OAuth2 and OpenID Connect verification flows.
- Add mTLS identity extraction and policy enforcement.
- Add ACL/group authorization model parity with Kong behavior.
- Add external secrets manager integration contracts (Vault/AWS/GCP).
- Add key/cert hot reload and secret rotation handling.
- Add security-focused integration tests and threat-model checks.

## PR5 (completed) — Traffic controls parity
- Add sliding window and fixed window policies in addition to token bucket.
- Add route/service/consumer-scoped limits and quotas.
- Add request/response transformations (headers/body/path rewrite).
- Add canary and weighted traffic splitting primitives.
- Add advanced fault-injection controls for resilience testing.

## PR6 (completed) — Plugin runtime parity (native + Wasm)
- Finalize stable Rust plugin trait contracts with versioning.
- Implement Wasm runtime host with sandboxed capability model.
- Add plugin phase ordering parity (init/access/header/body/log).
- Add plugin config schema validation and lifecycle rollback.
- Add migration tooling guidance from Lua plugins to Rust/Wasm plugins.
- Add plugin compatibility test matrix.

## PR7 — Configuration and control plane parity
- Add DB-less declarative config parity surface.
- Add live config reload with transactional validation/swap.
- Add compatibility ingest for existing Kong declarative syntax.
- Add hybrid mode control-plane/data-plane sync contracts.
- Add rollback-safe config rollout and diff-based apply.

## PR8 — Observability and operations parity
- Add OpenTelemetry spans/attributes parity.
- Add richer Prometheus metrics parity (latency histograms, labels).
- Add structured access/error log sinks and sampling controls.
- Add runtime diagnostics endpoints and debug profiles.
- Add SLO dashboards + alerting reference pack.

## PR9 — Kubernetes and deployment parity
- Add Kubernetes-native deployment manifests and probes.
- Integrate control hooks needed by ingress workflows.
- Add rolling upgrade and config migration docs.
- Add edge/cloud deployment profiles and benchmark baselines.

## PR10 — Cutover readiness and parity certification
- Execute parity checklist against agreed Kong feature matrix.
- Run staged traffic replay and side-by-side validation.
- Fix parity gaps and publish known differences.
- Produce migration runbook for production cutover.
- Mark Rust core as replacement-ready for controlled adoption.

## Definition of Done for full replacement
- Feature matrix complete for required proxy, security, traffic control, plugin, and observability capabilities.
- Stability/performance targets met under representative production workloads.
- Migration path documented for configurations and plugin model transitions.
- Operational playbooks validated (upgrade, rollback, incident handling).
