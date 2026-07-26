mod balancer;
mod config;
mod observability;
mod plugin;
mod rate_limit;
mod resilience;
mod router;
mod security;
mod wasm_abi;

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, State},
    http::{header::AUTHORIZATION, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, Version},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};

use balancer::select_target;
use config::{GatewayConfig, UpstreamConfig};
use observability::Metrics;
use plugin::{PluginContext, PluginManager};
use rate_limit::RateLimiter;
use resilience::{should_retry_method, should_retry_status, target_key, RuntimeRegistry};
use router::Protocol;
use security::{AuthContext, AuthMode};

#[derive(Clone)]
struct AppState {
    config: Arc<GatewayConfig>,
    metrics: Arc<Metrics>,
    limiter: Arc<RateLimiter>,
    plugins: Arc<PluginManager>,
    client: reqwest::Client,
    request_counter: Arc<AtomicUsize>,
    draining: Arc<AtomicBool>,
    in_flight: Arc<AtomicUsize>,
    runtime: Arc<HashMap<String, Arc<RuntimeRegistry>>>,
}

struct InFlightGuard {
    counter: Arc<AtomicUsize>,
}

impl InFlightGuard {
    fn new(counter: Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self { counter }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

#[tokio::main]
async fn main() {
    observability::init_tracing();

    let config_path = std::env::var("GATEWAY_CONFIG").unwrap_or_else(|_| "examples/config.yaml".to_string());
    let config = match GatewayConfig::load_from_path(&config_path) {
        Ok(config) => config,
        Err(err) => {
            tracing::error!(error = %err, "failed to load configuration");
            std::process::exit(1);
        }
    };

    let plugin_manager = match PluginManager::from_config(&config.plugins) {
        Ok(manager) => manager,
        Err(err) => {
            tracing::error!(error = %err, "failed to initialize plugins");
            std::process::exit(1);
        }
    };

    let runtime = Arc::new(build_runtime_registry(&config));

    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(config.server.proxy.max_idle_per_host)
        .pool_idle_timeout(Duration::from_secs(config.server.proxy.idle_timeout_secs))
        .connect_timeout(Duration::from_millis(config.server.proxy.connect_timeout_ms))
        .timeout(Duration::from_millis(config.server.proxy.read_timeout_ms))
        .build()
        .expect("reqwest client creation should succeed");

    let state = AppState {
        config: Arc::new(config.clone()),
        metrics: Arc::new(Metrics::default()),
        limiter: Arc::new(RateLimiter::new(config.rate_limit.clone())),
        plugins: Arc::new(plugin_manager),
        client,
        request_counter: Arc::new(AtomicUsize::new(0)),
        draining: Arc::new(AtomicBool::new(false)),
        in_flight: Arc::new(AtomicUsize::new(0)),
        runtime,
    };

    spawn_active_health_checks(&state);

    let app = Router::new()
        .route("/healthz", get(healthz_handler))
        .route("/metrics", get(metrics_handler))
        .fallback(proxy_handler)
        .with_state(Arc::new(state.clone()));

    let addr: SocketAddr = config
        .server
        .listen_addr
        .parse()
        .expect("listen_addr should be a valid socket address");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind listener");

    tracing::info!(listen_addr = %addr, "gateway core rust slice listening");

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(graceful_shutdown_signal(Arc::new(state), config.server.shutdown.clone()))
        .await
        .expect("gateway server failed");
}

fn build_runtime_registry(config: &GatewayConfig) -> HashMap<String, Arc<RuntimeRegistry>> {
    config
        .upstreams
        .iter()
        .map(|upstream| {
            (
                upstream.name.clone(),
                Arc::new(RuntimeRegistry::new(
                    upstream.health_checks.passive.clone(),
                    upstream.circuit_breaker.clone(),
                )),
            )
        })
        .collect()
}

fn spawn_active_health_checks(state: &AppState) {
    for upstream in &state.config.upstreams {
        if !upstream.health_checks.active.enabled {
            continue;
        }

        let Some(registry) = state.runtime.get(&upstream.name).cloned() else {
            continue;
        };

        let client = state.client.clone();
        let draining = state.draining.clone();
        let upstream_name = upstream.name.clone();
        let targets = upstream.targets.clone();
        let active_cfg = upstream.health_checks.active.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(active_cfg.interval_ms));
            loop {
                interval.tick().await;
                if draining.load(Ordering::Relaxed) {
                    break;
                }

                for target in &targets {
                    let url = format!("http://{}{}", target.address, active_cfg.path);
                    let healthy = match client
                        .get(url)
                        .timeout(Duration::from_millis(active_cfg.timeout_ms))
                        .send()
                        .await
                    {
                        Ok(resp) => resp.status().is_success(),
                        Err(_) => false,
                    };

                    registry.set_active_health(&target_key(&upstream_name, &target.id), healthy);
                }
            }
        });
    }
}

async fn healthz_handler() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn metrics_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    (
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        state.metrics.render_prometheus(),
    )
}

async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    version: Version,
    headers: HeaderMap,
    body: Body,
) -> Response {
    state.metrics.inc_request();

    if state.draining.load(Ordering::Relaxed) {
        return (StatusCode::SERVICE_UNAVAILABLE, "gateway is draining").into_response();
    }

    let _guard = InFlightGuard::new(state.in_flight.clone());

    let protocol = match version {
        Version::HTTP_2 => Protocol::Http2,
        _ => Protocol::Http1,
    };

    let path = uri.path();
    let path_and_query = uri.path_and_query().map(|v| v.as_str()).unwrap_or(path);

    let route = match router::match_route(&state.config.routes, path, protocol) {
        Some(route) => route,
        None => return (StatusCode::NOT_FOUND, "no matching route").into_response(),
    };

    let plugin_result = state.plugins.run(&PluginContext {
        route: route.name.clone(),
        path: path.to_string(),
    });

    if !plugin_result.allowed {
        state.metrics.inc_unauthorized();
        return (
            StatusCode::FORBIDDEN,
            plugin_result.reason.unwrap_or_else(|| "blocked by plugin".to_string()),
        )
            .into_response();
    }

    let auth_header = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok());

    let roles = match state.config.security.authenticate_jwt(auth_header) {
        Ok(roles) => roles,
        Err(err) => {
            state.metrics.inc_unauthorized();
            tracing::warn!(error = %err, route = %route.name, "authentication failed");
            return (StatusCode::UNAUTHORIZED, "authentication failed").into_response();
        }
    };

    let auth_ctx = AuthContext {
        mode: AuthMode::Jwt,
        roles: &roles,
        route_name: &route.name,
    };

    if !state.config.security.authorize(&auth_ctx) {
        state.metrics.inc_unauthorized();
        return (StatusCode::FORBIDDEN, "authorization denied").into_response();
    }

    let client_key = format!("{}:{}", route.name, client_addr.ip());
    if !state.limiter.check(&client_key) {
        state.metrics.inc_rate_limited();
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    }

    let upstream = match state
        .config
        .upstreams
        .iter()
        .find(|upstream| upstream.name == route.upstream)
    {
        Some(upstream) => upstream,
        None => {
            state.metrics.inc_error();
            return (StatusCode::BAD_GATEWAY, "upstream config not found").into_response();
        }
    };

    let Some(runtime_registry) = state.runtime.get(&upstream.name) else {
        state.metrics.inc_error();
        return (StatusCode::BAD_GATEWAY, "runtime state unavailable").into_response();
    };

    let forwarded_headers = forwardable_headers(&headers);
    let overall_timeout = Duration::from_millis(state.config.server.proxy.request_timeout_ms);
    let retry_cfg = &state.config.server.proxy.retries;
    let max_attempts = if should_retry_method(&method, retry_cfg.idempotent_only) {
        retry_cfg.max_attempts.max(1)
    } else {
        1
    };

    let body_bytes = match to_bytes(body, state.config.server.max_request_body_bytes).await {
        Ok(bytes) => bytes,
        Err(_) => {
            state.metrics.inc_error();
            return (StatusCode::BAD_REQUEST, "failed to read request body").into_response();
        }
    };

    let mut last_status: Option<StatusCode> = None;
    let started = Instant::now();
    for attempt in 1..=max_attempts {
        if started.elapsed() >= overall_timeout {
            state.metrics.inc_upstream_failure();
            return (StatusCode::GATEWAY_TIMEOUT, "upstream request timed out").into_response();
        }

        let request_count = state.request_counter.fetch_add(1, Ordering::Relaxed);
        let Some(target) = pick_target(upstream, runtime_registry, &client_key, request_count + attempt as usize) else {
            state.metrics.inc_error();
            return (StatusCode::BAD_GATEWAY, "no healthy upstream target available").into_response();
        };

        let target_runtime_key = target_key(&upstream.name, &target.id);
        let upstream_url = format!("http://{}{}", target.address, path_and_query);

        let mut request_builder = state.client.request(method.clone(), upstream_url);
        for (name, value) in &forwarded_headers {
            request_builder = request_builder.header(name, value);
        }

        let send_result = request_builder.body(body_bytes.clone()).send().await;
        let upstream_response = match send_result {
            Ok(response) => response,
            Err(err) => {
                runtime_registry.record_failure(&target_runtime_key);
                state.metrics.inc_upstream_failure();
                tracing::warn!(error = %err, route = %route.name, attempt, "upstream request failed");

                if attempt < max_attempts {
                    tokio::time::sleep(Duration::from_millis(retry_cfg.backoff_ms)).await;
                    continue;
                }

                return (StatusCode::BAD_GATEWAY, "upstream request failed").into_response();
            }
        };

        if should_retry_status(upstream_response.status()) && attempt < max_attempts {
            runtime_registry.record_failure(&target_runtime_key);
            last_status = Some(upstream_response.status());
            tokio::time::sleep(Duration::from_millis(retry_cfg.backoff_ms)).await;
            continue;
        }

        if upstream_response.status().is_server_error() {
            runtime_registry.record_failure(&target_runtime_key);
        } else {
            runtime_registry.record_success(&target_runtime_key);
        }

        let status = upstream_response.status();
        let upstream_headers = upstream_response.headers().clone();
        let response_stream = upstream_response.bytes_stream();

        let mut response_builder = Response::builder().status(status);
        for (name, value) in &upstream_headers {
            if !is_hop_by_hop_header(name.as_str()) {
                response_builder = response_builder.header(name, value);
            }
        }

        return response_builder
            .body(Body::from_stream(response_stream))
            .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "failed to build response").into_response());
    }

    match last_status {
        Some(status) => (status, "upstream retries exhausted").into_response(),
        None => (StatusCode::BAD_GATEWAY, "upstream retries exhausted").into_response(),
    }
}

fn pick_target(
    upstream: &UpstreamConfig,
    runtime: &RuntimeRegistry,
    request_key: &str,
    request_count: usize,
) -> Option<crate::balancer::UpstreamTarget> {
    let available_targets = upstream
        .targets
        .iter()
        .filter(|target| runtime.is_available(&target_key(&upstream.name, &target.id)))
        .cloned()
        .collect::<Vec<_>>();

    if available_targets.is_empty() {
        return None;
    }

    select_target(
        upstream.strategy.clone(),
        &available_targets,
        Some(request_key),
        request_count,
    )
    .cloned()
}

async fn graceful_shutdown_signal(state: Arc<AppState>, shutdown_cfg: config::ShutdownConfig) {
    if tokio::signal::ctrl_c().await.is_err() {
        return;
    }

    tracing::info!("shutdown signal received; entering draining mode");
    state.draining.store(true, Ordering::Relaxed);

    let deadline = Instant::now() + Duration::from_millis(shutdown_cfg.drain_timeout_ms);
    while state.in_flight.load(Ordering::Relaxed) > 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(shutdown_cfg.drain_poll_ms)).await;
    }

    tracing::info!(in_flight = state.in_flight.load(Ordering::Relaxed), "draining complete");
}

fn forwardable_headers(headers: &HeaderMap) -> Vec<(HeaderName, HeaderValue)> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            let header_name = name.as_str();
            if is_hop_by_hop_header(header_name) || header_name.eq_ignore_ascii_case("host") {
                return None;
            }

            Some((name.clone(), value.clone()))
        })
        .collect()
}

fn is_hop_by_hop_header(header_name: &str) -> bool {
    matches!(
        header_name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}
