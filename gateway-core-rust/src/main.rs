mod balancer;
mod config;
mod observability;
mod plugin;
mod rate_limit;
mod router;
mod security;
mod wasm_abi;

use std::{net::SocketAddr, sync::Arc};

use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, State},
    http::{header::AUTHORIZATION, HeaderMap, Method, StatusCode, Uri, Version},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};

use balancer::select_target;
use config::GatewayConfig;
use observability::Metrics;
use plugin::{PluginContext, PluginManager};
use rate_limit::RateLimiter;
use router::Protocol;
use security::{AuthContext, AuthMode};

#[derive(Clone)]
struct AppState {
    config: Arc<GatewayConfig>,
    metrics: Arc<Metrics>,
    limiter: Arc<RateLimiter>,
    plugins: Arc<PluginManager>,
    client: reqwest::Client,
    request_counter: Arc<std::sync::atomic::AtomicUsize>,
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

    let state = AppState {
        config: Arc::new(config.clone()),
        metrics: Arc::new(Metrics::default()),
        limiter: Arc::new(RateLimiter::new(config.rate_limit.clone())),
        plugins: Arc::new(plugin_manager),
        client: reqwest::Client::builder()
            .danger_accept_invalid_certs(false)
            .build()
            .expect("reqwest client creation should succeed"),
        request_counter: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    };

    let app = Router::new()
        .route("/healthz", get(healthz_handler))
        .route("/metrics", get(metrics_handler))
        .fallback(proxy_handler)
        .with_state(Arc::new(state));

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
        .await
        .expect("gateway server failed");
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

    let request_count = state
        .request_counter
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let target = match select_target(
        upstream.strategy.clone(),
        &upstream.targets,
        Some(&client_key),
        request_count,
    ) {
        Some(target) => target,
        None => {
            state.metrics.inc_error();
            return (StatusCode::BAD_GATEWAY, "no upstream target available").into_response();
        }
    };

    let upstream_url = format!("http://{}{}", target.address, path_and_query);

    let body_bytes = match to_bytes(body, 8 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => {
            state.metrics.inc_error();
            return (StatusCode::BAD_REQUEST, "failed to read request body").into_response();
        }
    };

    let mut request_builder = state.client.request(method.clone(), upstream_url);
    for (name, value) in &headers {
        if !is_hop_by_hop_header(name.as_str()) && name.as_str() != "host" {
            request_builder = request_builder.header(name, value);
        }
    }

    let upstream_response = match request_builder.body(body_bytes).send().await {
        Ok(response) => response,
        Err(err) => {
            state.metrics.inc_upstream_failure();
            tracing::error!(error = %err, route = %route.name, "upstream request failed");
            return (StatusCode::BAD_GATEWAY, "upstream request failed").into_response();
        }
    };

    let status = upstream_response.status();
    let upstream_headers = upstream_response.headers().clone();
    let response_body = match upstream_response.bytes().await {
        Ok(body) => body,
        Err(err) => {
            state.metrics.inc_upstream_failure();
            tracing::error!(error = %err, "failed to read upstream response body");
            return (StatusCode::BAD_GATEWAY, "upstream response invalid").into_response();
        }
    };

    let mut response_builder = Response::builder().status(status);
    for (name, value) in &upstream_headers {
        if !is_hop_by_hop_header(name.as_str()) {
            response_builder = response_builder.header(name, value);
        }
    }

    response_builder
        .body(Body::from(response_body))
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "failed to build response").into_response())
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
