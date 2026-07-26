mod balancer;
mod config;
mod observability;
mod plugin;
mod router;
mod security;
mod wasm_abi;

use config::GatewayConfig;

#[tokio::main]
async fn main() {
    observability::init_tracing();

    let config_path = std::env::var("GATEWAY_CONFIG").unwrap_or_else(|_| "examples/config.yaml".to_string());
    match GatewayConfig::load_from_path(&config_path) {
        Ok(config) => {
            tracing::info!(routes = config.routes.len(), upstreams = config.upstreams.len(), "gateway-core-rust booted");
        }
        Err(err) => {
            tracing::error!(error = %err, "failed to load configuration");
            std::process::exit(1);
        }
    }
}
