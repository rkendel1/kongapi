use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct Metrics {
    total_requests: AtomicU64,
    total_errors: AtomicU64,
    total_unauthorized: AtomicU64,
    total_rate_limited: AtomicU64,
    total_upstream_failures: AtomicU64,
}

impl Metrics {
    pub fn inc_request(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_error(&self) {
        self.total_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_unauthorized(&self) {
        self.total_unauthorized.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rate_limited(&self) {
        self.total_rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_upstream_failure(&self) {
        self.total_upstream_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn render_prometheus(&self) -> String {
        format!(
            "# TYPE gateway_requests_total counter\ngateway_requests_total {}\n# TYPE gateway_errors_total counter\ngateway_errors_total {}\n# TYPE gateway_unauthorized_total counter\ngateway_unauthorized_total {}\n# TYPE gateway_rate_limited_total counter\ngateway_rate_limited_total {}\n# TYPE gateway_upstream_failures_total counter\ngateway_upstream_failures_total {}\n",
            self.total_requests.load(Ordering::Relaxed),
            self.total_errors.load(Ordering::Relaxed),
            self.total_unauthorized.load(Ordering::Relaxed),
            self.total_rate_limited.load(Ordering::Relaxed),
            self.total_upstream_failures.load(Ordering::Relaxed)
        )
    }
}

pub fn init_tracing() {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let _ = tracing_subscriber::fmt().with_env_filter(env_filter).try_init();
}

#[cfg(test)]
mod tests {
    use super::Metrics;

    #[test]
    fn renders_prometheus_metrics() {
        let metrics = Metrics::default();
        metrics.inc_request();
        metrics.inc_error();

        let rendered = metrics.render_prometheus();
        assert!(rendered.contains("gateway_requests_total 1"));
        assert!(rendered.contains("gateway_errors_total 1"));
    }
}
