use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct Metrics {
    total_requests: AtomicU64,
    total_errors: AtomicU64,
}

impl Metrics {
    pub fn inc_request(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_error(&self) {
        self.total_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> (u64, u64) {
        (
            self.total_requests.load(Ordering::Relaxed),
            self.total_errors.load(Ordering::Relaxed),
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
    fn tracks_requests_and_errors() {
        let metrics = Metrics::default();
        metrics.inc_request();
        metrics.inc_error();

        assert_eq!(metrics.snapshot(), (1, 1));
    }
}
