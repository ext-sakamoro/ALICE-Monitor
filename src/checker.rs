//! Health checker: registry of checks + history.

use std::time::Duration;

use crate::check::{CheckKind, HealthCheckResult, HealthStatus};
use crate::time::now_secs;

/// Simulated health checker that stores check definitions and results.
#[derive(Debug, Default)]
pub struct HealthChecker {
    checks: Vec<CheckKind>,
    history: Vec<HealthCheckResult>,
}

impl HealthChecker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, kind: CheckKind) {
        self.checks.push(kind);
    }

    #[must_use]
    pub fn registered(&self) -> &[CheckKind] {
        &self.checks
    }

    pub fn record(&mut self, result: HealthCheckResult) {
        self.history.push(result);
    }

    #[must_use]
    pub fn results(&self) -> &[HealthCheckResult] {
        &self.history
    }

    #[must_use]
    pub fn results_for(&self, kind: &CheckKind) -> Vec<&HealthCheckResult> {
        self.history.iter().filter(|r| &r.kind == kind).collect()
    }

    #[must_use]
    pub fn latest(&self, kind: &CheckKind) -> Option<&HealthCheckResult> {
        self.history.iter().rev().find(|r| &r.kind == kind)
    }

    /// Run a simulated check — deterministic stub.
    #[must_use]
    pub fn simulate_check(kind: &CheckKind) -> HealthCheckResult {
        let (status, latency_ms) = match kind {
            CheckKind::Http(url) => {
                if url.starts_with("https") {
                    (HealthStatus::Healthy, 42)
                } else {
                    (HealthStatus::Degraded, 150)
                }
            }
            CheckKind::Tcp(_, port) => {
                if port % 2 == 0 {
                    (HealthStatus::Healthy, 5)
                } else {
                    (HealthStatus::Unhealthy, 1000)
                }
            }
            CheckKind::Process(pid) => {
                if *pid > 0 {
                    (HealthStatus::Healthy, 1)
                } else {
                    (HealthStatus::Unhealthy, 0)
                }
            }
        };
        HealthCheckResult::new(
            kind.clone(),
            status,
            Duration::from_millis(latency_ms),
            format!("simulated {status}"),
            now_secs(),
        )
    }

    /// Run all registered checks (simulated).
    pub fn run_all(&mut self) {
        let kinds: Vec<CheckKind> = self.checks.clone();
        for kind in &kinds {
            let result = Self::simulate_check(kind);
            self.record(result);
        }
    }
}
