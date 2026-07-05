//! Health check kinds and results.

use std::fmt;
use std::time::Duration;

/// The kind of health check to perform.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CheckKind {
    Http(String),
    Tcp(String, u16),
    Process(u32),
}

impl fmt::Display for CheckKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(url) => write!(f, "HTTP({url})"),
            Self::Tcp(host, port) => write!(f, "TCP({host}:{port})"),
            Self::Process(pid) => write!(f, "Process({pid})"),
        }
    }
}

/// Result status of a health check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

impl fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unhealthy => "unhealthy",
            Self::Unknown => "unknown",
        };
        f.write_str(label)
    }
}

/// A single health-check result.
#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    pub kind: CheckKind,
    pub status: HealthStatus,
    pub latency: Duration,
    pub message: String,
    pub timestamp: u64,
}

impl HealthCheckResult {
    #[must_use]
    pub fn new(
        kind: CheckKind,
        status: HealthStatus,
        latency: Duration,
        message: impl Into<String>,
        timestamp: u64,
    ) -> Self {
        Self {
            kind,
            status,
            latency,
            message: message.into(),
            timestamp,
        }
    }

    /// Whether the check passed (healthy or degraded).
    #[must_use]
    pub const fn is_up(&self) -> bool {
        matches!(self.status, HealthStatus::Healthy | HealthStatus::Degraded)
    }
}
