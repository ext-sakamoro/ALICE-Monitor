//! Alert thresholds + engine.

use std::fmt;

/// Comparison operator for alert thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    GreaterThan,
    GreaterOrEqual,
    LessThan,
    LessOrEqual,
    Equal,
}

impl Comparison {
    /// Evaluate the comparison: `lhs <op> rhs`.
    #[must_use]
    pub fn evaluate(self, lhs: f64, rhs: f64) -> bool {
        match self {
            Self::GreaterThan => lhs > rhs,
            Self::GreaterOrEqual => lhs >= rhs,
            Self::LessThan => lhs < rhs,
            Self::LessOrEqual => lhs <= rhs,
            Self::Equal => (lhs - rhs).abs() < f64::EPSILON,
        }
    }
}

/// Severity levels for alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

impl fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        };
        f.write_str(s)
    }
}

/// An alert threshold definition.
#[derive(Debug, Clone)]
pub struct AlertThreshold {
    pub metric_name: String,
    pub comparison: Comparison,
    pub value: f64,
    pub severity: AlertSeverity,
    pub message: String,
}

/// A fired alert.
#[derive(Debug, Clone)]
pub struct Alert {
    pub threshold: AlertThreshold,
    pub actual_value: f64,
    pub timestamp: u64,
}

impl Alert {
    #[must_use]
    pub const fn new(threshold: AlertThreshold, actual_value: f64, timestamp: u64) -> Self {
        Self {
            threshold,
            actual_value,
            timestamp,
        }
    }
}

/// Alert engine: register thresholds and evaluate metrics against them.
#[derive(Debug, Default)]
pub struct AlertEngine {
    thresholds: Vec<AlertThreshold>,
    fired: Vec<Alert>,
}

impl AlertEngine {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_threshold(&mut self, threshold: AlertThreshold) {
        self.thresholds.push(threshold);
    }

    #[must_use]
    pub fn thresholds(&self) -> &[AlertThreshold] {
        &self.thresholds
    }

    /// Evaluate a metric value against all matching thresholds; fire alerts.
    pub fn evaluate(&mut self, metric_name: &str, value: f64, timestamp: u64) -> Vec<Alert> {
        let mut alerts = Vec::new();
        for t in &self.thresholds {
            if t.metric_name == metric_name && t.comparison.evaluate(value, t.value) {
                let a = Alert::new(t.clone(), value, timestamp);
                alerts.push(a.clone());
                self.fired.push(a);
            }
        }
        alerts
    }

    #[must_use]
    pub fn fired_alerts(&self) -> &[Alert] {
        &self.fired
    }

    pub fn clear_alerts(&mut self) {
        self.fired.clear();
    }
}
