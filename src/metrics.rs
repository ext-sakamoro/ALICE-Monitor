//! Dashboard metrics (time-series).

use std::collections::HashMap;

/// A point in a time-series metric.
#[derive(Debug, Clone, Copy)]
pub struct MetricPoint {
    pub value: f64,
    pub timestamp: u64,
}

/// A named metric with time-series data.
#[derive(Debug, Clone)]
pub struct Metric {
    pub name: String,
    pub unit: String,
    pub points: Vec<MetricPoint>,
}

impl Metric {
    #[must_use]
    pub fn new(name: impl Into<String>, unit: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            unit: unit.into(),
            points: Vec::new(),
        }
    }

    pub fn push(&mut self, value: f64, timestamp: u64) {
        self.points.push(MetricPoint { value, timestamp });
    }

    #[must_use]
    pub fn latest(&self) -> Option<f64> {
        self.points.last().map(|p| p.value)
    }

    #[must_use]
    pub fn min(&self) -> Option<f64> {
        self.points.iter().map(|p| p.value).reduce(f64::min)
    }

    #[must_use]
    pub fn max(&self) -> Option<f64> {
        self.points.iter().map(|p| p.value).reduce(f64::max)
    }

    #[must_use]
    pub fn mean(&self) -> Option<f64> {
        if self.points.is_empty() {
            return None;
        }
        let sum: f64 = self.points.iter().map(|p| p.value).sum();
        Some(sum / self.points.len() as f64)
    }

    #[must_use]
    pub const fn count(&self) -> usize {
        self.points.len()
    }

    /// Return points within a time range (inclusive).
    #[must_use]
    pub fn range(&self, from: u64, to: u64) -> Vec<&MetricPoint> {
        self.points
            .iter()
            .filter(|p| p.timestamp >= from && p.timestamp <= to)
            .collect()
    }

    /// Standard deviation of values.
    #[must_use]
    pub fn stddev(&self) -> Option<f64> {
        let mean = self.mean()?;
        let variance = self
            .points
            .iter()
            .map(|p| (p.value - mean).powi(2))
            .sum::<f64>()
            / self.points.len() as f64;
        Some(variance.sqrt())
    }

    /// Percentile (0..=100) using nearest-rank method.
    #[must_use]
    pub fn percentile(&self, p: f64) -> Option<f64> {
        if self.points.is_empty() {
            return None;
        }
        let mut sorted: Vec<f64> = self.points.iter().map(|pt| pt.value).collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let rank = (p / 100.0 * (sorted.len() as f64 - 1.0)).round() as usize;
        let idx = rank.min(sorted.len() - 1);
        Some(sorted[idx])
    }
}

/// Dashboard that holds named metrics.
#[derive(Debug, Default)]
pub struct Dashboard {
    metrics: HashMap<String, Metric>,
}

impl Dashboard {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_metric(&mut self, name: impl Into<String>, unit: impl Into<String>) {
        let n: String = name.into();
        self.metrics
            .entry(n.clone())
            .or_insert_with(|| Metric::new(n, unit.into()));
    }

    pub fn record(&mut self, name: &str, value: f64, timestamp: u64) {
        if let Some(m) = self.metrics.get_mut(name) {
            m.push(value, timestamp);
        }
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Metric> {
        self.metrics.get(name)
    }

    #[must_use]
    pub fn metric_names(&self) -> Vec<&str> {
        self.metrics.keys().map(String::as_str).collect()
    }

    /// Generate a simple text summary of all metrics.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut lines: Vec<String> = self
            .metrics
            .iter()
            .map(|(name, m)| {
                let latest = m
                    .latest()
                    .map_or_else(|| "N/A".to_string(), |v| format!("{v:.2}"));
                format!("{name}: {latest} {}", m.unit)
            })
            .collect();
        lines.sort();
        lines.join("\n")
    }
}
