//! Heartbeat detection.

use std::collections::HashMap;

/// Heartbeat tracker for services.
#[derive(Debug, Default)]
pub struct HeartbeatTracker {
    heartbeats: HashMap<String, Vec<u64>>,
    /// Maximum allowed gap between heartbeats in seconds.
    pub max_gap_secs: u64,
}

impl HeartbeatTracker {
    #[must_use]
    pub fn new(max_gap_secs: u64) -> Self {
        Self {
            heartbeats: HashMap::new(),
            max_gap_secs,
        }
    }

    /// Record a heartbeat from a service.
    pub fn beat(&mut self, service: impl Into<String>, timestamp: u64) {
        self.heartbeats
            .entry(service.into())
            .or_default()
            .push(timestamp);
    }

    /// Check if a service is alive.
    #[must_use]
    pub fn is_alive(&self, service: &str, now: u64) -> bool {
        self.heartbeats
            .get(service)
            .and_then(|beats| beats.last())
            .is_some_and(|last| now.saturating_sub(*last) <= self.max_gap_secs)
    }

    #[must_use]
    pub fn services(&self) -> Vec<&str> {
        self.heartbeats.keys().map(String::as_str).collect()
    }

    #[must_use]
    pub fn last_beat(&self, service: &str) -> Option<u64> {
        self.heartbeats.get(service).and_then(|b| b.last().copied())
    }

    #[must_use]
    pub fn beat_count(&self, service: &str) -> usize {
        self.heartbeats.get(service).map_or(0, Vec::len)
    }

    #[must_use]
    pub fn dead_services(&self, now: u64) -> Vec<&str> {
        self.heartbeats
            .keys()
            .filter(|s| !self.is_alive(s, now))
            .map(String::as_str)
            .collect()
    }

    /// Average interval between heartbeats for a service.
    #[must_use]
    pub fn avg_interval(&self, service: &str) -> Option<f64> {
        let beats = self.heartbeats.get(service)?;
        if beats.len() < 2 {
            return None;
        }
        let total: u64 = beats.windows(2).map(|w| w[1] - w[0]).sum();
        Some(total as f64 / (beats.len() - 1) as f64)
    }
}
