//! SLA tracking + uptime calculation.

use std::collections::HashMap;

/// SLA target definition.
#[derive(Debug, Clone)]
pub struct SlaTarget {
    pub name: String,
    /// Target uptime as a fraction (e.g. 0.999 = 99.9%).
    pub target_uptime: f64,
    /// Total observation window in seconds.
    pub window_secs: u64,
}

impl SlaTarget {
    #[must_use]
    pub fn new(name: impl Into<String>, target_uptime: f64, window_secs: u64) -> Self {
        Self {
            name: name.into(),
            target_uptime,
            window_secs,
        }
    }

    /// Maximum allowed downtime in seconds for this SLA window.
    #[must_use]
    pub fn max_downtime_secs(&self) -> u64 {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let dt = (self.window_secs as f64 * (1.0 - self.target_uptime)).floor() as u64;
        dt
    }
}

/// Uptime record: a series of (timestamp, `is_up`) observations.
#[derive(Debug, Clone)]
pub struct UptimeRecord {
    pub service_name: String,
    entries: Vec<(u64, bool)>,
}

impl UptimeRecord {
    #[must_use]
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            entries: Vec::new(),
        }
    }

    pub fn record(&mut self, timestamp: u64, is_up: bool) {
        self.entries.push((timestamp, is_up));
    }

    #[must_use]
    pub const fn total_checks(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn up_count(&self) -> usize {
        self.entries.iter().filter(|(_, up)| *up).count()
    }

    #[must_use]
    pub fn down_count(&self) -> usize {
        self.entries.iter().filter(|(_, up)| !*up).count()
    }

    #[must_use]
    pub fn uptime_fraction(&self) -> f64 {
        if self.entries.is_empty() {
            return 1.0;
        }
        self.up_count() as f64 / self.entries.len() as f64
    }

    #[must_use]
    pub fn uptime_percent_str(&self) -> String {
        format!("{:.2}%", self.uptime_fraction() * 100.0)
    }

    #[must_use]
    pub fn meets_sla(&self, target: &SlaTarget) -> bool {
        self.uptime_fraction() >= target.target_uptime
    }

    #[must_use]
    pub fn range(&self, from: u64, to: u64) -> Vec<(u64, bool)> {
        self.entries
            .iter()
            .filter(|(t, _)| *t >= from && *t <= to)
            .copied()
            .collect()
    }

    /// Longest consecutive downtime streak (count of checks).
    #[must_use]
    pub fn longest_downtime_streak(&self) -> usize {
        let mut max_streak = 0_usize;
        let mut current = 0_usize;
        for (_, up) in &self.entries {
            if *up {
                current = 0;
            } else {
                current += 1;
                max_streak = max_streak.max(current);
            }
        }
        max_streak
    }
}

/// SLA tracker combining targets and uptime records.
#[derive(Debug, Default)]
pub struct SlaTracker {
    targets: Vec<SlaTarget>,
    records: HashMap<String, UptimeRecord>,
}

impl SlaTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_target(&mut self, target: SlaTarget) {
        let name = target.name.clone();
        self.targets.push(target);
        self.records
            .entry(name.clone())
            .or_insert_with(|| UptimeRecord::new(name));
    }

    pub fn record(&mut self, service: &str, timestamp: u64, is_up: bool) {
        if let Some(r) = self.records.get_mut(service) {
            r.record(timestamp, is_up);
        }
    }

    #[must_use]
    pub fn get_record(&self, service: &str) -> Option<&UptimeRecord> {
        self.records.get(service)
    }

    #[must_use]
    pub fn targets(&self) -> &[SlaTarget] {
        &self.targets
    }

    /// Check all SLAs and return a list of (service, met).
    #[must_use]
    pub fn check_all(&self) -> Vec<(&str, bool)> {
        self.targets
            .iter()
            .map(|t| {
                let met = self.records.get(&t.name).is_none_or(|r| r.meets_sla(t));
                (t.name.as_str(), met)
            })
            .collect()
    }
}
