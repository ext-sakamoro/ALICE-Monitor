#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::module_name_repetitions,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

//! ALICE-Monitor: Infrastructure monitoring library.
//!
//! Provides health checks (HTTP, TCP, process), alert thresholds,
//! dashboard metrics, SLA tracking, uptime calculation, incident management,
//! status pages, and heartbeat detection.

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;
use std::time::{Duration, SystemTime};

// ---------------------------------------------------------------------------
// Timestamp helper (seconds since UNIX epoch)
// ---------------------------------------------------------------------------

/// Returns the current UNIX timestamp in seconds.
///
/// # Panics
///
/// Panics if the system clock is before the UNIX epoch.
#[must_use]
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs()
}

// ---------------------------------------------------------------------------
// Health-check types
// ---------------------------------------------------------------------------

/// The kind of health check to perform.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CheckKind {
    /// HTTP endpoint check with URL.
    Http(String),
    /// TCP socket check with host and port.
    Tcp(String, u16),
    /// Local process check with PID.
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
    /// Create a new health-check result.
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

// ---------------------------------------------------------------------------
// Health checker (registry of checks + history)
// ---------------------------------------------------------------------------

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

    /// Register a new check kind.
    pub fn register(&mut self, kind: CheckKind) {
        self.checks.push(kind);
    }

    /// Return all registered check kinds.
    #[must_use]
    pub fn registered(&self) -> &[CheckKind] {
        &self.checks
    }

    /// Record a health-check result.
    pub fn record(&mut self, result: HealthCheckResult) {
        self.history.push(result);
    }

    /// Return all recorded results.
    #[must_use]
    pub fn results(&self) -> &[HealthCheckResult] {
        &self.history
    }

    /// Return results filtered by check kind.
    #[must_use]
    pub fn results_for(&self, kind: &CheckKind) -> Vec<&HealthCheckResult> {
        self.history.iter().filter(|r| &r.kind == kind).collect()
    }

    /// Latest result for a given check kind.
    #[must_use]
    pub fn latest(&self, kind: &CheckKind) -> Option<&HealthCheckResult> {
        self.history.iter().rev().find(|r| &r.kind == kind)
    }

    /// Run a simulated check — returns `Healthy` for even PIDs / ports,
    /// `Unhealthy` for odd, as a deterministic stub.
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

// ---------------------------------------------------------------------------
// Alert thresholds
// ---------------------------------------------------------------------------

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

/// An alert threshold definition.
#[derive(Debug, Clone)]
pub struct AlertThreshold {
    pub metric_name: String,
    pub comparison: Comparison,
    pub value: f64,
    pub severity: AlertSeverity,
    pub message: String,
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

    /// Evaluate a metric value against all matching thresholds, fire alerts.
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

// ---------------------------------------------------------------------------
// Dashboard metrics
// ---------------------------------------------------------------------------

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

    /// Percentile (0..=100). Uses nearest-rank method.
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

// ---------------------------------------------------------------------------
// SLA tracking & uptime calculation
// ---------------------------------------------------------------------------

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

    /// Uptime fraction (0.0 .. 1.0).
    #[must_use]
    pub fn uptime_fraction(&self) -> f64 {
        if self.entries.is_empty() {
            return 1.0;
        }
        self.up_count() as f64 / self.entries.len() as f64
    }

    /// Uptime percentage string (e.g. "99.95%").
    #[must_use]
    pub fn uptime_percent_str(&self) -> String {
        format!("{:.2}%", self.uptime_fraction() * 100.0)
    }

    /// Whether the SLA target is met.
    #[must_use]
    pub fn meets_sla(&self, target: &SlaTarget) -> bool {
        self.uptime_fraction() >= target.target_uptime
    }

    /// Entries within a time range.
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

// ---------------------------------------------------------------------------
// Incident management
// ---------------------------------------------------------------------------

/// Incident severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IncidentSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for IncidentSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        f.write_str(s)
    }
}

/// Current state of an incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IncidentState {
    Open,
    Acknowledged,
    Investigating,
    Resolved,
    Closed,
}

impl fmt::Display for IncidentState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Open => "open",
            Self::Acknowledged => "acknowledged",
            Self::Investigating => "investigating",
            Self::Resolved => "resolved",
            Self::Closed => "closed",
        };
        f.write_str(s)
    }
}

/// A timeline entry for an incident.
#[derive(Debug, Clone)]
pub struct IncidentEvent {
    pub state: IncidentState,
    pub message: String,
    pub timestamp: u64,
}

/// An incident.
#[derive(Debug, Clone)]
pub struct Incident {
    pub id: u64,
    pub title: String,
    pub severity: IncidentSeverity,
    pub state: IncidentState,
    pub created_at: u64,
    pub updated_at: u64,
    pub timeline: Vec<IncidentEvent>,
}

impl Incident {
    #[must_use]
    pub fn new(
        id: u64,
        title: impl Into<String>,
        severity: IncidentSeverity,
        created_at: u64,
    ) -> Self {
        let state = IncidentState::Open;
        let title = title.into();
        let event = IncidentEvent {
            state,
            message: format!("Incident created: {title}"),
            timestamp: created_at,
        };
        Self {
            id,
            title,
            severity,
            state,
            created_at,
            updated_at: created_at,
            timeline: vec![event],
        }
    }

    /// Transition to a new state.
    pub fn transition(&mut self, state: IncidentState, message: impl Into<String>, timestamp: u64) {
        self.state = state;
        self.updated_at = timestamp;
        self.timeline.push(IncidentEvent {
            state,
            message: message.into(),
            timestamp,
        });
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(
            self.state,
            IncidentState::Open | IncidentState::Acknowledged | IncidentState::Investigating
        )
    }

    /// Duration from creation to latest update, in seconds.
    #[must_use]
    pub const fn duration_secs(&self) -> u64 {
        self.updated_at - self.created_at
    }
}

/// Incident manager.
#[derive(Debug, Default)]
pub struct IncidentManager {
    incidents: Vec<Incident>,
    next_id: u64,
}

impl IncidentManager {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            incidents: Vec::new(),
            next_id: 1,
        }
    }

    /// Create a new incident and return its ID.
    pub fn create(
        &mut self,
        title: impl Into<String>,
        severity: IncidentSeverity,
        timestamp: u64,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.incidents
            .push(Incident::new(id, title, severity, timestamp));
        id
    }

    pub fn transition(
        &mut self,
        id: u64,
        state: IncidentState,
        message: impl Into<String>,
        timestamp: u64,
    ) -> bool {
        self.incidents
            .iter_mut()
            .find(|i| i.id == id)
            .is_some_and(|inc| {
                inc.transition(state, message, timestamp);
                true
            })
    }

    #[must_use]
    pub fn get(&self, id: u64) -> Option<&Incident> {
        self.incidents.iter().find(|i| i.id == id)
    }

    #[must_use]
    pub fn active(&self) -> Vec<&Incident> {
        self.incidents.iter().filter(|i| i.is_active()).collect()
    }

    #[must_use]
    pub fn resolved(&self) -> Vec<&Incident> {
        self.incidents
            .iter()
            .filter(|i| matches!(i.state, IncidentState::Resolved | IncidentState::Closed))
            .collect()
    }

    #[must_use]
    pub fn all(&self) -> &[Incident] {
        &self.incidents
    }

    #[must_use]
    pub const fn count(&self) -> usize {
        self.incidents.len()
    }

    /// Mean time to resolve (seconds) for resolved/closed incidents.
    #[must_use]
    pub fn mttr(&self) -> Option<f64> {
        let resolved: Vec<&Incident> = self.resolved();
        if resolved.is_empty() {
            return None;
        }
        let total: u64 = resolved.iter().map(|i| i.duration_secs()).sum();
        Some(total as f64 / resolved.len() as f64)
    }
}

// ---------------------------------------------------------------------------
// Status page
// ---------------------------------------------------------------------------

/// Overall status of a component on the status page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComponentStatus {
    Operational,
    DegradedPerformance,
    PartialOutage,
    MajorOutage,
    Maintenance,
}

impl fmt::Display for ComponentStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Operational => "operational",
            Self::DegradedPerformance => "degraded performance",
            Self::PartialOutage => "partial outage",
            Self::MajorOutage => "major outage",
            Self::Maintenance => "maintenance",
        };
        f.write_str(s)
    }
}

/// A component on the status page.
#[derive(Debug, Clone)]
pub struct StatusComponent {
    pub name: String,
    pub status: ComponentStatus,
    pub description: String,
    pub updated_at: u64,
}

/// Status page holding multiple components.
#[derive(Debug, Default)]
pub struct StatusPage {
    pub title: String,
    components: Vec<StatusComponent>,
}

impl StatusPage {
    #[must_use]
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            components: Vec::new(),
        }
    }

    pub fn add_component(
        &mut self,
        name: impl Into<String>,
        status: ComponentStatus,
        description: impl Into<String>,
        updated_at: u64,
    ) {
        self.components.push(StatusComponent {
            name: name.into(),
            status,
            description: description.into(),
            updated_at,
        });
    }

    pub fn update_status(&mut self, name: &str, status: ComponentStatus, updated_at: u64) {
        if let Some(c) = self.components.iter_mut().find(|c| c.name == name) {
            c.status = status;
            c.updated_at = updated_at;
        }
    }

    #[must_use]
    pub fn components(&self) -> &[StatusComponent] {
        &self.components
    }

    #[must_use]
    pub fn get_component(&self, name: &str) -> Option<&StatusComponent> {
        self.components.iter().find(|c| c.name == name)
    }

    /// Overall status — the worst component status.
    #[must_use]
    pub fn overall_status(&self) -> ComponentStatus {
        if self.components.is_empty() {
            return ComponentStatus::Operational;
        }
        let worst = self
            .components
            .iter()
            .map(|c| match c.status {
                ComponentStatus::Operational => 0,
                ComponentStatus::Maintenance => 1,
                ComponentStatus::DegradedPerformance => 2,
                ComponentStatus::PartialOutage => 3,
                ComponentStatus::MajorOutage => 4,
            })
            .max()
            .unwrap_or(0);
        match worst {
            0 => ComponentStatus::Operational,
            1 => ComponentStatus::Maintenance,
            2 => ComponentStatus::DegradedPerformance,
            3 => ComponentStatus::PartialOutage,
            _ => ComponentStatus::MajorOutage,
        }
    }

    /// Render the status page as plain text.
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut out = format!(
            "=== {} ===\nOverall: {}\n\n",
            self.title,
            self.overall_status()
        );
        for c in &self.components {
            let _ = writeln!(out, "  [{}] {} — {}", c.status, c.name, c.description);
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Heartbeat detection
// ---------------------------------------------------------------------------

/// Heartbeat tracker for services.
#[derive(Debug, Default)]
pub struct HeartbeatTracker {
    /// Service name -> list of heartbeat timestamps.
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

    /// Check if a service is alive (last heartbeat within `max_gap` of `now`).
    #[must_use]
    pub fn is_alive(&self, service: &str, now: u64) -> bool {
        self.heartbeats
            .get(service)
            .and_then(|beats| beats.last())
            .is_some_and(|last| now.saturating_sub(*last) <= self.max_gap_secs)
    }

    /// Return all known services.
    #[must_use]
    pub fn services(&self) -> Vec<&str> {
        self.heartbeats.keys().map(String::as_str).collect()
    }

    /// Last heartbeat timestamp for a service.
    #[must_use]
    pub fn last_beat(&self, service: &str) -> Option<u64> {
        self.heartbeats.get(service).and_then(|b| b.last().copied())
    }

    /// Number of heartbeats received from a service.
    #[must_use]
    pub fn beat_count(&self, service: &str) -> usize {
        self.heartbeats.get(service).map_or(0, Vec::len)
    }

    /// Services that are dead (no heartbeat within `max_gap` of `now`).
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- CheckKind --

    #[test]
    fn check_kind_display_http() {
        let ck = CheckKind::Http("https://example.com".into());
        assert_eq!(ck.to_string(), "HTTP(https://example.com)");
    }

    #[test]
    fn check_kind_display_tcp() {
        let ck = CheckKind::Tcp("localhost".into(), 8080);
        assert_eq!(ck.to_string(), "TCP(localhost:8080)");
    }

    #[test]
    fn check_kind_display_process() {
        let ck = CheckKind::Process(1234);
        assert_eq!(ck.to_string(), "Process(1234)");
    }

    #[test]
    fn check_kind_eq() {
        let a = CheckKind::Http("a".into());
        let b = CheckKind::Http("a".into());
        assert_eq!(a, b);
    }

    #[test]
    fn check_kind_ne() {
        let a = CheckKind::Http("a".into());
        let b = CheckKind::Http("b".into());
        assert_ne!(a, b);
    }

    // -- HealthStatus --

    #[test]
    fn health_status_display() {
        assert_eq!(HealthStatus::Healthy.to_string(), "healthy");
        assert_eq!(HealthStatus::Degraded.to_string(), "degraded");
        assert_eq!(HealthStatus::Unhealthy.to_string(), "unhealthy");
        assert_eq!(HealthStatus::Unknown.to_string(), "unknown");
    }

    // -- HealthCheckResult --

    #[test]
    fn health_check_result_new() {
        let r = HealthCheckResult::new(
            CheckKind::Http("https://x.com".into()),
            HealthStatus::Healthy,
            Duration::from_millis(10),
            "ok",
            1000,
        );
        assert_eq!(r.status, HealthStatus::Healthy);
        assert_eq!(r.timestamp, 1000);
    }

    #[test]
    fn health_check_is_up_healthy() {
        let r = HealthCheckResult::new(
            CheckKind::Process(1),
            HealthStatus::Healthy,
            Duration::ZERO,
            "",
            0,
        );
        assert!(r.is_up());
    }

    #[test]
    fn health_check_is_up_degraded() {
        let r = HealthCheckResult::new(
            CheckKind::Process(1),
            HealthStatus::Degraded,
            Duration::ZERO,
            "",
            0,
        );
        assert!(r.is_up());
    }

    #[test]
    fn health_check_is_up_unhealthy() {
        let r = HealthCheckResult::new(
            CheckKind::Process(1),
            HealthStatus::Unhealthy,
            Duration::ZERO,
            "",
            0,
        );
        assert!(!r.is_up());
    }

    #[test]
    fn health_check_is_up_unknown() {
        let r = HealthCheckResult::new(
            CheckKind::Process(1),
            HealthStatus::Unknown,
            Duration::ZERO,
            "",
            0,
        );
        assert!(!r.is_up());
    }

    // -- HealthChecker --

    #[test]
    fn checker_register_and_list() {
        let mut hc = HealthChecker::new();
        hc.register(CheckKind::Http("https://a.com".into()));
        hc.register(CheckKind::Tcp("b".into(), 80));
        assert_eq!(hc.registered().len(), 2);
    }

    #[test]
    fn checker_record_and_results() {
        let mut hc = HealthChecker::new();
        hc.record(HealthCheckResult::new(
            CheckKind::Process(10),
            HealthStatus::Healthy,
            Duration::ZERO,
            "ok",
            1,
        ));
        assert_eq!(hc.results().len(), 1);
    }

    #[test]
    fn checker_results_for() {
        let mut hc = HealthChecker::new();
        let k = CheckKind::Process(10);
        hc.record(HealthCheckResult::new(
            k.clone(),
            HealthStatus::Healthy,
            Duration::ZERO,
            "",
            1,
        ));
        hc.record(HealthCheckResult::new(
            CheckKind::Process(20),
            HealthStatus::Healthy,
            Duration::ZERO,
            "",
            2,
        ));
        assert_eq!(hc.results_for(&k).len(), 1);
    }

    #[test]
    fn checker_latest() {
        let mut hc = HealthChecker::new();
        let k = CheckKind::Process(10);
        hc.record(HealthCheckResult::new(
            k.clone(),
            HealthStatus::Healthy,
            Duration::ZERO,
            "first",
            1,
        ));
        hc.record(HealthCheckResult::new(
            k.clone(),
            HealthStatus::Unhealthy,
            Duration::ZERO,
            "second",
            2,
        ));
        let latest = hc.latest(&k).unwrap();
        assert_eq!(latest.message, "second");
    }

    #[test]
    fn checker_latest_none() {
        let hc = HealthChecker::new();
        assert!(hc.latest(&CheckKind::Process(99)).is_none());
    }

    #[test]
    fn simulate_http_https() {
        let r = HealthChecker::simulate_check(&CheckKind::Http("https://ok.com".into()));
        assert_eq!(r.status, HealthStatus::Healthy);
    }

    #[test]
    fn simulate_http_plain() {
        let r = HealthChecker::simulate_check(&CheckKind::Http("http://ok.com".into()));
        assert_eq!(r.status, HealthStatus::Degraded);
    }

    #[test]
    fn simulate_tcp_even() {
        let r = HealthChecker::simulate_check(&CheckKind::Tcp("h".into(), 80));
        assert_eq!(r.status, HealthStatus::Healthy);
    }

    #[test]
    fn simulate_tcp_odd() {
        let r = HealthChecker::simulate_check(&CheckKind::Tcp("h".into(), 81));
        assert_eq!(r.status, HealthStatus::Unhealthy);
    }

    #[test]
    fn simulate_process_positive() {
        let r = HealthChecker::simulate_check(&CheckKind::Process(1));
        assert_eq!(r.status, HealthStatus::Healthy);
    }

    #[test]
    fn simulate_process_zero() {
        let r = HealthChecker::simulate_check(&CheckKind::Process(0));
        assert_eq!(r.status, HealthStatus::Unhealthy);
    }

    #[test]
    fn checker_run_all() {
        let mut hc = HealthChecker::new();
        hc.register(CheckKind::Http("https://a.com".into()));
        hc.register(CheckKind::Tcp("b".into(), 80));
        hc.run_all();
        assert_eq!(hc.results().len(), 2);
    }

    // -- Comparison --

    #[test]
    fn comparison_gt() {
        assert!(Comparison::GreaterThan.evaluate(5.0, 3.0));
        assert!(!Comparison::GreaterThan.evaluate(3.0, 5.0));
    }

    #[test]
    fn comparison_ge() {
        assert!(Comparison::GreaterOrEqual.evaluate(5.0, 5.0));
        assert!(Comparison::GreaterOrEqual.evaluate(6.0, 5.0));
        assert!(!Comparison::GreaterOrEqual.evaluate(4.0, 5.0));
    }

    #[test]
    fn comparison_lt() {
        assert!(Comparison::LessThan.evaluate(3.0, 5.0));
        assert!(!Comparison::LessThan.evaluate(5.0, 3.0));
    }

    #[test]
    fn comparison_le() {
        assert!(Comparison::LessOrEqual.evaluate(5.0, 5.0));
        assert!(Comparison::LessOrEqual.evaluate(4.0, 5.0));
    }

    #[test]
    fn comparison_eq() {
        assert!(Comparison::Equal.evaluate(3.0, 3.0));
        assert!(!Comparison::Equal.evaluate(3.0, 4.0));
    }

    // -- AlertEngine --

    #[test]
    fn alert_engine_new_empty() {
        let e = AlertEngine::new();
        assert!(e.thresholds().is_empty());
        assert!(e.fired_alerts().is_empty());
    }

    #[test]
    fn alert_engine_fires() {
        let mut e = AlertEngine::new();
        e.add_threshold(AlertThreshold {
            metric_name: "cpu".into(),
            comparison: Comparison::GreaterThan,
            value: 90.0,
            severity: AlertSeverity::Critical,
            message: "CPU high".into(),
        });
        let alerts = e.evaluate("cpu", 95.0, 100);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].actual_value, 95.0);
    }

    #[test]
    fn alert_engine_no_fire() {
        let mut e = AlertEngine::new();
        e.add_threshold(AlertThreshold {
            metric_name: "cpu".into(),
            comparison: Comparison::GreaterThan,
            value: 90.0,
            severity: AlertSeverity::Warning,
            message: "".into(),
        });
        let alerts = e.evaluate("cpu", 50.0, 100);
        assert!(alerts.is_empty());
    }

    #[test]
    fn alert_engine_wrong_metric() {
        let mut e = AlertEngine::new();
        e.add_threshold(AlertThreshold {
            metric_name: "cpu".into(),
            comparison: Comparison::GreaterThan,
            value: 90.0,
            severity: AlertSeverity::Info,
            message: "".into(),
        });
        let alerts = e.evaluate("memory", 99.0, 100);
        assert!(alerts.is_empty());
    }

    #[test]
    fn alert_engine_clear() {
        let mut e = AlertEngine::new();
        e.add_threshold(AlertThreshold {
            metric_name: "x".into(),
            comparison: Comparison::GreaterThan,
            value: 0.0,
            severity: AlertSeverity::Info,
            message: "".into(),
        });
        e.evaluate("x", 1.0, 1);
        assert_eq!(e.fired_alerts().len(), 1);
        e.clear_alerts();
        assert!(e.fired_alerts().is_empty());
    }

    #[test]
    fn alert_severity_ord() {
        assert!(AlertSeverity::Info < AlertSeverity::Warning);
        assert!(AlertSeverity::Warning < AlertSeverity::Critical);
    }

    #[test]
    fn alert_severity_display() {
        assert_eq!(AlertSeverity::Critical.to_string(), "critical");
    }

    // -- Metric --

    #[test]
    fn metric_new_empty() {
        let m = Metric::new("cpu", "%");
        assert_eq!(m.count(), 0);
        assert!(m.latest().is_none());
    }

    #[test]
    fn metric_push_and_latest() {
        let mut m = Metric::new("cpu", "%");
        m.push(50.0, 1);
        m.push(75.0, 2);
        assert_eq!(m.latest(), Some(75.0));
    }

    #[test]
    fn metric_min_max() {
        let mut m = Metric::new("cpu", "%");
        m.push(10.0, 1);
        m.push(50.0, 2);
        m.push(30.0, 3);
        assert_eq!(m.min(), Some(10.0));
        assert_eq!(m.max(), Some(50.0));
    }

    #[test]
    fn metric_mean() {
        let mut m = Metric::new("t", "ms");
        m.push(10.0, 1);
        m.push(20.0, 2);
        m.push(30.0, 3);
        let mean = m.mean().unwrap();
        assert!((mean - 20.0).abs() < f64::EPSILON);
    }

    #[test]
    fn metric_mean_empty() {
        let m = Metric::new("t", "ms");
        assert!(m.mean().is_none());
    }

    #[test]
    fn metric_range() {
        let mut m = Metric::new("t", "ms");
        m.push(1.0, 10);
        m.push(2.0, 20);
        m.push(3.0, 30);
        let r = m.range(15, 25);
        assert_eq!(r.len(), 1);
        assert!((r[0].value - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn metric_stddev() {
        let mut m = Metric::new("t", "ms");
        m.push(2.0, 1);
        m.push(4.0, 2);
        m.push(4.0, 3);
        m.push(4.0, 4);
        m.push(5.0, 5);
        m.push(5.0, 6);
        m.push(7.0, 7);
        m.push(9.0, 8);
        let sd = m.stddev().unwrap();
        assert!(sd > 1.0 && sd < 3.0);
    }

    #[test]
    fn metric_stddev_empty() {
        let m = Metric::new("t", "ms");
        assert!(m.stddev().is_none());
    }

    #[test]
    fn metric_percentile_50() {
        let mut m = Metric::new("t", "ms");
        for i in 1_u32..=100 {
            m.push(f64::from(i), u64::from(i));
        }
        let p50 = m.percentile(50.0).unwrap();
        assert!((p50 - 50.0).abs() < 1.5);
    }

    #[test]
    fn metric_percentile_empty() {
        let m = Metric::new("t", "ms");
        assert!(m.percentile(50.0).is_none());
    }

    #[test]
    fn metric_percentile_single() {
        let mut m = Metric::new("t", "ms");
        m.push(42.0, 1);
        assert_eq!(m.percentile(99.0), Some(42.0));
    }

    #[test]
    fn metric_min_empty() {
        let m = Metric::new("t", "ms");
        assert!(m.min().is_none());
    }

    #[test]
    fn metric_max_empty() {
        let m = Metric::new("t", "ms");
        assert!(m.max().is_none());
    }

    // -- Dashboard --

    #[test]
    fn dashboard_register_and_record() {
        let mut d = Dashboard::new();
        d.register_metric("cpu", "%");
        d.record("cpu", 55.0, 1);
        assert_eq!(d.get("cpu").unwrap().latest(), Some(55.0));
    }

    #[test]
    fn dashboard_unknown_metric_ignored() {
        let mut d = Dashboard::new();
        d.record("nope", 1.0, 1);
        assert!(d.get("nope").is_none());
    }

    #[test]
    fn dashboard_metric_names() {
        let mut d = Dashboard::new();
        d.register_metric("a", "x");
        d.register_metric("b", "y");
        let names = d.metric_names();
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn dashboard_summary() {
        let mut d = Dashboard::new();
        d.register_metric("cpu", "%");
        d.record("cpu", 42.0, 1);
        let s = d.summary();
        assert!(s.contains("cpu"));
        assert!(s.contains("42.00"));
    }

    // -- SlaTarget --

    #[test]
    fn sla_target_max_downtime() {
        let s = SlaTarget::new("api", 0.999, 86400);
        // 0.1% of 86400 = 86.4 -> floor = 86
        assert_eq!(s.max_downtime_secs(), 86);
    }

    #[test]
    fn sla_target_100_percent() {
        let s = SlaTarget::new("api", 1.0, 86400);
        assert_eq!(s.max_downtime_secs(), 0);
    }

    // -- UptimeRecord --

    #[test]
    fn uptime_empty() {
        let u = UptimeRecord::new("svc");
        assert_eq!(u.total_checks(), 0);
        assert_eq!(u.uptime_fraction(), 1.0);
    }

    #[test]
    fn uptime_all_up() {
        let mut u = UptimeRecord::new("svc");
        for i in 0..100 {
            u.record(i, true);
        }
        assert_eq!(u.uptime_fraction(), 1.0);
        assert_eq!(u.up_count(), 100);
        assert_eq!(u.down_count(), 0);
    }

    #[test]
    fn uptime_half() {
        let mut u = UptimeRecord::new("svc");
        for i in 0..10 {
            u.record(i, i % 2 == 0);
        }
        assert!((u.uptime_fraction() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn uptime_percent_str() {
        let mut u = UptimeRecord::new("svc");
        for i in 0..1000 {
            u.record(i, i < 999);
        }
        let s = u.uptime_percent_str();
        assert!(s.contains("99."));
    }

    #[test]
    fn uptime_meets_sla_pass() {
        let mut u = UptimeRecord::new("svc");
        for i in 0..1000 {
            u.record(i, true);
        }
        let target = SlaTarget::new("svc", 0.999, 86400);
        assert!(u.meets_sla(&target));
    }

    #[test]
    fn uptime_meets_sla_fail() {
        let mut u = UptimeRecord::new("svc");
        for i in 0..1000 {
            u.record(i, i % 2 == 0);
        }
        let target = SlaTarget::new("svc", 0.999, 86400);
        assert!(!u.meets_sla(&target));
    }

    #[test]
    fn uptime_range() {
        let mut u = UptimeRecord::new("svc");
        u.record(10, true);
        u.record(20, false);
        u.record(30, true);
        let r = u.range(15, 25);
        assert_eq!(r.len(), 1);
        assert!(!r[0].1);
    }

    #[test]
    fn uptime_longest_downtime_streak_none() {
        let mut u = UptimeRecord::new("svc");
        for i in 0..10 {
            u.record(i, true);
        }
        assert_eq!(u.longest_downtime_streak(), 0);
    }

    #[test]
    fn uptime_longest_downtime_streak() {
        let mut u = UptimeRecord::new("svc");
        u.record(1, true);
        u.record(2, false);
        u.record(3, false);
        u.record(4, false);
        u.record(5, true);
        u.record(6, false);
        assert_eq!(u.longest_downtime_streak(), 3);
    }

    // -- SlaTracker --

    #[test]
    fn sla_tracker_add_and_record() {
        let mut st = SlaTracker::new();
        st.add_target(SlaTarget::new("api", 0.99, 3600));
        st.record("api", 1, true);
        st.record("api", 2, true);
        let rec = st.get_record("api").unwrap();
        assert_eq!(rec.total_checks(), 2);
    }

    #[test]
    fn sla_tracker_check_all() {
        let mut st = SlaTracker::new();
        st.add_target(SlaTarget::new("api", 0.99, 3600));
        for i in 0..100 {
            st.record("api", i, true);
        }
        let checks = st.check_all();
        assert_eq!(checks.len(), 1);
        assert!(checks[0].1);
    }

    #[test]
    fn sla_tracker_no_record() {
        let mut st = SlaTracker::new();
        st.add_target(SlaTarget::new("api", 0.99, 3600));
        // no records — defaults to met
        let checks = st.check_all();
        assert!(checks[0].1);
    }

    #[test]
    fn sla_tracker_record_unknown_service() {
        let mut st = SlaTracker::new();
        st.record("unknown", 1, true); // no-op
        assert!(st.get_record("unknown").is_none());
    }

    // -- Incident --

    #[test]
    fn incident_new() {
        let inc = Incident::new(1, "outage", IncidentSeverity::High, 1000);
        assert_eq!(inc.state, IncidentState::Open);
        assert!(inc.is_active());
        assert_eq!(inc.timeline.len(), 1);
    }

    #[test]
    fn incident_transition() {
        let mut inc = Incident::new(1, "outage", IncidentSeverity::Critical, 1000);
        inc.transition(IncidentState::Acknowledged, "ack", 1001);
        assert_eq!(inc.state, IncidentState::Acknowledged);
        assert!(inc.is_active());
        inc.transition(IncidentState::Resolved, "fixed", 1010);
        assert_eq!(inc.state, IncidentState::Resolved);
        assert!(!inc.is_active());
        assert_eq!(inc.duration_secs(), 10);
    }

    #[test]
    fn incident_closed_not_active() {
        let mut inc = Incident::new(1, "x", IncidentSeverity::Low, 0);
        inc.transition(IncidentState::Closed, "done", 10);
        assert!(!inc.is_active());
    }

    #[test]
    fn incident_investigating_is_active() {
        let mut inc = Incident::new(1, "x", IncidentSeverity::Medium, 0);
        inc.transition(IncidentState::Investigating, "looking", 5);
        assert!(inc.is_active());
    }

    #[test]
    fn incident_severity_display() {
        assert_eq!(IncidentSeverity::Low.to_string(), "low");
        assert_eq!(IncidentSeverity::Critical.to_string(), "critical");
    }

    #[test]
    fn incident_severity_ord() {
        assert!(IncidentSeverity::Low < IncidentSeverity::Medium);
        assert!(IncidentSeverity::High < IncidentSeverity::Critical);
    }

    #[test]
    fn incident_state_display() {
        assert_eq!(IncidentState::Open.to_string(), "open");
        assert_eq!(IncidentState::Resolved.to_string(), "resolved");
    }

    // -- IncidentManager --

    #[test]
    fn manager_create() {
        let mut m = IncidentManager::new();
        let id = m.create("outage", IncidentSeverity::High, 100);
        assert_eq!(id, 1);
        assert_eq!(m.count(), 1);
    }

    #[test]
    fn manager_auto_increment() {
        let mut m = IncidentManager::new();
        let a = m.create("a", IncidentSeverity::Low, 1);
        let b = m.create("b", IncidentSeverity::Low, 2);
        assert_eq!(a, 1);
        assert_eq!(b, 2);
    }

    #[test]
    fn manager_transition() {
        let mut m = IncidentManager::new();
        let id = m.create("x", IncidentSeverity::Medium, 0);
        assert!(m.transition(id, IncidentState::Resolved, "done", 10));
        assert!(!m.get(id).unwrap().is_active());
    }

    #[test]
    fn manager_transition_unknown() {
        let mut m = IncidentManager::new();
        assert!(!m.transition(999, IncidentState::Resolved, "x", 0));
    }

    #[test]
    fn manager_active_and_resolved() {
        let mut m = IncidentManager::new();
        m.create("a", IncidentSeverity::Low, 0);
        let b = m.create("b", IncidentSeverity::High, 1);
        m.transition(b, IncidentState::Resolved, "fixed", 10);
        assert_eq!(m.active().len(), 1);
        assert_eq!(m.resolved().len(), 1);
    }

    #[test]
    fn manager_mttr() {
        let mut m = IncidentManager::new();
        let a = m.create("a", IncidentSeverity::Low, 0);
        m.transition(a, IncidentState::Resolved, "fix", 10);
        let b = m.create("b", IncidentSeverity::Low, 100);
        m.transition(b, IncidentState::Resolved, "fix", 120);
        // (10 + 20) / 2 = 15
        assert!((m.mttr().unwrap() - 15.0).abs() < f64::EPSILON);
    }

    #[test]
    fn manager_mttr_none() {
        let m = IncidentManager::new();
        assert!(m.mttr().is_none());
    }

    #[test]
    fn manager_get_none() {
        let m = IncidentManager::new();
        assert!(m.get(1).is_none());
    }

    #[test]
    fn manager_all() {
        let mut m = IncidentManager::new();
        m.create("a", IncidentSeverity::Low, 0);
        m.create("b", IncidentSeverity::Low, 0);
        assert_eq!(m.all().len(), 2);
    }

    // -- ComponentStatus --

    #[test]
    fn component_status_display() {
        assert_eq!(ComponentStatus::Operational.to_string(), "operational");
        assert_eq!(ComponentStatus::MajorOutage.to_string(), "major outage");
        assert_eq!(ComponentStatus::Maintenance.to_string(), "maintenance");
    }

    // -- StatusPage --

    #[test]
    fn status_page_empty() {
        let sp = StatusPage::new("Test");
        assert_eq!(sp.overall_status(), ComponentStatus::Operational);
        assert!(sp.components().is_empty());
    }

    #[test]
    fn status_page_add_component() {
        let mut sp = StatusPage::new("Test");
        sp.add_component("API", ComponentStatus::Operational, "Main API", 1);
        assert_eq!(sp.components().len(), 1);
    }

    #[test]
    fn status_page_overall_worst() {
        let mut sp = StatusPage::new("Test");
        sp.add_component("A", ComponentStatus::Operational, "", 1);
        sp.add_component("B", ComponentStatus::MajorOutage, "", 1);
        assert_eq!(sp.overall_status(), ComponentStatus::MajorOutage);
    }

    #[test]
    fn status_page_update() {
        let mut sp = StatusPage::new("Test");
        sp.add_component("A", ComponentStatus::Operational, "", 1);
        sp.update_status("A", ComponentStatus::PartialOutage, 2);
        assert_eq!(
            sp.get_component("A").unwrap().status,
            ComponentStatus::PartialOutage
        );
    }

    #[test]
    fn status_page_get_component_none() {
        let sp = StatusPage::new("Test");
        assert!(sp.get_component("nope").is_none());
    }

    #[test]
    fn status_page_render_text() {
        let mut sp = StatusPage::new("System Status");
        sp.add_component("API", ComponentStatus::Operational, "REST API", 1);
        let text = sp.render_text();
        assert!(text.contains("System Status"));
        assert!(text.contains("API"));
    }

    #[test]
    fn status_page_degraded_overall() {
        let mut sp = StatusPage::new("T");
        sp.add_component("A", ComponentStatus::Operational, "", 0);
        sp.add_component("B", ComponentStatus::DegradedPerformance, "", 0);
        assert_eq!(sp.overall_status(), ComponentStatus::DegradedPerformance);
    }

    #[test]
    fn status_page_maintenance_overall() {
        let mut sp = StatusPage::new("T");
        sp.add_component("A", ComponentStatus::Operational, "", 0);
        sp.add_component("B", ComponentStatus::Maintenance, "", 0);
        assert_eq!(sp.overall_status(), ComponentStatus::Maintenance);
    }

    #[test]
    fn status_page_partial_outage_overall() {
        let mut sp = StatusPage::new("T");
        sp.add_component("A", ComponentStatus::DegradedPerformance, "", 0);
        sp.add_component("B", ComponentStatus::PartialOutage, "", 0);
        assert_eq!(sp.overall_status(), ComponentStatus::PartialOutage);
    }

    // -- HeartbeatTracker --

    #[test]
    fn heartbeat_new() {
        let ht = HeartbeatTracker::new(30);
        assert_eq!(ht.max_gap_secs, 30);
        assert!(ht.services().is_empty());
    }

    #[test]
    fn heartbeat_beat_and_alive() {
        let mut ht = HeartbeatTracker::new(30);
        ht.beat("svc-a", 100);
        assert!(ht.is_alive("svc-a", 120));
        assert!(!ht.is_alive("svc-a", 200));
    }

    #[test]
    fn heartbeat_unknown_service() {
        let ht = HeartbeatTracker::new(30);
        assert!(!ht.is_alive("nope", 100));
    }

    #[test]
    fn heartbeat_services_list() {
        let mut ht = HeartbeatTracker::new(10);
        ht.beat("a", 1);
        ht.beat("b", 1);
        assert_eq!(ht.services().len(), 2);
    }

    #[test]
    fn heartbeat_last_beat() {
        let mut ht = HeartbeatTracker::new(10);
        ht.beat("a", 10);
        ht.beat("a", 20);
        assert_eq!(ht.last_beat("a"), Some(20));
    }

    #[test]
    fn heartbeat_last_beat_none() {
        let ht = HeartbeatTracker::new(10);
        assert!(ht.last_beat("x").is_none());
    }

    #[test]
    fn heartbeat_beat_count() {
        let mut ht = HeartbeatTracker::new(10);
        ht.beat("a", 1);
        ht.beat("a", 2);
        ht.beat("a", 3);
        assert_eq!(ht.beat_count("a"), 3);
        assert_eq!(ht.beat_count("b"), 0);
    }

    #[test]
    fn heartbeat_dead_services() {
        let mut ht = HeartbeatTracker::new(10);
        ht.beat("alive", 100);
        ht.beat("dead", 50);
        let dead = ht.dead_services(105);
        assert!(dead.contains(&"dead"));
        assert!(!dead.contains(&"alive"));
    }

    #[test]
    fn heartbeat_avg_interval() {
        let mut ht = HeartbeatTracker::new(60);
        ht.beat("a", 10);
        ht.beat("a", 20);
        ht.beat("a", 30);
        let avg = ht.avg_interval("a").unwrap();
        assert!((avg - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn heartbeat_avg_interval_single() {
        let mut ht = HeartbeatTracker::new(60);
        ht.beat("a", 10);
        assert!(ht.avg_interval("a").is_none());
    }

    #[test]
    fn heartbeat_avg_interval_none() {
        let ht = HeartbeatTracker::new(60);
        assert!(ht.avg_interval("x").is_none());
    }

    #[test]
    fn heartbeat_edge_exact_gap() {
        let mut ht = HeartbeatTracker::new(30);
        ht.beat("a", 100);
        // exactly at boundary
        assert!(ht.is_alive("a", 130));
        // one past
        assert!(!ht.is_alive("a", 131));
    }
}
