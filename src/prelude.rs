//! Convenience re-export (= `use alice_monitor::prelude::*;`).

pub use crate::alert::{Alert, AlertEngine, AlertSeverity, AlertThreshold, Comparison};
pub use crate::check::{CheckKind, HealthCheckResult, HealthStatus};
pub use crate::checker::HealthChecker;
pub use crate::heartbeat::HeartbeatTracker;
pub use crate::incident::{
    Incident, IncidentEvent, IncidentManager, IncidentSeverity, IncidentState,
};
pub use crate::metrics::{Dashboard, Metric, MetricPoint};
pub use crate::sla::{SlaTarget, SlaTracker, UptimeRecord};
pub use crate::status::{ComponentStatus, StatusComponent, StatusPage};
pub use crate::time::now_secs;
