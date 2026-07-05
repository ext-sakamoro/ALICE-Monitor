//! Incident management.

use std::fmt;

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
