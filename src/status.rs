//! Status page.

use std::fmt;
use std::fmt::Write;

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
