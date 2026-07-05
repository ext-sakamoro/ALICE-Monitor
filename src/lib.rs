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

pub mod alert;
pub mod check;
pub mod checker;
pub mod heartbeat;
pub mod incident;
pub mod metrics;
pub mod prelude;
pub mod sla;
pub mod status;
pub mod time;

#[cfg(test)]
mod integration_tests;

// Backward-compat re-exports.
pub use crate::alert::*;
pub use crate::check::*;
pub use crate::checker::*;
pub use crate::heartbeat::*;
pub use crate::incident::*;
pub use crate::metrics::*;
pub use crate::sla::*;
pub use crate::status::*;
pub use crate::time::*;
