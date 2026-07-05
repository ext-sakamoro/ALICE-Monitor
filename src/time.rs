//! UNIX timestamp helper.

use std::time::SystemTime;

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
