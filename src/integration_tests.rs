//! Integration tests moved from monolithic lib.rs.

#![allow(
    clippy::float_cmp,
    clippy::similar_names,
    clippy::unreadable_literal,
    clippy::redundant_clone,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::doc_markdown,
    clippy::suboptimal_flops,
    clippy::many_single_char_names,
    clippy::needless_range_loop,
    clippy::manual_midpoint
)]

use std::time::Duration;

use crate::alert::{AlertEngine, AlertSeverity, AlertThreshold, Comparison};
use crate::check::{CheckKind, HealthCheckResult, HealthStatus};
use crate::checker::HealthChecker;
use crate::heartbeat::HeartbeatTracker;
use crate::incident::{Incident, IncidentManager, IncidentSeverity, IncidentState};
use crate::metrics::{Dashboard, Metric};
use crate::sla::{SlaTarget, SlaTracker, UptimeRecord};
use crate::status::{ComponentStatus, StatusPage};

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
        message: String::new(),
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
        message: String::new(),
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
        message: String::new(),
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
