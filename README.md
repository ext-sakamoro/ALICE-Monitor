**English** | [日本語](README_JP.md)

# ALICE-Monitor

**ALICE Infrastructure Monitoring** — Health checks, alert thresholds, SLA tracking, uptime calculation, incident management, status pages, and heartbeat detection.

Part of [Project A.L.I.C.E.](https://github.com/anthropics/alice) ecosystem.

## Features

- **Health Checks** — HTTP endpoint, TCP socket, and local process monitoring
- **Health Status** — Healthy / Degraded / Unhealthy / Unknown status tracking
- **Alert Thresholds** — Configurable alerting with severity levels
- **SLA Tracking** — Service level agreement compliance monitoring
- **Uptime Calculation** — Availability percentage computation
- **Incident Management** — Incident creation, tracking, and resolution
- **Status Pages** — Service status dashboard data generation
- **Heartbeat Detection** — Periodic liveness signal monitoring

## Architecture

```
CheckKind
 ├── Http(url)
 ├── Tcp(host, port)
 └── Process(pid)

HealthCheckResult
 ├── kind: CheckKind
 ├── status: HealthStatus
 ├── latency: Duration
 └── timestamp

AlertManager
 ├── Threshold definitions
 └── Severity levels

SlaTracker
 ├── Uptime calculation
 └── SLA compliance check

IncidentManager
 └── Create / Track / Resolve
```

## Quick Start

```rust
use alice_monitor::{CheckKind, HealthStatus, HealthCheckResult};
use std::time::Duration;

let result = HealthCheckResult::new(
    CheckKind::Http("https://api.example.com/health".into()),
    HealthStatus::Healthy,
    Duration::from_millis(42),
    "OK",
);
```

## License

AGPL-3.0
