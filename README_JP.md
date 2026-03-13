[English](README.md) | **日本語**

# ALICE-Monitor

**ALICE インフラストラクチャ監視** — ヘルスチェック、アラート閾値、SLA追跡、稼働率計算、インシデント管理、ステータスページ、ハートビート検出。

[Project A.L.I.C.E.](https://github.com/anthropics/alice) エコシステムの一部。

## 機能

- **ヘルスチェック** — HTTPエンドポイント、TCPソケット、ローカルプロセス監視
- **ヘルスステータス** — Healthy / Degraded / Unhealthy / Unknown の状態追跡
- **アラート閾値** — 重要度レベル付きの設定可能なアラート
- **SLA追跡** — サービスレベル契約の遵守状況監視
- **稼働率計算** — 可用性パーセンテージの算出
- **インシデント管理** — インシデントの作成・追跡・解決
- **ステータスページ** — サービス状態ダッシュボードデータの生成
- **ハートビート検出** — 定期的な生存信号の監視

## アーキテクチャ

```
CheckKind
 ├── Http（URL）
 ├── Tcp（ホスト、ポート）
 └── Process（PID）

HealthCheckResult
 ├── kind: CheckKind
 ├── status: HealthStatus
 ├── latency: Duration
 └── timestamp

AlertManager
 ├── 閾値定義
 └── 重要度レベル

SlaTracker
 ├── 稼働率計算
 └── SLA遵守チェック

IncidentManager
 └── 作成 / 追跡 / 解決
```

## クイックスタート

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

## ライセンス

AGPL-3.0
