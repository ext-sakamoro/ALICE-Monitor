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

`AGPL-3.0 OR LicenseRef-Commercial` — デュアルライセンス どちらかを選べる

| 選択肢 | 条文 | こういう時 |
|--------|------|-----------|
| **AGPL-3.0** | [LICENSE-AGPL](LICENSE-AGPL) — 無償、報告義務なし | 自分の project も AGPL 互換の OSS、または社内利用のみ |
| **商用ライセンス** | [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md) — 有償、コピーレフト義務を解除 | クローズドソース製品 / 商用 SaaS / エッジ・ファームウェア配布 / plugin 再配布 / ソース開示を禁じるプラットフォーム NDA |

AGPL は強いコピーレフト: `alice-monitor` を link して配布 / 提供する製品・ファームウェア・
サービスは AGPL で公開する義務がある これはオープンなエコシステムのための意図的な
選択で、それが実行できない場合のために商用ライセンスを用意している

商用ライセンスの問い合わせ: <contact@extoria.co.jp>
