# DR-017: Process Chain Audit Logging

- **Status**: Accepted
- **Date**: 2026-04-08

## 背景

SSH agent への鍵アクセスを監査するため、リクエスト元プロセスの情報を詳細に記録する必要がある。従来の ProcessInfo は pid, name, path, ppid のみで、「誰が」「どこから」「何のコマンドで」アクセスしたかの追跡が不十分だった。セキュリティ監査やインシデント対応において、プロセスの実行ユーザー、作業ディレクトリ、コマンドライン引数、起動時刻は不可欠な情報である。

## 決定

### ProcessInfo の拡張

`ProcessInfo` に以下のフィールドを追加:

| フィールド | 型 | 用途 |
|---|---|---|
| `uid` | `Option<u32>` | 実ユーザーID |
| `gid` | `Option<u32>` | 実グループID |
| `cwd` | `Option<PathBuf>` | カレントワーキングディレクトリ |
| `argv` | `Option<Vec<String>>` | コマンドライン引数 |
| `start_time` | `Option<u64>` | プロセス起動時刻（Unix epoch 秒） |

すべて `Option` で、取得できない場合は `None`。`serde(skip_serializing_if = "Option::is_none")` で JSONL 出力時に省略。

### プラットフォーム別実装

#### macOS

- **uid / gid / start_time**: `proc_pidinfo(PROC_PIDTBSDINFO)` で `proc_bsdinfo` を取得。`pbi_ruid`（実UID）、`pbi_rgid`（実GID）、`pbi_start_tvsec`（起動時刻）を使用
- **cwd**: `proc_pidinfo(PROC_PIDVNODEPATHINFO)` で `proc_vnodepathinfo` を取得。`pvi_cdir.vip_path` からカレントディレクトリを取得
- **argv**: `sysctl(CTL_KERN, KERN_PROCARGS2)` で取得。バッファレイアウトは `[argc: i32][exec_path\0][padding\0...][arg0\0][arg1\0]...[argN\0][env...]`。exec_path をスキップし、NUL パディングを読み飛ばして argc 個の引数を読み取る

#### Linux

- **uid / gid**: `/proc/PID/status` の `Uid:` / `Gid:` 行から実ID（最初のフィールド）を取得
- **start_time**: `/proc/PID/stat` の field 22（starttime、clock ticks）を `/proc/stat` の `btime`（ブート時刻）と `sysconf(_SC_CLK_TCK)` で epoch 秒に変換
- **cwd**: `/proc/PID/cwd` のシンボリックリンクを readlink
- **argv**: `/proc/PID/cmdline` を NUL 区切りで分割

### Audit ログ出力

`REQUEST_IDENTITIES` および `SIGN_REQUEST` の処理時に、tracing の `info!` マクロで JSONL 形式の audit ログを出力する。

- **target**: `authsock_warden::audit`
- **出力先**: proxy.rs（agent バックエンド）と warden_proxy.rs（warden バックエンド、op 鍵を含む）の両方

#### REQUEST_IDENTITIES のログ構造

```json
{
  "event": "REQUEST_IDENTITIES",
  "socket": "/path/to/socket",
  "original": 5,
  "filtered": 2,
  "keys": [{"key": "ssh-ed25519 SHA256:xxxx...", "comment": "..."}],
  "process_chain": [{"pid": 1234, "name": "ssh", "uid": 501, "argv": ["ssh", "host"], ...}]
}
```

#### SIGN_REQUEST のログ構造

```json
{
  "event": "SIGN_REQUEST",
  "socket": "/path/to/socket",
  "key": "ssh-ed25519 SHA256:xxxx...",
  "result": "success|denied|failed|error",
  "backend": "agent|op",
  "process_chain": [...]
}
```

### target ベースフィルタリング

tracing の target フィルタにより、audit ログを独立して制御できる:

```
# 通常ログは info、audit は別ファイルに出力
RUST_LOG=info,authsock_warden::audit=info

# audit のみ有効化
RUST_LOG=warn,authsock_warden::audit=info
```

これにより、アプリケーションログと監査ログを異なるレベル・出力先で運用できる。

## 検討した代替案

### syslog / auditd 連携

- **利点**: OS レベルの監査基盤と統合。改ざん耐性が高い。既存の SIEM との連携が容易
- **欠点**: macOS と Linux で API が大きく異なる。macOS の Unified Logging (os_log) と Linux の auditd は抽象化が困難。実装コストが高い
- **判断**: 将来の拡張として残す。現時点では tracing + JSONL で十分な監査能力を確保し、syslog 転送は tracing の subscriber レイヤーで後付け可能

### 構造化ログライブラリ（slog 等）の独立使用

- **利点**: audit 専用のログパイプラインを構築可能
- **欠点**: tracing と二重管理になる。tracing の target フィルタで同等のことが実現可能
- **判断**: 不採用。tracing の target ベースフィルタリングで audit ログの独立制御が十分に可能

## リスク/トレードオフ

- **パフォーマンス**: プロセスチェーン全体の情報取得（特に argv の sysctl/procfs 読み取り）はリクエストごとに発生する。ただし SSH agent リクエストは低頻度であり、実用上のボトルネックにはならない
- **権限**: macOS では `proc_pidinfo` / `sysctl(KERN_PROCARGS2)` は同一ユーザーのプロセスに対してのみ完全な情報を返す。他ユーザーのプロセスは一部フィールドが取得できない場合がある（`Option` で吸収）
- **argv のセキュリティ**: コマンドライン引数にパスワード等の機密情報が含まれる可能性がある。ログの保管・アクセス制御はユーザーの責任

## 関連

- `src/policy/process.rs` — ProcessInfo / ProcessChain の実装
- `src/agent/proxy.rs` — agent バックエンドの audit ログ出力
- `src/agent/warden_proxy.rs` — warden バックエンドの audit ログ出力
