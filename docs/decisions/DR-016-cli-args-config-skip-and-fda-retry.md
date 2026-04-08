# DR-016: CLI 引数時のデフォルト Config スキップと FDA Check Retry

- **Status**: Accepted
- **Date**: 2026-04-08

## 背景

### デフォルト config の上書き問題

`authsock-warden run` を CLI 引数（`--socket`, `--source` 等）のみで起動した場合、`--config` を指定していなくても、デフォルトの config ファイル（`~/.config/authsock-warden/config.toml`）が存在すると自動的に読み込まれる。config に定義された socket パスと CLI で指定した socket パスが競合し、常駐プロセス（LaunchAgent）が使用中の socket を上書きしてしまう問題があった。

典型的なシナリオ:

```
# LaunchAgent が config.toml の設定で常駐中（/tmp/authsock-warden.sock を使用）
# ユーザーが一時的に別の設定でテスト起動
authsock-warden run --socket /tmp/test.sock --source op://
# → config.toml も読み込まれ、/tmp/authsock-warden.sock も開いてしまう
```

### FDA チェックの初回レイテンシ

FDA (Full Disk Access) チェックは `open --wait-apps` で .app バンドルを起動して行う（DR-014）。app バンドルの初回起動時には macOS のプロセス起動レイテンシがあり、1回のチェックでは FDA が有効であっても false を返すことがあった。

## 決定

### 1. CLI 引数時のデフォルト config スキップ

`--config` 未指定かつ CLI 引数（`--socket`, `--source` 等）ありの場合、デフォルト config ファイルの自動読み込みをスキップする。

- `--config` 明示指定時は常に読み込む（CLI 引数との併用も可能）
- `--config` なし + CLI 引数なし → 従来通りデフォルト config を自動検出・読み込み

判定ロジック（`src/cli/commands/run.rs`）:

```rust
let has_cli_args = !args.source.is_empty() || !args.socket.is_empty();
let effective_config_path = if config_path.is_none() && has_cli_args {
    None  // skip auto-detection
} else {
    config_path
};
```

### 2. FDA check のリトライ

`check_fda_with_retry()` で最大3回リトライする。各試行の間に1秒の待機を入れ、app 起動レイテンシを吸収する。

```rust
fn check_fda_with_retry() -> Result<bool> {
    for _ in 0..3 {
        if check_fda_via_app()? {
            return Ok(true);
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Ok(false)
}
```

### 3. FDA 確認後の System Settings 自動クローズ

FDA が有効になったことを検出した後、`osascript` で System Settings を自動的に閉じる。service register のフローで自動的に開いた System Settings を閉じることで、ユーザーの手間を減らす。

```rust
let _ = std::process::Command::new("osascript")
    .args(["-e", "tell application \"System Settings\" to quit"])
    .status();
```

## 理由

- **config スキップ**: CLI 引数で明示的にソケットを指定している場合、デフォルト config の自動読み込みは意図しない副作用を起こす。`--config` を明示指定した場合は意図が明確なので読み込む
- **3回リトライ**: .app バンドルの初回起動は macOS のプロセスキャッシュ等の影響でレイテンシがある。3回 x 1秒の待機で実用上十分に吸収できる
- **System Settings の自動クローズ**: service register のフロー内で自動的に開いたウィンドウなので、完了後に自動で閉じるのが自然

## リスク/トレードオフ

- **config スキップの暗黙性**: CLI 引数の有無でデフォルト config の読み込み有無が変わる挙動は、ユーザーにとって予測しにくい可能性がある。ただし `--config` を明示指定すれば常に読み込まれるため、意図的に両方を使いたい場合は回避可能
- **リトライ回数の固定**: 3回では不足するケースがあり得るが、実運用では問題が報告されていない。過度に増やすとユーザーの待ち時間が増える

## 関連

- [DR-012](DR-012-app-bundle-wrapper.md) — .app バンドルラッパーによる TCC 許可の永続化
- [DR-014](DR-014-macos-fda-tcc.md) — macOS FDA (Full Disk Access) による TCC 問題の解決
