# authsock-warden Design

## 概要
SSH_AUTH_SOCK の番人。複数の鍵ソース（1Password SSH agent、op CLI、ファイル）を統合し、鍵フィルタリング + 署名条件制御 + 鍵の遅延取得/自動破棄を行うSSH agentプロキシ。

## 名前の由来
authsock（SSH_AUTH_SOCK）+ warden（番人・管理人）

## 解決する問題
- SSH署名に1PasswordのSSH agent（SSH_AUTH_SOCK）を使っている
- 1Password側では鍵ごとに再認証（TouchID）のタイムアウトを個別設定できない
- 秘密鍵のローカルコピーは作りたくない（セキュリティ・2重管理の観点）
- AI agentがリモートからSSH署名を行う際、TouchIDが物理的に不可能
- 用途ごとに異なるソケットで異なる鍵セット・ポリシーを適用したい

## アーキテクチャ

### レイヤー構成
1. **SSH Agent Protocol サーバ** — Unix domain socket で SSH agent protocol を提供
2. **KeySource 抽象化** — 複数の鍵ソースを統一インタフェースで管理
3. **フィルタレイヤー** — ソケット単位で公開鍵の可視性を制御（authsock-filter由来）
4. **ポリシーエンジン** — 鍵ごと・ソケットごとの署名許可条件（3層ポリシー）
5. **鍵ライフサイクル管理** — 4状態遷移、タイムアウト、re-auth
6. **セキュリティ** — メモリ保護（mlock, zeroize）、デバッガ拒否

### KeySource 抽象化

authsock-warden は複数の鍵ソースタイプをサポートする。

| ソースタイプ | type値 | 署名方式 | 鍵の在処 | 認証 |
|---|---|---|---|---|
| agent (proxy) | `"agent"` | upstream に転送 | upstream が保持 | upstream 任せ |
| 1Password | `"op"` | warden がローカル署名 | op CLI で遅延取得 → メモリ | TouchID |
| ファイル | `"file"` | warden がローカル署名 | ファイルから読み込み → メモリ | パスフレーズ |

共通パターン:
- 公開鍵の発見（起動時）
- 署名時の認証（初回）
- メモリ保持（ローカル署名の場合）
- タイムアウト/破棄

trait設計イメージ:
```rust
trait KeySource {
    fn name(&self) -> &str;
    fn discover(&self) -> Vec<Identity>;
    fn sign(&self, key: &PublicKey, data: &[u8], flags: u32) -> Result<Signature>;
    fn forget(&self, key: &PublicKey);  // proxy はno-op
}
```

### 鍵の4状態ライフサイクル

```
Not Loaded → Active → Locked → Forgotten
                ↑        │
                └────────┘ (re-auth)
```

| 状態 | メモリ | 署名 | 遷移条件 |
|---|---|---|---|
| Not Loaded | なし | 不可 | → Active: 初回取得（TouchID/パスフレーズ） |
| Active | あり | 可 | → Locked: timeout (on_timeout = "lock") |
| Locked | あり | 不可（re-auth待ち） | → Active: re-auth 成功 |
| Forgotten | ゼロクリア済み | 不可 | → Active: 再取得（TouchID必須） |

agent (proxy) ソースはメモリに鍵を持たないので lock/forget 対象外。署名の可否は upstream agent に委ねる。

### 署名フロー
1. クライアントがSSH_AUTH_SOCKに署名リクエスト送信
2. 接続元プロセス判定（LOCAL_PEERPID + プロセスツリー遡上）
3. ポリシーエンジンが許可判定（effective ポリシー = key ∩ socket）
4. KeySource に署名を委譲:
   - agent: upstream に転送
   - op/file: 鍵ストアから秘密鍵取得（未ロードなら取得 → 認証）→ warden自身が署名
5. レスポンス返却
6. タイムアウト/アイドル条件で鍵を Locked または Forgotten に遷移

### refresh フロー

refresh は常に同一フローで、ローカル/リモートを区別しない。warden 独自の認証が必須であり、op item get の成功は認証としてカウントしない:

```
refresh:
  1. warden 独自の認証（必須）
     設定された認証方式で認証:
     - re-auth command: 外部スクリプト（TouchIDラッパー、Passkey等）
     → 認証成功: ステップ2へ
     → 認証失敗: エラー
  2. 認証成功後の処理
     - op item get を試みる（ベストエフォート、鍵更新可能なら更新）
     - タイマーリセット
```

re-auth command で外部委譲することで、ユーザーが自分の環境に最適な認証フローを自由に構築可能。ローカル/リモートの判定は command 側の責任で、warden は結果（exit code）だけを見る。

### 公開鍵 → itemid マッピング（起動時）
1. 1Password SSH agentに公開鍵一覧を要求（ssh-add -L相当）
2. op item list --categories "SSH Key" でitemid一覧 + fingerprint取得（TouchID 1回）
3. fingerprint でマッチング → {pubkey_wire_format → itemid} マップ構築

## ポリシーの3層構造

1. **[[keys]]** — 鍵ごとのグローバルポリシー（天井）
2. **[sockets.xxx]** — ソケットごとのポリシー（制限のみ可、天井を超えられない）
3. **effective** = key と socket の交差（most restrictive wins）

ルール:
- `timeout`: min(key.timeout, socket.timeout)
- `allowed_processes`: key.processes ∩ socket.processes
- 未指定 = 制限しない（天井側に従う）

セキュリティツールとして、ソケット設定で意図せず天井を超えて緩くなることを防ぐ。

## re-auth 設計

on_timeout = "lock" の場合、メモリに鍵を保持したまま署名をロック。re-auth で解除。
on_timeout = "forget" の場合、即座にゼロクリア。再取得にはTouchID必須。

### 認証手段

初期実装は **re-auth command**（外部スクリプトに委譲）のみ。他は将来のビルトインオプション。

| 手段 | ローカル | リモート | 状態 |
|---|---|---|---|
| **command** | OK | OK | 初期実装 |
| macOS LocalAuthentication | OK | 不可 | 将来オプション |
| localhost HTTP + WebAuthn | OK | 不可 | 将来オプション |
| relay + WebAuthn | 不可 | OK | 将来オプション |

```toml
[auth]
method = "command"
command = "/path/to/notify-and-verify.sh"
# exit 0 = approved, exit 1 = denied
```

command でユーザーが自由に認証フローを組める（TouchID ラッパー、Passkey、Push通知等）。

### セキュリティ設計

| レイヤー | 手法 | 効果 |
|---|---|---|
| L0 | DYLD_INSERT_LIBRARIES 検出・拒否 | hook注入対策 |
| L1 | ptrace(PT_DENY_ATTACH) | デバッガアタッチ拒否 |
| L2 | mlock() | スワップ禁止 |
| L3 | zeroize + secrecy クレート | Drop時自動ゼロクリア |

### プロセス判定
- macOS: LOCAL_PEERPID でクライアントPID取得 → proc_pidpath/sysctl で親方向に遡上
- Linux: SO_PEERCRED でPID取得 → /proc/{pid}/exe, /proc/{pid}/status で遡上
- allowed_processes リストとプロセスチェーン全体をマッチング

## 設定ファイル

```toml
[policy]
idle_check_interval = "30s"
idle_check_command = "/path/to/cmux-check.sh"

[auth]
method = "command"
command = "/path/to/notify-and-verify.sh"

# 鍵ソース定義
[[sources]]
type = "agent"
name = "1password-proxy"
socket = "~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"

[[sources]]
type = "op"
name = "1password-managed"

[[sources]]
type = "file"
name = "local-keys"
paths = ["~/.ssh/id_work", "~/.ssh/id_personal"]

# ソケット定義
[sockets.work]
path = "$XDG_RUNTIME_DIR/authsock-warden/work.sock"
sources = ["1password-managed"]
filters = ["comment=~@work"]
timeout = "1h"
allowed_processes = ["git"]

[sockets.all]
path = "$XDG_RUNTIME_DIR/authsock-warden/all.sock"
sources = ["1password-proxy", "local-keys"]

# 鍵ごとのポリシー
[[keys]]
public_key = "ssh-ed25519 AAAA..."
timeout = "4h"
on_timeout = "lock"
forget_after = "24h"
allowed_processes = ["ssh", "git", "jj"]
```

## 技術スタック
- 言語: Rust (edition 2024)
- 非同期: tokio
- SSH鍵: ssh-key クレート
- CLI: clap (derive)
- 設定: serde + toml
- セキュリティ: zeroize, secrecy, nix (mlock/ptrace)

## authsock-filter との関係
authsock-warden は kawaz/authsock-filter の後継プロジェクト。authsock-filter の protocol/agent/filter モジュールを移植し、署名デーモン・メモリ保護・プロセス判定機能を追加。authsock-filter は既存ユーザー向けにそのまま維持。agent (proxy) ソースタイプにより authsock-filter の機能を完全に包含する。
