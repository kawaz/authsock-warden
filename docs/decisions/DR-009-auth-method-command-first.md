# DR-009: 認証手段の選定 — re-auth command を優先実装

- **Status**: Active
- **Date**: 2026-04-02

## 背景
warden 独自の認証（refresh 時、Locked → Active 遷移時）に使う手段を決める必要がある。

候補:
1. macOS LocalAuthentication フレームワーク（TouchID 直接呼び出し）
2. localhost HTTP + WebAuthn/Passkey
3. relay サーバ + WebAuthn/Passkey（リモート対応）
4. re-auth command（外部スクリプトに委譲）

## 比較

| 手段 | ローカル | リモート | 実装コスト | クロスプラットフォーム |
|---|---|---|---|---|
| macOS LocalAuthentication | OK | 不可 | 中（Rust FFI） | macOSのみ |
| localhost HTTP + WebAuthn | OK | 不可 | 中 | macOS + Linux |
| relay + WebAuthn | 不可 | OK | 高 | macOS + Linux |
| re-auth command | OK | OK | 低 | 任意 |

補足:
- WebAuthn は Secure Context 必須だが `localhost` は例外で HTTP でも動作する
- re-auth command はユーザーが自由に認証フローを組める（Passkey、Push通知、CLI確認等）

## 決定
**re-auth command を優先実装。** 他の手段は将来のビルトインオプションとして必要に応じて追加。

```toml
[auth]
method = "command"
command = "/path/to/notify-and-verify.sh"
# exit 0 = approved, exit 1 = denied
```

## 理由
- re-auth command で全ユースケース（ローカル TouchID、リモート Passkey、Push 通知等）を外部委譲で実現可能
- 実装コストが最も低く、プロジェクト初期に適切
- ユーザーが自分の環境に最適な認証フローを自由に構築できる
- LocalAuthentication や WebAuthn は command のラッパーとしても提供でき、将来ビルトイン化しても command との互換性を維持可能
