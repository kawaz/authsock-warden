# Design Records

## Active

- [DR-001](DR-001-language-choice.md) — 実装言語: Rust を選択（Go との比較）
- [DR-002](DR-002-new-repo-vs-rename.md) — authsock-filter のリネームではなく新規リポジトリとして作成
- [DR-003](DR-003-pubkey-itemid-mapping.md) — 公開鍵→itemidマッピング: fingerprint ベースで op item list 1回のみ
- [DR-004](DR-004-op-cli-session-caching.md) — op CLI のTouchIDキャッシュ: PID祖先チェーンで共有、warden自プロセスから直接呼び出し
- [DR-006](DR-006-key-lifecycle-4states.md) — 鍵の4状態ライフサイクル: Not Loaded → Active → Locked → Forgotten
- [DR-007](DR-007-refresh-flow.md) — 統一refreshフロー: warden独自認証を必須とし、ローカル/リモートを区別しない
- [DR-008](DR-008-policy-merge-strategy.md) — ポリシーのマージ戦略: 鍵が天井、ソケットが制限（most restrictive wins）
- [DR-009](DR-009-auth-method-command-first.md) — 認証手段: re-auth command を優先実装、LocalAuthentication/WebAuthn は将来オプション
- [DR-010](DR-010-source-group-design.md) — source グループ設計: members で複数鍵ソースを束ねる、CLI グループ方式と対応
- [DR-011](DR-011-op-key-discovery-strategy.md) — op 鍵発見の段階的キャッシュ戦略: agent socket リフレッシュ + ディスクキャッシュ + op item list は初回のみ
- [DR-012](DR-012-app-bundle-wrapper.md) — .app バンドルラッパーによる TCC 許可の永続化
- [DR-013](DR-013-homebrew-formula-cask.md) — Homebrew Cask のみで配布: macOS は Cask (.app バンドル)、Linux は GitHub Releases 直接取得
- [DR-014](DR-014-macos-fda-tcc.md) — macOS FDA (Full Disk Access) による TCC 問題の解決: kTCCServiceSystemPolicyAppData の制限を FDA で包含的に回避
- [DR-015](DR-015-rsa-pkcs8-signing.md) — RSA PKCS#8 署名対応: rsa + pkcs8 クレートで 1Password の PKCS#8 RSA 鍵をパース、SHA2 署名アルゴリズム選択を実装
- [DR-016](DR-016-cli-args-config-skip-and-fda-retry.md) — CLI 引数時のデフォルト Config スキップと FDA Check Retry
- [DR-017](DR-017-process-chain-audit-logging.md) — Process Chain Audit Logging: ProcessInfo 拡張 (uid/gid/cwd/argv/start_time) と JSONL 形式の監査ログ
- [DR-018](DR-018-kv-cache-warden.md) — KV キャッシュ機能（cache-warden 構想）: セキュア KV + プロセス認証 + TouchID + TTL による汎用キャッシュ

## Superseded

- [DR-005](DR-005-key-source-abstraction.md) — 鍵ソースの抽象化（DR-010 で置換）

## Archived

(なし)
