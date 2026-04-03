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
- [DR-013](DR-013-homebrew-formula-cask.md) — Homebrew Formula + Cask の2本立て配布: Formula は Linux 専用、Cask は macOS 専用 (.app バンドル)
- [DR-014](DR-014-macos-fda-tcc.md) — macOS FDA (Full Disk Access) による TCC 問題の解決: kTCCServiceSystemPolicyAppData の制限を FDA で包含的に回避

## Superseded

- [DR-005](DR-005-key-source-abstraction.md) — 鍵ソースの抽象化（DR-010 で置換）

## Archived

(なし)
