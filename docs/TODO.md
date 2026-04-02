# TODO

## 設計負債（レビュー指摘）

### High Priority
- [ ] **WardProxy/KeyRegistry 統合** — 秘密鍵キャッシュが KeyRegistry の zeroize 保護をバイパスしている。OpManagedKey.cached_private_key を KeyRegistry に統合すべき
- [ ] **PKCS#8 パーサー改善** — pkcs8 クレートは 1Password の non-canonical DER を拒否するため断念。1Password 側が修正されるか、lenient モードが追加されるまで現行のパターンマッチを維持。Design rationale コメント追加済み
- [ ] **RSA 署名 flags 対応** — SSH_AGENT_RSA_SHA2_256/512 フラグに応じてハッシュアルゴリズムを切り替え

### Medium Priority
- [ ] **OP_AGENT_SOCK 環境変数** — 1Password agent socket パスをオーバーライド可能に
- [ ] **キャッシュファイル TOCTOU** — tempfile + rename でアトミック書き込み
- [ ] **sign_with_op 並行フェッチ排他** — 同じ鍵への並行署名で複数回 TouchID が出る問題
- [ ] **warden_proxy.rs 分割** — 800行超で大きすぎる。op 発見ロジックを別ファイルに

### Low Priority
- [ ] **macOS コード署名** — Hardened Runtime + Notarization (Apple Developer secrets 必要)
- [ ] **per-key timeout/lock/forget の run コマンド結合** — keystore ライフサイクルを WardProxy に統合
- [ ] **refresh/status/keys コマンド本実装**
- [ ] **file: ソース実装**
- [ ] **aqua standard registry 登録**

## 機能ロードマップ

- [ ] per-key timeout + lock/forget ライフサイクル
- [ ] re-auth command による Locked → Active 遷移
- [ ] refresh コマンド（タイマーリセット）
- [ ] status コマンド（鍵状態表示）
- [ ] idle_check_command によるアイドル検知
- [ ] SIGHUP でのリロード
