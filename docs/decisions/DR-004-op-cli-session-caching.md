# DR-004: op CLI の TouchID キャッシュ挙動

- **Status**: Active
- **Date**: 2026-04-02

## 背景
authsock-warden は op CLI を使って1Passwordからデータを取得する。起動時や署名時に毎回 TouchID が要求されると実用に耐えない。

## 調査結果（2026-04-02 実測）

### 基本挙動
- op CLI は呼び出しごとに biometric 認証（TouchID）を要求する
- ただし直接の呼び出し元PIDが記録されてタイムアウト付きで保持される

### PID祖先チェーンによるキャッシュ
- shellA で `op item list` → TouchID 発生
- shellA で `op item get` → TouchID 不要（同じPID祖先）
- shellB で `op item get` → TouchID 発生（別PID祖先）
- shellA 内で `zsh`（子シェル）→ `op item get` → TouchID 不要（祖先チェーンに認証済みPIDあり）

### && 連結時の挙動
- 1つのBash呼び出しで `op item list && op item get x3` を && 連結 → TouchID 1回のみ

### タイムアウト
- 1Passwordの設定に依存（ユーザーは12時間設定）

### Claude Code の Bash ツール
- Claude Code の Bash ツールは別プロセスツリーで実行される
- 親シェルの op 認証は Claude の Bash ツールには継承されない

## 設計への影響
- authsock-warden は自プロセスから直接 `std::process::Command` で op を呼ぶこと
- 外部プロセスに委譲するとキャッシュが効かない
- 起動時に1回 TouchID を通せば、以降の鍵取得はタイムアウトまでキャッシュで通る
- タイムアウト超過時は再度 TouchID が必要（許容範囲）
