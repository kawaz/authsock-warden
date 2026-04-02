# op CLI の TouchID キャッシュ挙動調査

- **Date**: 2026-04-02

## 目的
authsock-warden の起動フローで op CLI を複数回呼び出す際に TouchID が何回発生するかを明らかにする。

## 実験1: 個別Bash呼び出し（op signout後）

| ステップ | コマンド | TouchID |
|---|---|---|
| signout | op signout --all | 1回 |
| 1 | op item list | 1回 |
| 2-8 | op item get x7件 | 各1回（計7回） |
| **合計** | | **9回** |

**結論**: 別々のBash呼び出しでは毎回TouchIDが発生。

## 実験2: パターン検証

### A: 同じコマンドを連続2回（別Bash呼び出し）
- op item list → TouchID
- op item list → TouchID
- **各呼び出しで発生**

### B: 3つのop item getを&&で1つのBashにまとめる
- op signout → TouchID
- op item get x3 を && 連結 → **TouchID 0回**
- **同一シェルプロセス内ではセッション共有**

### C: op item list && op item getを1つのBashにまとめる
- op signout → TouchID
- 以降すべて → **TouchID 0回（Bのセッション継続）**

## 実験3: ユーザー追試

| シェル | 操作 | TouchID |
|---|---|---|
| shellA | op item list | 1回 |
| shellA | op item get keyA | 不要 |
| shellA | op item get keyB | 不要 |
| shellB | op item get keyA | 1回 |
| shellB | op item get keyB | 不要 |
| shellC | op item list | 1回 |
| shellC | zsh → op item get keyA | 不要 |
| shellC | zsh → op item get keyB | 不要 |

## メカニズムの推定
1. op の直接の実行元PIDが記録され、タイムアウト付きで保持
2. チェック時は祖先チェーンを遡り、記録済みPIDが見つかれば許可
3. タイムアウトは1Passwordの設定に依存（ユーザーは12時間設定）

## Claude Code との相互作用
- Claude Code の Bash ツールはフロントエンドとは別のバックエンドプロセスから実行される
- 親シェルで op 認証済みでも、Claude の Bash ツールには継承されない
- プロセスツリー:
  - 親zsh (91160) → claude CLI (14367) [フロントエンド]
  - 別ツリー: zsh (37164) → claude (5375) → Bash ツール (21843) [バックエンド]

## authsock-warden への示唆
- warden プロセスから直接 `Command::new("op")` で呼ぶ → キャッシュが効く
- 起動時に1回 TouchID → 以降タイムアウトまでフリー
