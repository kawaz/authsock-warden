# DR-002: 新規リポジトリ vs authsock-filter リネーム

- **Status**: Active
- **Date**: 2026-04-02

## 背景
authsock-filter（既存のSSH鍵フィルタツール）を拡張してwardenの機能を追加するか、新規リポジトリとして作成するか。

## 検討した選択肢

### A. authsock-filter をリネーム・拡張
- **利点**: git履歴が維持される。GitHubの自動リダイレクトで旧URLが壊れない。
- **欠点**: aqua standard registry に登録済みで、不明なユーザーがいる可能性がある。リネームは既存ユーザーに影響を与える。

### B. 新規リポジトリとして作成
- **利点**: 既存ユーザーに影響なし。warden向けに最適化したアーキテクチャで一から設計可能。
- **欠点**: git履歴リセット。コードの重複が一時的に発生。

### C. コード移植（authsock-filterは残す）
- **利点**: Bと同様 + authsock-filter のコードを参考にしつつ warden 向けに再設計可能。
- **欠点**: Bと同じ。

## 決定
**C. コード移植。authsock-filter はそのまま残し、authsock-warden を新規リポジトリとして作成。**

## 理由
authsock-filter は Homebrew tap と aqua standard registry で配布されており、未知のユーザーがいる可能性がある。warden の完成度が十分になるまで authsock-filter はアーカイブせずそのまま維持する。
