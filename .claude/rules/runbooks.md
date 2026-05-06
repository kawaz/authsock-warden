# Runbook 参照ルール

CI / リリース / デプロイで失敗が出たときは、まず `docs/runbooks/` を確認すること。コードを触る前にドキュメントの「即断する判断根拠」を当てはめる。

## 既存の runbook

- [Apple notarization 403 "agreement missing"](../../docs/runbooks/release-notarization-403.md) — release ワークフローの notarize ステップが 403 で失敗したとき
