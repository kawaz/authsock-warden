# 1Password SSH agent の公開鍵コメントフィールド調査

- **Date**: 2026-04-02

## 目的
ssh-add -L で取得する公開鍵の3列目（コメント）に itemid や vault 情報が含まれるか確認。

## 結果
コメントフィールドは単なるラベル文字列。

```
ssh-ed25519 AAAA... SSH: kawaz@kawaz-mbp.local_20151013
```

- `op://vault/itemid` のような構造化情報は含まれない
- itemid や vault 名は含まれない
- 1Passwordアイテムに設定されたタイトル/コメントがそのまま返される

## 結論
公開鍵のコメントフィールドからは 1Password のリソースを特定できない。公開鍵そのもの（またはfingerprint）をキーにしたマッピングが必要。
