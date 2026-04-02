# op:// Secret Reference 構文調査

- **Date**: 2026-04-02
- **Sources**: https://developer.1password.com/docs/cli/secret-reference-syntax/ 他

## 目的

authsock-warden の source member 記法で `op://` を使うにあたり、1Password 公式の仕様を把握する。

## 公式の正式形式

```
op://vault/item/[section/]field[?attr=value]
```

3〜4コンポーネント必須。vault, item, field は省略不可。

## パスコンポーネントの指定方法

| コンポーネント | 名前（表示名） | ID（26文字英数字） | 備考 |
|---|---|---|---|
| vault | OK | OK | 同名 vault が複数ある場合は ID 必須 |
| item | OK | OK | ID のほうが高速。vault 移動時のみ ID が変わる |
| field | ラベルで指定 | ID で指定 | SSH Key のフィールド: `public key`, `private key`, `fingerprint`, `key type` |

- **大文字小文字は区別しない**（case-insensitive）
- スペース含む名前は引用符で囲む: `op://"My Vault"/item/field`
- `/`, `=`, `\` 等の特殊文字を含む名前は ID で指定する必要あり

## クエリパラメータ

| パラメータ | 用途 |
|---|---|
| `?attr=type` | フィールドの型を取得 |
| `?attr=otp` | OTP フィールドからワンタイムパスワード生成 |
| `?ssh-format=openssh` | SSH 秘密鍵を OpenSSH 形式で取得 |

## ワイルドカード・カテゴリ指定

- ワイルドカード: **不可**
- 正規表現: **不可**
- カテゴリ指定: **不可**（`op://` にはカテゴリフィルタ構文がない）

## テンプレート変数

```
op://${VAULT:-dev}/item/field
```

`${VAR:-default}` でデフォルト値を設定可能。

## authsock-warden での独自拡張

公式は常に vault/item/field の3要素が必要だが、warden は SSH 鍵スコープのショートカットとして以下を独自定義:

| warden 記法 | 意味 | 内部動作 |
|---|---|---|
| `op://` | 全 vault の全 SSH 鍵 | `op item list --categories SSH_KEY` |
| `op://vault` | vault 内の SSH 鍵 | `op item list --categories SSH_KEY --vault vault` |
| `op://vault/item` | 特定の SSH 鍵 | `op item get vault/item` |

公式形式との区別:
- 公式: パスが3要素以上（vault/item/field）
- warden: パスが0〜2要素（vault のみ、または vault/item）
- 衝突しない（field 省略は公式では invalid）
