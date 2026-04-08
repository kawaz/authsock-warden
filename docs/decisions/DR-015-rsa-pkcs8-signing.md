# DR-015: RSA PKCS#8 署名対応

- **Status**: Accepted
- **Date**: 2026-04-08

## 背景

1Password の `op` CLI が返す RSA 秘密鍵は PKCS#8 形式（`BEGIN PRIVATE KEY`）でエンコードされている。authsock-warden は従来 OpenSSH 形式（`BEGIN OPENSSH PRIVATE KEY`）のみ対応しており、Ed25519 については OID パターンマッチによる手動パースで PKCS#8 に対応済みだったが（既存の `parse_pkcs8_ed25519`）、RSA の PKCS#8 形式は未対応だった。

また、SSH エージェントプロトコルでは RSA 鍵の署名時に `SSH_AGENT_RSA_SHA2_256`（0x02）/ `SSH_AGENT_RSA_SHA2_512`（0x04）フラグでハッシュアルゴリズムを指定するが、この分岐処理も未実装だった。

## 検討した選択肢

### A. pkcs8 クレートのみで RSA / Ed25519 両方をパース

- **利点**: 標準的な ASN.1 パーサで統一的に処理できる
- **欠点**: 1Password が出力する Ed25519 鍵の DER エンコーディングが non-canonical（RFC 5958 の strict DER に準拠しない）であり、`pkcs8::PrivateKeyInfo` がパースを拒否する。Ed25519 には適用できない

### B. RSA は pkcs8 クレート、Ed25519 は OID パターンマッチ（採用）

- **利点**: RSA の PKCS#8 構造は標準準拠しており `pkcs8` + `rsa` クレートで正しくパースできる。Ed25519 は既存の手動パースがそのまま使える
- **欠点**: 鍵タイプによってパース戦略が異なる。ただし実際には 1Password の出力特性に起因する必然的な分岐である

### C. 全鍵タイプを OID パターンマッチで手動パース

- **利点**: 外部クレート不要
- **欠点**: RSA の PKCS#8 構造は Ed25519 と比べて複雑（複数の大整数フィールド）で、手動パースはエラーが起きやすい

## 決定

**B. RSA は `rsa` + `pkcs8` クレートでパース、Ed25519 は既存の OID パターンマッチを継続。**

加えて、SSH エージェントプロトコルのフラグに応じた RSA 署名アルゴリズム選択を実装する。

## 設計

### PKCS#8 RSA 鍵のパース

`parse_pkcs8_rsa` 関数で `rsa::RsaPrivateKey::from_pkcs8_pem()` を使い、PKCS#8 PEM から RSA 秘密鍵を取得。その後 `ssh_key::private::RsaKeypair` に変換して `ssh_key::PrivateKey` として扱う。

```
PEM (BEGIN PRIVATE KEY)
  → rsa::RsaPrivateKey::from_pkcs8_pem()
  → RsaKeypair::try_from()
  → PrivateKey::from()
```

### RSA 署名アルゴリズム選択

`sign_rsa` 関数で SignRequest のフラグを参照し、署名アルゴリズムを分岐:

| フラグ | アルゴリズム | SSH 名 |
|---|---|---|
| `SSH_AGENT_RSA_SHA2_512` (0x04) | SHA-512 + PKCS#1 v1.5 | `rsa-sha2-512` |
| `SSH_AGENT_RSA_SHA2_256` (0x02) | SHA-256 + PKCS#1 v1.5 | `rsa-sha2-256` |
| なし (0x00) | ssh-key クレートのデフォルト (SHA-1) | `ssh-rsa` |

### パース順序

`parse_private_key` は以下の順でパースを試行:

1. OpenSSH 形式（`PrivateKey::from_openssh`）
2. PKCS#8 Ed25519（OID パターンマッチ）
3. PKCS#8 RSA（`rsa` + `pkcs8` クレート）

### 追加クレート

- `rsa = "0.9"` — RSA 秘密鍵操作と PKCS#1 v1.5 署名
- `pkcs8 = "0.10"` — `DecodePrivateKey` トレイトによる PKCS#8 PEM パース
- `sha2 = "0.10"` — SHA-256/SHA-512 ハッシュ（署名アルゴリズム用）
- `signature = "2"` — 署名トレイト（`Signer`）

## 理由

- **1Password の RSA 鍵は PKCS#8 形式**: op CLI の `op item get --format=pem` は RSA 鍵を PKCS#8（`BEGIN PRIVATE KEY`）で返す。OpenSSH 形式への変換手段がないため、PKCS#8 パースの対応が必要
- **Ed25519 と RSA で戦略を分ける必然性**: 1Password の Ed25519 出力が non-canonical DER であるため `pkcs8` クレートでは拒否される。RSA は標準準拠しているため `pkcs8` クレートで正しくパースできる。鍵タイプごとに最適な戦略を使い分けるのは妥当
- **SSH_AGENT_RSA_SHA2_256/512 対応**: OpenSSH 7.2 以降、クライアントはフラグで sha2 系ハッシュを要求する。未対応だと RSA 鍵での認証が sha1（ssh-rsa）にフォールバックし、多くのサーバで拒否される

## リスク/トレードオフ

- **クレート数の増加**: rsa, pkcs8, sha2, signature の4クレートが追加された。ただし ssh-key クレートの依存ツリーと重複しており、実際のバイナリサイズへの影響は限定的
- **Ed25519 の手動パースの維持**: OID パターンマッチは Ed25519 の固定構造に依存している。将来 1Password が DER エンコーディングを修正すれば `pkcs8` クレートに統一できるが、現時点では手動パースが唯一の手段

## 関連

- `src/keystore/signer.rs` — 実装箇所（`parse_pkcs8_rsa`, `sign_rsa`）
