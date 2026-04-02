# SSH Agent Protocol の公開鍵形式調査

- **Date**: 2026-04-02

## 目的
SSH agent protocol の署名リクエストに含まれる公開鍵の形式と、ssh-add -L で取得する公開鍵の形式の関係を明らかにする。起動時に構築したマップを署名リクエスト時に引けるか確認。

## SSH Agent Protocol (draft-miller-ssh-agent)

### SSH_AGENTC_SIGN_REQUEST (13) のメッセージ形式
```
byte     SSH_AGENTC_SIGN_REQUEST
string   key blob
string   data
uint32   flags
```

key blob は「標準的な SSH wire format」でエンコードされた公開鍵。

### SSH wire format
- RSA/DSS: RFC 4253 section 6.6
- ECDSA: RFC 5656
- Ed25519/Ed448: RFC 8709

## authorized_keys 形式との関係

- `ssh.PublicKey.Marshal()` 相当 → SSH wire format のバイト列
- authorized_keys 形式 = `キータイプ名 + " " + base64(wire_format) + "\n"`
- つまり authorized_keys は wire format の base64 ラッパー

## マップキーとしての利用

golang.org/x/crypto/ssh/agent の keyring.go 実装が参考になる:

```go
// Sign メソッド内のキーマッチング
wanted := key.Marshal()
bytes.Equal(k.signer.PublicKey().Marshal(), wanted)
```

`Marshal()` の出力バイト列同士を比較して鍵の同一性を判定している。

## 結論

- ssh-add -L の公開鍵を `ParseAuthorizedKey()` でパース → `Marshal()` でバイト列取得
- 署名リクエストの key_blob（wire format）と完全一致
- `string(pubkey.Marshal())` や `Vec<u8>` をハッシュマップのキーにすれば O(1) ルックアップ可能
- authsock-warden の {pubkey_wire_format → itemid} マップは正しく機能する
