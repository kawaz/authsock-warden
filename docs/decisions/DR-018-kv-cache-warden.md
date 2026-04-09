# DR-018: KV キャッシュ機能（cache-warden 構想）

- **Status**: Proposed
- **Date**: 2026-04-08

## 背景

1Password (op CLI) はセキュアだが遅い（item あたり 0.5〜1秒）。環境変数は速いがセキュアでない（`/proc/PID/environ` で見える）。

authsock-warden が既に持つ mlock/zeroize、プロセスチェーン検証、TTL 管理、TouchID 連携は汎用 KV キャッシュに転用できる。「速くてセキュアで、TTL 切れたら生体認証で延長」を提供するツールは既存に無い。

SSH agent のキーも本質的には同じ構造であり、warden のコアは「セキュア KV + プロセス認証 + TouchID + TTL」、SSH agent はその上のプロトコルアダプタと捉え直せる。

## 決定

**別プロジェクトではなく authsock-warden のサブコマンドとして統合する方向。** ただし別プロジェクト（cache-warden）として作る可能性も残っており、最終決定はまだ。

## 理由

- コア機能（mlock/zeroize、プロセスチェーン検証、TTL 管理、TouchID 連携）の共有コード量が多く、重複を避けるため統合が自然
- SSH agent と KV キャッシュは同じ「セキュア値の保護と提供」というドメインに属する
- 統合することでデーモンプロセスも1つで済む

## 設計概要

### 2種類の value ソース

| 種類 | set 時 | soft TTL 切れ | hard TTL 切れ |
|---|---|---|---|
| **static** | `warden kv set KEY --value "xxx"` やパイプ | TouchID → 延長 | zeroize。再取得不可（再 set が必要） |
| **command** | `warden kv set KEY --command "op read ..."` | TouchID → 延長 | zeroize → コマンド再実行 → TouchID → キャッシュ再生成 |

### soft TTL と hard TTL

- **soft TTL 切れ**: authsock-warden 自身が TouchID (LocalAuthentication.framework) でユーザー認証 → 成功したらキャッシュ延長。上流に取りに行かない
- **hard TTL 切れ**: メモリから zeroize + 削除。command 型なら再取得、static 型はエラー

### CLI イメージ

```bash
warden kv set DB_PASSWORD --command "op read 'op://vault/item/password'" --soft-ttl 1h --hard-ttl 24h
warden kv set API_TOKEN --command "curl -s https://metadata/token" --soft-ttl 15m --hard-ttl 1h
warden kv set TEMP_CERT --value "$(cat cert.pem)" --soft-ttl 8h
warden kv get DB_PASSWORD   # キャッシュヒット: 数ms
```

### アーキテクチャビジョン

```
warden (コア: セキュア KV + プロセス認証 + TouchID + TTL)
├── SSH agent protocol adapter (既存の proxy/warden_proxy)
├── KV CLI (warden kv get/set/del)
└── KV Unix socket API (将来: 他プロセスからプログラマティックに)
```

## 自前 TouchID

現状 authsock-warden は TouchID を全て 1Password (op) 経由で行っている。KV キャッシュでは authsock-warden 自身が LocalAuthentication.framework (`LAContext.evaluatePolicy`) で TouchID を発行する必要がある。

Rust からは security-framework クレートか objc2 で実装する。SSH 鍵の署名時にも op に頼らず自前 TouchID でゲートできるようになる。

## 既存ツールとの比較

| 機能 | keyctl | op-cache | Vault dev | warden KV |
|---|---|---|---|---|
| TTL | ○ | ○ | ○ (lease) | ○ |
| TTL切れ→TouchID再活性化 | - | - | - | ○ |
| mlock/zeroize | △ | - | △ | ○ |
| プロセスチェーン認可 | △ | - | ○ | ○ |
| macOS対応 | - | ○ | ○ | ○ |
| 1Password統合 | - | ○ | - | ○ |

## 名前

- authsock-warden に統合する場合: authsock-warden のまま（将来 warden にリネームの可能性）
- 別プロジェクトにする場合: cache-warden が候補

## 未決事項

- 統合 vs 別プロジェクトの最終判断
- TouchID 実装方式（security-framework vs objc2）の選定
- KV Unix socket API のプロトコル設計
- static 型で hard TTL 切れ時のユーザー通知方法
