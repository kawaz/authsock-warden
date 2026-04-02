# DR-011: op 鍵発見の段階的キャッシュ戦略

- **Status**: Active
- **Date**: 2026-04-03

## 背景

op:// ソースの鍵発見（公開鍵一覧 + itemid マッピング）にかかる時間を最小化したい。

| 操作 | 所要時間 | TouchID |
|---|---|---|
| `op item list` | 4-5秒 | 1回（セッション初回） |
| `op item get` (1件) | 4秒 | キャッシュ次第 |
| 1Password agent REQUEST_IDENTITIES | 0.1秒未満 | なし |
| ディスクキャッシュ読み込み | 即座 | なし |

`op item list` は TouchID を引き起こす可能性があり、本プロジェクトの目的（TouchID の頻度を制御する）と矛盾する。不要なタイミングでの op CLI 呼び出しは避けるべき。

## 決定

**4段階のフォールバック戦略 + 1Password agent をリフレッシュソースとして毎回利用。**

### 初回発見（OpState が Uninitialized のとき）

```
1. ディスクキャッシュ読み込み（~/.cache/authsock-warden/op_map.json）
2. op item list → fingerprint-to-itemid マップ（TouchID 1回）
3. キャッシュに fingerprint が一致する公開鍵がある → そのまま使う
4. 1Password agent socket → REQUEST_IDENTITIES → fingerprint 照合で残りを解決
5. まだ残り → op item get を並列実行
6. キャッシュを更新保存
```

### 2回目以降の REQUEST_IDENTITIES（OpState が Ready のとき）

```
1. 1Password agent socket → REQUEST_IDENTITIES（即座、TouchID なし）
2. 既知の鍵 → キャッシュから返す
3. agent に新しい鍵がある（キャッシュにない fingerprint）→ 差分のみ op item get
4. キャッシュ更新
```

**op item list は再実行しない。** agent socket のリフレッシュだけで、Private vault の鍵追加は即座に検出できる。

### op item list の再実行タイミング

- 初回起動時（キャッシュが空）
- 明示的なリロード要求（SIGHUP、将来の `authsock-warden reload` コマンド）
- agent socket に見えない vault の鍵が必要な場合（ユーザーが手動判断）

### agent socket に見えない鍵の扱い

1Password の SSH agent 設定（agent.toml）で特定 vault のみが有効になっている場合、agent socket の REQUEST_IDENTITIES にはその vault の鍵しか返らない。他の vault の鍵は初回の op item list + op item get で発見され、ディスクキャッシュに保存される。以降は鍵の追加・削除がない限りキャッシュで解決できる。

### 1Password agent socket のパス

`op://` 指定時に暗黙的に 1Password agent socket を利用する。パスはプラットフォーム固有:

| OS | パス |
|---|---|
| macOS | `~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock` |
| Linux | `~/.1password/agent.sock` |

socket が存在しない場合（1Password 未インストール等）はステップ 2 をスキップし、op item get フォールバックのみ使用する。

### op 秘密鍵取得時の `--reveal` フラグ

`op item get --fields private_key` で秘密鍵を取得する際、`--reveal` フラグを明示的に付与する。現状 `--reveal` なしでも SSH Key フィールドの秘密鍵は取得できてしまうが、これは 1Password 側で SSHKEY フィールドタイプが CONCEALED と同等のアクセス制御を受けていない可能性があり、将来修正される可能性がある。

## 理由

- **TouchID の不意な発生を防ぐ**: op CLI 呼び出しは TouchID のトリガーになりうる。本プロジェクトの目的は TouchID の頻度を制御することなので、自動的な op CLI 再実行は避ける
- **高速レスポンス**: 2回目以降の REQUEST_IDENTITIES は agent socket + キャッシュで 0.1 秒未満
- **鍵追加の即時反映**: 1Password に鍵を追加すると agent socket に即座に反映される（Private vault の場合）。warden は次の REQUEST_IDENTITIES で検出する
- **ディスクキャッシュの安全性**: 公開鍵と fingerprint のみを保存。秘密情報は含まれない
