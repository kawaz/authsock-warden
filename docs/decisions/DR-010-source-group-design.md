# DR-010: source グループ設計

- **Status**: Active
- **Date**: 2026-04-02
- **Supersedes**: [DR-005](DR-005-key-source-abstraction.md)

## 背景

DR-005 では source を type 別に個別定義し、ソケット側で `sources = ["name1", "name2"]` と複数参照する設計だった。しかし議論で以下の課題が出た:

1. 同じ用途（例: 仕事用）の鍵が agent と file に分散している場合、2つの source を定義して名前で紐付ける手間がある
2. CLI での `--upstream` 相当の指定方法と設定ファイルの構造が乖離する
3. authsock-filter の `--upstream` がグループの開始を意味する設計は直感的

## 検討した選択肢

### A. 現行設計（type タグ付き enum、ソケットから複数参照）

```toml
[[sources]]
type = "agent"
name = "work-agent"
socket = "..."

[[sources]]
type = "file"
name = "work-files"
paths = ["~/.ssh/id_work"]

[sockets.work]
sources = ["work-agent", "work-files"]
```

- **利点**: serde の tagged enum で実装が単純
- **欠点**: 同一用途の鍵を束ねるのに複数エントリ + ソケット側の列挙が必要

### B. source = グループ（members で複数の鍵ソースを束ねる）

```toml
[[sources]]
name = "work"
members = ["op:////", "~/Library/.../agent.sock", "~/.ssh/id_work"]

[sockets.work]
source = "work"
```

- **利点**: 1つの名前で複数種類の鍵を束ねられる。CLI のグループ方式と自然に対応
- **欠点**: member の文字列パースが必要（type:path 記法）

### C. source に構造化フィールドを並列定義

```toml
[[sources]]
name = "work"
agents = ["~/Library/.../agent.sock"]
files = ["~/.ssh/id_work"]
op = true
```

- **利点**: 各フィールドが型安全
- **欠点**: フィールドが増えるたびに構造体が膨張

## 決定

**B. source = グループ。members で複数の鍵ソースを束ねる。**

### member の記法

| 記法 | 意味 | 例 |
|---|---|---|
| `op:////` | 全 vault の全 SSH 鍵（op CLI で管理、warden がローカル署名） | `op:////` |
| `op:////VAULT` | 指定 vault の SSH 鍵のみ | `op:////emerada` |
| `op:////VAULT/ITEM` | 特定の鍵のみ | `op:////Private/kawaz-mbp-key` |
| `agent:PATH` | SSH agent ソケットに転送（明示指定） | `agent:~/.ssh/agent.sock` |
| `file:PATH` | 秘密鍵ファイルから読み込み（明示指定） | `file:~/.ssh/id_work` |
| `PATH`（プレフィックスなし） | パスの種類で自動判定: socket → agent、通常ファイル → file | `~/.ssh/id_work` |

`op:////` 記法は 1Password 公式の secret reference 形式（`op:////vault/item/field`）と一致しており、op CLI ユーザーに馴染みがある。

自動判定により、ほとんどの場合 type プレフィックスは不要。

#### 自動判定の安全性

自動判定は agent と file で署名主体・メモリ管理が根本的に異なるため、パスの実体変化で意図しないモード切替が起きるリスクがある。以下の緩和策を適用する:

- **判定は起動時の1回のみ**。実行中のファイル種別変化には追従しない
- **判定結果を起動時ログに明示出力**（`INFO source "work": /path/to/sock detected as agent`）
- **判定に失敗（パスが存在しない等）した場合はエラーで起動を拒否**（fail-closed）
- 設定ファイルでは明示プレフィックス推奨。自動判定は CLI のカジュアル利用向け

### ソケットからの参照

```toml
[sockets.work]
source = "work"    # 単一グループ参照
```

`sources = [...]`（複数参照）ではなく `source = "..."`（単一参照）。複数種類の鍵を使いたければ source の members にまとめる。

### CLI 対応

```bash
# --source がグループを開始、以降の --socket はそのグループに属する
authsock-warden run \
  --source op://,~/Library/.../agent.sock \
  --socket /tmp/work.sock comment=*@work* \
  --socket /tmp/all.sock

# 名前付き
authsock-warden run \
  --source work=op://,~/Library/.../agent.sock \
  --socket /tmp/work.sock comment=*@work*

# --source 省略時は $SSH_AUTH_SOCK を暗黙の agent ソースとして使用
authsock-warden run --socket /tmp/warden.sock
```

### 同一公開鍵が複数 member から見える場合

members の順序で先勝ち。例えば `["op://", "agent:..."]` なら op で管理対象に設定された鍵は op が優先、それ以外は agent 経由。

### 動作モードの違い

同じ1Passwordの鍵でも member の指定方法で動作が変わる:

| member | 署名 | メモリ管理 | TouchID |
|---|---|---|---|
| `op://` | warden がローカル署名 | 4状態ライフサイクル | 鍵取得時のみ |
| `agent:~/.../1password/agent.sock` | 1Password が署名 | 持たない（proxy） | 1Password の設定に従う |

ユーザーがどちらのモードを使うか選べる。

## 理由

- 「仕事用の鍵セット」を1つの名前で表現でき、設定の意図が明確
- CLI の `--source MEMBER,MEMBER` グループ方式と設定ファイルの `members = [...]` が自然に対応
- authsock-filter の `--upstream` グループ方式を踏襲・拡張しており移行が容易
- member の自動判定により、カジュアルな利用時はパスを並べるだけで動く
