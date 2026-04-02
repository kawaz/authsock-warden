# 1Password SSH 連携機能の調査

- **Date**: 2026-04-02
- **Sources**: https://developer.1password.com/docs/ssh/ 配下のドキュメント一式

## 目的

authsock-warden の設計にあたり、1Password SSH 連携機能の最新状況を把握し、機能の重複・責務の違い・wardenが補完すべき領域を明確にする。

## 1Password SSH 機能の全体像

### 基本機能
- SSH鍵の生成（Ed25519推奨、RSA 2048/3072/4096 対応）
- 既存鍵のインポート（ファイル選択 or ドラッグ&ドロップ、パスフレーズ付き鍵も対応）
- 公開鍵・フィンガープリントの自動生成、コピー・ダウンロード
- エンドツーエンド暗号化で秘密鍵を保管

### SSH Agent
- Unix domain socket 経由の SSH agent protocol サーバ
- macOS: `~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock`
- Linux/Windows: 各プラットフォーム固有のパス
- デフォルトで Personal, Private, Employee vault の適格鍵が利用可能

### 認証方式
- Touch ID (macOS)
- Apple Watch (macOS)
- Windows Hello (Windows)
- システム認証 (Linux)
- 1Password アカウントパスワード
- SSO 利用時は IdP へのリダイレクト

### agent.toml 設定ファイル
- パス: `~/.config/1Password/ssh/agent.toml`（XDG_CONFIG_HOME 対応）
- TOML 形式、UTF-8
- `[[ssh-keys]]` セクションで鍵を指定:
  ```toml
  [[ssh-keys]]
  item = "鍵の名前"
  vault = "ボルト名"
  account = "アカウント名"
  ```
- 複数 `[[ssh-keys]]` の順序が提示順序を決定
- **鍵ごとのタイムアウト設定は不可**（アプリ全体の設定のみ）
- **プロセス別のアクセス制御設定は agent.toml にはない**

### SSH Bookmarks（ベータ）
- 1Password アプリから直接 SSH ホストに接続
- SSH 活動ログから自動作成、または SSH Key item に手動で `ssh://` URL を追加
- `~/.ssh/1Password/config` を自動生成して `~/.ssh/config` に Include
- ホストと鍵のマッピングを自動管理

### Git 署名統合
- 1Password アプリから Git commit 署名を自動設定
- SSH 鍵による Git コミット署名

### エージェント転送
- `ssh -A` または `~/.ssh/config` の `ForwardAgent yes` で利用
- リモートからの SSH 要求がローカルの 1Password agent に転送される
- 1Password agent は各鍵の使用前に承認を要求（標準 ssh-agent より安全）
- **注意**: 一度認可されると、同リモート環境内の同 OS ユーザーの新接続は全て認可される

### クライアント互換性
- OpenSSH, Git CLI, JetBrains IDEs, GitHub Desktop, VS Code 等 30+ ツール対応
- 非互換: Termius, Xcode, Postico, Sequel Ace（ビルトイン鍵管理使用）

## セキュリティ機能

| 機能 | 詳細 |
|---|---|
| 秘密鍵の保管 | 1Password 内に保持、外部に流出しない |
| メモリ管理 | ロック時は秘密鍵をメモリから削除、承認情報のみ保持 |
| 公開鍵の保存 | ディスクに暗号化なしで保存（公開情報のため） |
| プロセス制御 | どのプロセスがどの秘密鍵を使用できるか制御可能 |
| バックグラウンド要求抑制 | フォアグラウンドにないアプリからの要求を検出・抑制 |
| 認可モデル | 各署名リクエストに対して明示的な認可が必要 |

## authsock-warden との比較分析

### 1Password が提供する機能（warden と重複）

| 機能 | 1Password | warden |
|---|---|---|
| SSH agent protocol | 提供 | 提供（プロキシ or 自前署名） |
| 署名時の認証 | TouchID/パスワード | re-auth command（外部委譲） |
| 鍵の可視性制御 | agent.toml で vault/item 単位 | filter で comment/fingerprint/keytype 等 |
| プロセス制御 | 「どのプロセスが使えるか制御可能」 | allowed_processes（PID + プロセスツリー） |
| バックグラウンド抑制 | フォアグラウンド判定 | なし（別アプローチ） |

### 1Password に**ない**機能（warden の差別化ポイント）

| 機能 | 説明 |
|---|---|
| **鍵ごとのタイムアウト** | 1Password はアプリ全体の設定のみ。warden は鍵ごとに timeout/forget_after を設定可能 |
| **on_timeout = "lock"** | 鍵をメモリに保持しつつ署名をロック。1Password はロック時に鍵をメモリから削除 |
| **リモート re-auth** | TouchID 不要な代替認証（Passkey等）。1Password は TouchID/Windows Hello 必須 |
| **refresh** | タイマーの手動リフレッシュ。1Password には該当機能なし |
| **複数ソース集約** | 1Password + ファイル + 他の agent を統合。1Password は自身の鍵のみ |
| **ソケット単位のフィルタ** | 用途別ソケットで異なる鍵セット。1Password は単一ソケット |
| **アイドル検知** | 外部スクリプトによるカスタムアイドル判定。1Password にはなし |
| **comment/regex フィルタ** | 柔軟なフィルタ構文。1Password は vault/item 名指定のみ |
| **GitHub ユーザー鍵フィルタ** | GitHub API から自動取得してフィルタ |
| **3層ポリシー** | key(天井) ∩ socket(制限) の交差ポリシー |

### warden に**ない**機能（1Password 固有）

| 機能 | 説明 |
|---|---|
| 鍵の生成 | warden は鍵ストアではない。1Password で生成 |
| 鍵のインポート | 同上 |
| Apple Watch 認証 | warden の re-auth command で代替可能だが、ビルトインではない |
| SSH Bookmarks | ホスト→鍵のマッピング + ワンクリック接続。warden のスコープ外 |
| ブラウザ公開鍵自動入力 | warden のスコープ外 |
| バックグラウンド要求抑制 | 1Password 固有のフォアグラウンド判定。warden は別アプローチ（プロセスツリー） |
| Git 署名自動設定 | 1Password アプリの GUI 機能 |
| エージェント転送の承認 | 1Password agent は転送先でも承認を要求 |

## 設計への示唆

### 1. プロセス制御について
1Password も「どのプロセスがどの秘密鍵を使用できるか制御可能」と記載しているが、agent.toml にはプロセス別設定がない。おそらく GUI の認可ダイアログで「このアプリを信頼」的な操作で制御している。warden の `allowed_processes`（PID ベース + プロセスツリー遡上）はより明示的で自動化しやすい。

### 2. タイムアウトについて
1Password のタイムアウトはアプリ全体で1つの値（ユーザーが12時間と設定している）。鍵ごとの個別タイムアウトは **1Password には存在しない**。これは warden の最大の差別化ポイント。

### 3. ロック時のメモリ管理
1Password は「ロック時に秘密鍵をメモリから削除」するため、ロック後の署名には必ず TouchID が必要。warden の `on_timeout = "lock"` はメモリに保持しつつ署名をロックし、re-auth command（Passkey等）で解除できる。**リモート操作時に TouchID 不要** というユースケースは 1Password 単体では実現不可能。

### 4. 複数ソース集約
1Password agent は自身の vault の鍵のみを扱う。ファイルベースの鍵や他の agent（YubiKey agent 等）との統合は不可。warden の `type = "agent"` / `"op"` / `"file"` による複数ソース集約は固有の価値。

### 5. Bookmarks 機能との関係
SSH Bookmarks はホスト→鍵のマッピングを 1Password 側で管理する機能。warden のフィルタ機能と部分的に重複するが、Bookmarks はホスト起点（「このホストにはこの鍵」）、warden のフィルタはソケット起点（「このソケットにはこれらの鍵」）で粒度が異なる。共存可能。

### 6. エージェント転送のセキュリティ
1Password agent は転送先でも署名前に承認を要求するため、標準 ssh-agent よりセキュア。warden を agent 転送先で使う場合は、warden が 1Password agent の承認機能を活かしつつ、追加のポリシー制御を提供する形になる。

## 結論

authsock-warden は 1Password SSH agent の **補完ツール** として明確に差別化できる:

1. **鍵ごとのタイムアウト管理** — 1Password にない
2. **リモート re-auth** — TouchID 不要の代替認証
3. **複数鍵ソースの統合** — 1Password + ファイル + 他 agent
4. **ソケット単位の柔軟なフィルタ** — 用途別に異なるポリシー
5. **プログラマブルなポリシー** — プロセスツリー判定、外部スクリプトによるアイドル検知

1Password が既に強力な SSH 管理を提供しているため、warden は「1Password を**より細かく制御する**ための上位レイヤー」として位置づけるのが適切。
