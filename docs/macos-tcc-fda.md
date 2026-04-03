# macOS TCC / FDA 技術知見

authsock-warden の開発で判明した macOS TCC (Transparency, Consent, and Control) の挙動をまとめる。

## TCC の概要

TCC は macOS のプライバシー保護フレームワーク。アプリが保護されたリソース（カメラ、マイク、他アプリのデータ等）にアクセスする際に、ユーザーの許可を求める仕組み。

許可情報は TCC データベースに保存される:

| データベース | パス | スコープ |
|---|---|---|
| ユーザー | `~/Library/Application Support/com.apple.TCC/TCC.db` | ユーザー固有の許可 |
| システム | `/Library/Application Support/com.apple.TCC/TCC.db` | システム全体の許可（FDA 等） |

## Responsible Process

TCC はアクセスを要求した「responsible process」に対して許可を管理する。responsible process の決定方法は起動経路に依存する:

### Terminal.app から実行

```
Terminal.app → shell → authsock-warden → op CLI
                                          ↑ responsible process = Terminal.app
```

Terminal.app の Bundle ID (`com.apple.Terminal`) が responsible process となる。Bundle ID は .app の更新やパス変更に影響されないため、一度許可すれば永続化される。

### LaunchAgent から実行

```
launchd → authsock-warden → op CLI
                             ↑ responsible process = authsock-warden のパス
```

LaunchAgent 経由ではバイナリ自身のパスが responsible process となる。Homebrew のバージョン付きディレクトリ (`/opt/homebrew/Cellar/xxx/0.1.11/bin/authsock-warden`) にインストールされている場合、アップグレードのたびにパスが変わり TCC 許可が失われる。

### .app バンドルから実行

```
launchd → AuthsockWarden.app/Contents/MacOS/authsock-warden → op CLI
                                                                ↑ responsible process = com.github.kawaz.authsock-warden (Bundle ID)
```

.app バンドル内のバイナリとして実行すると、Bundle ID が responsible process となる。パスの変更に影響されない。

### `open` コマンド経由

```bash
open /Applications/AuthsockWarden.app --args internal fda-check
```

`open` コマンドで .app を起動すると、macOS は .app を「アプリケーション」として認識し、responsible process が Bundle ID になる。これは CLI から直接バイナリを実行した場合と異なる挙動。

## TCC カテゴリの違い

### kTCCServiceSystemPolicyAppData（ほかのアプリからのデータへのアクセス権）

- 対象: `~/Library/Group Containers/`, `~/Library/Containers/` 等
- op CLI が 1Password のデータにアクセスする際にトリガーされる
- **LaunchAgent 経由では許可が永続化されない**（ダイアログが毎回表示される）

### kTCCServiceSystemPolicyAllFiles（Full Disk Access / FDA）

- 対象: ファイルシステム全体
- kTCCServiceSystemPolicyAppData を包含する
- **System Settings で ON にすれば永続的に有効**
- ダイアログではなく、System Settings での明示的な操作が必要

### 包含関係

```
FDA (kTCCServiceSystemPolicyAllFiles)
 └── AppData (kTCCServiceSystemPolicyAppData)
 └── その他の保護カテゴリ（一部）
```

FDA を ON にすれば、AppData の個別許可は不要。

## FDA のチェック方法

### TCC データベースの読み取り試行

```rust
let tcc_db = Path::new("/Library/Application Support/com.apple.TCC/TCC.db");
let has_fda = std::fs::metadata(tcc_db).is_ok();
```

システムの TCC データベース自体の読み取りに FDA が必要であるため、metadata の取得成否で FDA の状態を判定できる。

| 結果 | 意味 |
|---|---|
| 成功 | FDA が ON |
| 失敗 | FDA が OFF、または FDA リストに未登録 |

FDA の OFF と未登録は区別できない。TCC DB の読み取り自体に FDA が必要なため。

### .app コンテキストでのチェック

FDA の許可はアプリ（responsible process）に対して付与される。正しいアプリの FDA 状態をチェックするには、そのアプリとして起動する必要がある:

```bash
# CLI から直接実行 → Terminal.app の FDA 状態を見てしまう
authsock-warden internal fda-check

# .app として起動 → AuthsockWarden.app の FDA 状態を見る
open --wait-apps /Applications/AuthsockWarden.app --args internal fda-check --raw
```

## .app バンドルと Bundle ID

### Info.plist の設定

```xml
<key>CFBundleIdentifier</key>
<string>com.github.kawaz.authsock-warden</string>

<key>LSBackgroundOnly</key>
<true/>
```

`LSBackgroundOnly` を `true` にすると、Dock にアイコンが表示されず、GUI ウィンドウも作成されない。バックグラウンドサービスとして動作する。

### LaunchAgent plist との連携

```xml
<key>AssociatedBundleIdentifiers</key>
<array>
    <string>com.github.kawaz.authsock-warden</string>
</array>
```

LaunchAgent plist に `AssociatedBundleIdentifiers` を記載することで、launchd がプロセスを .app の Bundle ID と関連付ける。

## FDA リストへの自動追加

.app を `open` コマンドで起動すると、macOS は自動的にその .app を FDA リスト（System Settings > Privacy & Security > Full Disk Access）に追加する。

- ユーザーは「+」ボタンでアプリを手動追加する必要がない
- リストに追加された時点では OFF 状態。ユーザーがトグルを ON にする必要がある
- service register 時の `check_fda_via_app()` 呼び出しがこの自動追加を兼ねる

## LSBackgroundOnly アプリの `open --wait-apps` 時の挙動

`LSBackgroundOnly = true` の .app を `open --wait-apps` で起動すると:

1. `open` が .app を起動する
2. .app はメインの処理（fda-check 等）を実行して終了する
3. `open` は .app の終了を待つ
4. stderr に以下のようなノイズが出力される:

```
Unable to find a bundle for com.github.kawaz.authsock-warden to block on.
```

このメッセージは `LSBackgroundOnly` アプリが GUI イベントループ（NSApplication）を持たないことに起因する。`open --wait-apps` はアプリの GUI 終了を監視する仕組みだが、LSBackgroundOnly アプリはプロセスの終了で完了する。動作自体は正常。

**対処**: stderr を `/dev/null` にリダイレクトして抑制する。

## コード署名との関係

- TCC の Bundle ID ベース識別は codesign の有無に関わらず動作する
- ただし Notarization（公証）には codesign が必須
- codesign はボトムアップで行う（バイナリ → .app）。`--deep` は使わない
