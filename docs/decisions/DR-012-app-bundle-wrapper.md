# DR-012: .app バンドルラッパーによる TCC 許可の永続化

- **Status**: Active
- **Date**: 2026-04-03

## 背景

LaunchAgent から起動した authsock-warden が op CLI を呼ぶと、macOS の TCC (Transparency, Consent, and Control) ダイアログが毎回表示される。

原因は TCC の "responsible process" の判定方式にある:

- **Terminal.app から実行**: Terminal の Bundle ID (`com.apple.Terminal`) が responsible process となり、一度許可すれば永続化される
- **LaunchAgent から実行**: バイナリ自身のパスが responsible process となり、パスベースで識別される
- **brew upgrade 時**: Homebrew がバージョン付きディレクトリにインストールするため、アップグレードのたびにパスが変わり TCC 許可が失われる

codesign 済みであっても、LaunchAgent 経由の実行ではパスベースの識別から逃れられない。

## 検討した選択肢

### A. Full Disk Access を手動付与

- **利点**: 確実に動作する
- **欠点**: ユーザー体験が悪い（システム環境設定で手動操作が必要）。過剰な権限を付与することになり、最小権限の原則に反する

### B. symlink で ~/Library/Group Containers/ へのアクセスを回避

- **利点**: 追加の構造変更が不要
- **欠点**: macOS が symlink を解決してしまい、TCC のチェック対象は実体パスのままになる。v0.1.11 で試みたが根本解決にならなかった

### C. .app バンドルラッパー

- **利点**: Bundle ID ベースの TCC 許可となり、パスが変わっても永続化される。macOS ネイティブの仕組みに沿った解決策
- **欠点**: macOS 固有の構造が必要。.app の中身を知らない人にはバイナリの場所がわかりにくい

## 決定

**方法 C: .app バンドルラッパーを採用。**

## 設計

### .app バンドル構造

```
AuthsockWarden.app/
  Contents/
    Info.plist
    MacOS/
      authsock-warden    # 実行バイナリ
```

### Info.plist の主要設定

- `CFBundleIdentifier`: `com.github.kawaz.authsock-warden`
- `LSBackgroundOnly`: `true` (GUI なし、Dock に表示しない)

### LaunchAgent plist

`AssociatedBundleIdentifiers` キーを追加し、TCC が .app の Bundle ID で許可を管理するようにする。

### コード署名

ボトムアップで署名する (バイナリ → .app)。`--deep` は使わない。`--deep` はネストされたバンドルの署名順序を保証しないため、Apple は推奨していない。

### Notarization

```
ditto で zip → notarytool submit → stapler staple
```

### Homebrew Formula

- **macOS**: `prefix.install "AuthsockWarden.app"` + `bin` ディレクトリへ symlink
- **Linux**: 変更なし (.app バンドルは macOS 専用)

### サービス登録

既存の `argv[0]` ベースのパス解決で安定 symlink (`/opt/homebrew/bin/authsock-warden`) を使用する。Homebrew が管理する symlink は upgrade 後も同じパスを維持するため、LaunchAgent plist の `ProgramArguments` を書き換える必要がない。

## リスク/トレードオフ

- **.app バンドルは macOS のみ**: Linux には影響なし。プラットフォーム固有のビルド成果物が増えるが、CI で分岐すれば管理可能
- **Homebrew の ad-hoc 再署名**: Cask は再署名するが、Formula (ソースビルド) では再署名されない。本プロジェクトは Formula で配布するため問題なし
- **brew upgrade 後のサービス reload**: upgrade 後にサービスの再起動が必要。これは .app 導入前から同様であり、新たなデメリットではない
- **バイナリの場所がわかりにくい**: .app 内部にバイナリがあるため直感的でないが、`bin` に symlink があるので CLI としての使用感は変わらない
