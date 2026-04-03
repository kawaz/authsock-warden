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

### Homebrew 配布

Homebrew での配布戦略は [DR-013](DR-013-homebrew-formula-cask.md) を参照。

## リスク/トレードオフ

- **.app バンドルは macOS のみ**: Linux には影響なし
- **macOS は .app が必須**: authsock-warden は LaunchAgent 常駐が主要ユースケース。LaunchAgent 経由では TCC 問題が必ず発生するため、macOS ユーザー全員に .app バンドルが必要
- **brew upgrade 後のサービス reload**: upgrade 後にサービスの再起動が必要。これは .app 導入前から同様

## 関連

- [DR-013](DR-013-homebrew-formula-cask.md) — Homebrew Formula + Cask の2本立て配布
- [DR-014](DR-014-macos-fda-tcc.md) — macOS FDA (Full Disk Access) による TCC 問題の解決
