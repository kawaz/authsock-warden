# DR-013: Homebrew Formula + Cask の2本立て配布

- **Status**: Active
- **Date**: 2026-04-03

## 背景

authsock-warden は macOS で .app バンドルとして配布する必要がある（[DR-012](DR-012-app-bundle-wrapper.md) 参照）。Homebrew での配布方法を決める必要がある。

当初は Formula 内で .app バンドルを含む tarball を配布する方式を試みたが、v0.1.12 で失敗した。

### v0.1.12 での失敗

Formula の tarball に `AuthsockWarden.app` ディレクトリのみを含めたところ、Homebrew の tarball stripping（トップレベルディレクトリが1つの場合に自動で strip する仕様）により、.app の中身が展開先のルートに cd されてしまい、インストールが壊れた。

回避策として tarball にベアバイナリも同梱し stripping を防いだが、Formula で .app を扱うこと自体が Homebrew の慣習から外れていた。

## 検討した選択肢

### A. Formula のみ（.app を含む tarball）

- **利点**: 1つの配布形式で完結
- **欠点**: tarball stripping 問題。Formula で .app を扱うのは非標準的。macOS/Linux で tarball の中身が異なり Formula が複雑化

### B. Formula + Cask の2本立て

- **利点**: Homebrew の慣習に沿った配布。Formula はベアバイナリ、Cask は .app バンドルと責務が明確に分離。`brew install` で macOS/Linux 自動切り替え
- **欠点**: 2つの配布定義を管理する必要がある

### C. Cask のみ（macOS 専用）

- **利点**: macOS は Cask が自然
- **欠点**: Linux ユーザーが Homebrew でインストールできない

## 決定

**B. Formula + Cask の2本立て。**

### Formula (`Formula/authsock-warden.rb`)

- Linux 専用: `bin.install "authsock-warden"`
- macOS URL は定義しない
- macOS で `brew install kawaz/tap/authsock-warden` した場合、Homebrew は同名の Cask にフォールバックする

### Cask (`Casks/authsock-warden.rb`)

- macOS 専用: `app "AuthsockWarden.app"` + `binary` stanza
- `binary` stanza で `/opt/homebrew/bin/authsock-warden` にシンボリックリンクが作成される
- Cask でインストールした .app は `/Applications/AuthsockWarden.app` に配置

### ユーザー体験

```bash
# macOS → Cask が使われる（Formula に macOS URL がないためフォールバック）
brew install kawaz/tap/authsock-warden

# Linux → Formula が使われる
brew install kawaz/tap/authsock-warden

# 明示的に Cask を指定（macOS）
brew install --cask kawaz/tap/authsock-warden
```

macOS/Linux ともに同じコマンドでインストール可能。

### サービス登録

Cask インストール後、service register は `argv[0]` から解決される symlink パス（`/opt/homebrew/bin/authsock-warden` → `/Applications/AuthsockWarden.app/Contents/MacOS/authsock-warden`）を使用する。symlink の解決先が .app 内のバイナリであることを検出し、LaunchAgent plist に `AssociatedBundleIdentifiers` を含める。

## 理由

- **Homebrew の慣習**: .app バンドルの配布は Cask が標準。Formula で .app を扱うのは非標準的で、tarball stripping など予期しない問題が発生する
- **責務の分離**: Formula は全プラットフォーム共通のベアバイナリ、Cask は macOS 固有の .app バンドル
- **フォールバック動作**: Formula に macOS URL がない場合、Homebrew は同名の Cask に自動フォールバックする。これにより `brew install` コマンドを統一できる

## リスク/トレードオフ

- **Cask の /Applications 配置**: CLI ツールとしては不自然だが、`binary` stanza で CLI パスが通るので使用感は変わらない
- **2つの配布定義の管理**: CI（release.yml）で Formula と Cask を同時に更新するため、管理コストは低い
