# DR-013: Homebrew Cask のみで配布

- **Status**: Active (Updated 2026-04-08)
- **Date**: 2026-04-03
- **Updated**: 2026-04-08

## 背景

authsock-warden は macOS で .app バンドルとして配布する必要がある（[DR-012](DR-012-app-bundle-wrapper.md) 参照）。Homebrew での配布方法を決める必要がある。

### v0.1.12 での失敗

Formula の tarball に `AuthsockWarden.app` ディレクトリのみを含めたところ、Homebrew の tarball stripping により .app の中身が展開先のルートに展開されてしまい、インストールが壊れた。

### v0.1.13〜v0.1.24: Formula + Cask 2本立て

Linux 向けに Formula、macOS 向けに Cask の2本立てで運用した。しかし以下の問題が発生:

- macOS 上で `brew upgrade` 時に `formula requires at least a URL` エラーが毎回表示される
- Formula の `on_linux` ブロック内の URL が macOS 上では解決されず、Formula 全体が invalid と判定される
- DR-013 初版で想定していた「Formula に macOS URL がない → Cask にフォールバック」の挙動は、実際の Homebrew では起きない

## 検討した選択肢

### A. Formula + Cask の2本立て（旧方針）

- **利点**: Linux ユーザーにも Homebrew でインストール手段を提供
- **欠点**: macOS で `formula requires at least a URL` エラーが出る。`on_linux` のみの Formula は Homebrew で正しくフォールバックしない

### B. Cask のみ

- **利点**: macOS での配布が自然。エラーなし。管理が単純
- **欠点**: Linux ユーザーは Homebrew でインストールできない

### C. Formula に macOS URL も追加

- **利点**: エラーが消える
- **欠点**: `brew install` で Formula が優先されて .app なしでインストールされる。Cask の意味がなくなる

## 決定

**B. Cask のみ。**

### 理由

- authsock-warden は実質 macOS 専用（1Password + TouchID 前提）
- Linux 向けの動作試験は未実施で、実用ユーザーもいない
- Linux で必要になれば GitHub Releases からバイナリを直接取得するか、systemd 等で独自に管理できる
- Formula + Cask の同名共存は Homebrew の挙動と噛み合わない問題がある

### Cask (`Casks/authsock-warden.rb`)

- macOS 専用: `app "AuthsockWarden.app"` + `binary` stanza
- `binary` stanza で `/opt/homebrew/bin/authsock-warden` にシンボリックリンクが作成される
- Cask でインストールした .app は `/Applications/AuthsockWarden.app` に配置

### ユーザー体験

```bash
# macOS
brew install --cask kawaz/tap/authsock-warden

# Linux — Homebrew 非対応。GitHub Releases からバイナリを取得
curl -L https://github.com/kawaz/authsock-warden/releases/latest/download/authsock-warden-x86_64-unknown-linux-gnu.tar.gz | tar xz
```

### サービス登録

Cask インストール後、service register は `argv[0]` から解決される symlink パス（`/opt/homebrew/bin/authsock-warden` → `/Applications/AuthsockWarden.app/Contents/MacOS/authsock-warden`）を使用する。symlink の解決先が .app 内のバイナリであることを検出し、LaunchAgent plist に `AssociatedBundleIdentifiers` を含める。

## リスク/トレードオフ

- **Linux ユーザー**: Homebrew でインストールできなくなるが、GitHub Releases からバイナリを直接取得可能
- **Cask の /Applications 配置**: CLI ツールとしては不自然だが、`binary` stanza で CLI パスが通るので使用感は変わらない
