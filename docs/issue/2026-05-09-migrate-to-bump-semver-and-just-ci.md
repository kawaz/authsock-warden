# `justfile::release` の sed 部分を `bump-semver` に移行 + `ci` レシピ + `just ci` 1 行 CI

## 背景

2026-05-09 に `kawaz/bump-semver` v0.2.0 がリリース済 (`brew install kawaz/tap/bump-semver`)。`Cargo.toml` / `*.json` / `VERSION` を basename で自動判定する flat 4-action CLI。

authsock-warden は Rust + Cargo.toml の典型的なリリースパターンを持っており、bump-semver の Cargo.toml handler が直接適用できる。

## やること

### 1. ローカル PATH に `bump-semver` を入れる前提条件

`kawaz/dotfiles/darwin/default.nix` の `homebrew.brews` に `"kawaz/tap/bump-semver"` を追加 (別 issue: `kawaz/dotfiles/docs/issue/2026-05-09-add-bump-semver-to-homebrew-brews.md`)。

### 2. `release` (もしくは `bump-version`) レシピの sed 部分を `bump-semver` に置換

現状の Cargo.toml 書き換え (推測; 実コードは確認):

```bash
current=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
IFS='.' read -r major minor patchv <<< "$current"
case "{{bump}}" in
    major) ... ;;
    minor) ... ;;
    patch) ... ;;
esac
new_version="${major}.${minor}.${patchv}"
sed -i '' "s/^version = \"${current}\"/version = \"${new_version}\"/" Cargo.toml
```

移行後:

```bash
new_version=$(bump-semver "{{level}}" Cargo.toml --write)
```

20+ 行 → 1 行。BSD/GNU sed 互換問題も bump-semver 内に閉じ込められる。

### 3. レシピ名統一

レシピ名 `release` または `bump-version` を `bump-semver` に揃える (kawaz リポ全体で統一)。引数名は `level="patch"`。

### 4. `ci` レシピ + `.github/workflows/ci.yml` の `just ci` 1 行化 (もし未対応なら)

```just
ci: check test build
```

```yaml
jobs:
  ci:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - uses: Swatinem/rust-cache@v2
      - uses: extractions/setup-just@v3
      - run: just ci
```

### 5. macOS 署名 / notarize / Cask Formula 切替 (DR-013) は影響なし

authsock-warden 固有の release.yml ロジック (.app バンドル + 署名 + notarize + staple、Cask 切替) は **触らない**。version 文字列の bump 処理だけが今回の対象。

## 想定される作業順序

1. dotfiles の brew install 追加が完了していることを確認
2. `which bump-semver` で確認
3. justfile の sed 部分を `bump-semver` に置換 + レシピ名 `bump-semver` に改名
4. CI workflow を `just ci` 1 行に集約 (該当する場合)
5. push → CI 緑確認 (release ジョブは Cargo.toml 変化検知で自動だが、テスト用 release は要確認)

## 関連

- bump-semver: https://github.com/kawaz/bump-semver (v0.2.0)
- 先行適用例: `kawaz/jj-worktree/main/justfile` (commit `ba9add89` 以降)
- ルール: `~/.claude/rules/docs-structure.md` の「バージョン bump レシピ」節

報告者: kawaz/jj-worktree main の親 CC (session_id: `718c6cc3-b154-4de5-9cbe-cccd6dcfa407`) — 2026-05-09
