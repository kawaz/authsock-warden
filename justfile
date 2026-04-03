# authsock-warden

# デフォルト: レシピ一覧
default:
    @just --list

# ビルド (release)
build:
    cargo build --release

# テスト
test:
    cargo test

# lint + format チェック
check:
    cargo fmt --check
    cargo clippy -- -D warnings

# format 適用
fmt:
    cargo fmt

# ワーキングコピーがクリーン（empty）であることを確認
ensure-clean:
    test "$(jj log -r @ --no-graph -T 'empty')" = "true"

# push (check + test を通してから push)
push: check test
    jj git push

# ビルドして実行
run *ARGS: build
    ./target/release/authsock-warden {{ARGS}}

# リリース (bump: major, minor, patch)
release bump="patch": ensure-clean check test build
    #!/usr/bin/env bash
    set -euo pipefail

    # Version bump
    current=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
    IFS='.' read -r major minor patchv <<< "$current"
    case "{{bump}}" in
        major) major=$((major + 1)); minor=0; patchv=0 ;;
        minor) minor=$((minor + 1)); patchv=0 ;;
        patch) patchv=$((patchv + 1)) ;;
        *) echo "Error: Invalid bump type '{{bump}}'" >&2; exit 1 ;;
    esac
    new_version="${major}.${minor}.${patchv}"
    sed -i '' "s/^version = \"${current}\"/version = \"${new_version}\"/" Cargo.toml
    cargo check --quiet
    echo "Version: ${current} -> ${new_version}"

    # CHANGELOG.md update via Claude
    claude -p "CHANGELOG.mdを更新してください。バージョンは v${current} -> v${new_version} です。[Unreleased] セクションの内容を [${new_version}] - $(date +%Y-%m-%d) に変更し、新しい空の [Unreleased] セクションを追加してください。"

    # Commit and push (GitHub Actions creates tag + release automatically)
    jj describe -m "Release v${new_version}"
    jj new
    jj bookmark set main -r @-
    just push

    # Watch release workflow
    gh run watch
