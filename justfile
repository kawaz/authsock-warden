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

# push (check + test を通してから push)
push: check test
    jj git push

# ビルドして実行
run *ARGS: build
    ./target/release/authsock-warden {{ARGS}}

# リリース (bump: major, minor, patch)
release bump="patch": check test build
    #!/usr/bin/env bash
    set -euo pipefail

    # Ensure working copy is clean (@ should be empty)
    if ! jj log -r @ --no-graph -T 'if(empty, "", "dirty")' | grep -q '^$'; then
        echo "Error: Working copy has uncommitted changes. Commit or discard first." >&2
        jj status >&2
        exit 1
    fi

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
    claude "CHANGELOG.mdを更新してください。バージョンは v${current} -> v${new_version} です。[Unreleased] セクションの内容を [${new_version}] - $(date +%Y-%m-%d) に変更し、新しい空の [Unreleased] セクションを追加してください。"

    # Verify CHANGELOG was updated
    if ! jj diff --no-pager | grep -q CHANGELOG.md; then
        echo "Error: CHANGELOG.md was not updated. Aborting." >&2
        jj restore Cargo.toml Cargo.lock
        exit 1
    fi

    # Commit and push (GitHub Actions creates tag + release automatically)
    jj describe -m "Release v${new_version}"
    jj new
    jj bookmark set main -r @-
    just push

    # Watch release workflow
    gh run watch
