default: fmt lint build test

fmt:
    cargo fmt

fmt-check:
    cargo fmt --check

lint:
    cargo clippy -- -D warnings

build:
    cargo build

build-release:
    cargo build --release

test:
    cargo test

check: fmt-check lint test

run *args:
    cargo run -- {{args}}

# Finalize a release: describe current change, new, bookmark, tag, push
# Use after version bump and CHANGELOG update are in the working copy
finalize-release version:
    #!/usr/bin/env bash
    set -euo pipefail
    jj describe -m "Release v{{version}}"
    jj new
    jj bookmark set main -r @-
    jj tag set "v{{version}}" -r @-
    jj git push --bookmark main
    just push-tag "v{{version}}"
    gh run watch

# Push a git tag (jj doesn't support tag push natively)
push-tag tag:
    #!/usr/bin/env bash
    set -euo pipefail
    jj git export
    GIT_WORK_TREE="$(pwd)" git --git-dir="$(jj root)/../.git" push origin "{{tag}}"

release bump="patch":
    #!/usr/bin/env bash
    set -euo pipefail

    # 0. Ensure clean workspace
    if [[ -n "$(jj status --no-pager 2>/dev/null | grep -v 'Working copy' | grep -v 'Parent commit' | grep -c '^[AMD]')" ]] && [[ "$(jj status --no-pager 2>/dev/null | grep -v 'Working copy' | grep -v 'Parent commit' | grep -c '^[AMD]')" -gt 0 ]]; then
        echo "Error: Working tree has uncommitted changes" >&2
        jj status >&2
        exit 1
    fi

    # Pre-checks
    cargo fmt --check || { echo "Error: Run 'cargo fmt' first." >&2; exit 1; }
    cargo clippy -- -D warnings
    cargo build --release
    cargo test

    # 1. Version bump in Cargo.toml
    current=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
    IFS='.' read -r major minor patchv <<< "$current"
    case "{{bump}}" in
        major) major=$((major + 1)); minor=0; patchv=0 ;;
        minor) minor=$((minor + 1)); patchv=0 ;;
        patch) patchv=$((patchv + 1)) ;;
        *) echo "Error: Invalid bump type '{{bump}}' (expected: major, minor, patch)" >&2; exit 1 ;;
    esac
    new_version="${major}.${minor}.${patchv}"
    sed -i '' "s/^version = \"${current}\"/version = \"${new_version}\"/" Cargo.toml
    cargo check --quiet  # Update Cargo.lock
    echo "Version: ${current} -> ${new_version}"

    # 2. CHANGELOG.md update via Claude
    claude "CHANGELOG.mdを更新してください。バージョンは v${current} -> v${new_version} です。[Unreleased] セクションの内容を [${new_version}] - $(date +%Y-%m-%d) に変更し、新しい空の [Unreleased] セクションを追加してください。"

    # Verify CHANGELOG was updated
    if ! jj diff --no-pager | grep -q CHANGELOG.md; then
        echo "Error: CHANGELOG.md was not updated. Aborting." >&2
        jj restore Cargo.toml Cargo.lock
        exit 1
    fi

    # 3. Finalize: describe, new, bookmark, tag, push, watch
    just finalize-release "${new_version}"
