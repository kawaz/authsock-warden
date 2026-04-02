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

# リリースフロー（authsock-filterの just release パターンを踏襲）
# release bump="patch":
#     (TODO: implement)
