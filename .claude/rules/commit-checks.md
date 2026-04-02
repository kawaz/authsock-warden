# コミット・プッシュ前チェック

コミットやプッシュの前に以下を実行:

```bash
just check
```

（cargo fmt --check + cargo clippy -- -D warnings + cargo test）
