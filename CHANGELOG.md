# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.15] - 2026-04-03

### Changed

- **Breaking (macOS Homebrew)**: macOS での Homebrew 配布を Cask のみに統一。
  - `brew install kawaz/tap/authsock-warden`（Formula）は macOS 非サポートとなり、実行すると Cask への移行を案内するメッセージを表示。
  - macOS ユーザーは `brew install --cask kawaz/tap/authsock-warden` を使用すること。
  - Linux では引き続き Formula でインストール可能。

## [0.1.14] - 2026-04-03

### Changed

- **Breaking (macOS Homebrew)**: Homebrew 配布を Formula + Cask の2本立てに変更。
  - `brew install kawaz/tap/authsock-warden` — ベアバイナリのみ（全プラットフォーム共通）
  - `brew install --cask kawaz/tap/authsock-warden` — .app バンドル（macOS 専用、TCC パーミッション永続化）
  - 従来 `brew install` で .app バンドルが入っていた macOS ユーザーは、TCC 永続化が必要な場合 `brew install --cask` への移行が必要。

## [0.1.13] - 2026-04-03

### Fixed

- macOS tarball に bare binary を同梱し、Homebrew でのインストール失敗を修正。Homebrew はトップレベルが単一ディレクトリの tarball を自動ストリップするため、`.app` バンドルのみだと Formula がバイナリを検出できなかった。

## [0.1.12] - 2026-04-03

### Added

- macOS バイナリを .app バンドルとしてパッケージング。TCC パーミッション（Accessibility 等）がアプリ単位で永続化され、アップデート後の再許可が不要に。

### Security

- 秘密鍵の PEM 文字列および Ed25519 シードのメモリゼロ化を強化
- ソケットバインド時に制限的な umask を設定し、TOCTOU 競合条件を防止
- プロトコルエンコーディングの整数キャストを安全な `try_from` に置換

### Fixed

- `service` および `config` サブコマンドのヘルプ説明文が欠落していた問題を修正

## [0.1.11] - 2026-04-03

### Changed

- 1Password agent socket の接続方法を変更: `~/.ssh/agent-1password.sock` の手動シンボリックリンク作成が不要に。warden が `~/.local/state/authsock-warden/agent-1password.sock` にシンボリックリンクを自動作成し、そこ経由で接続する。macOS の TCC プライバシーダイアログを自動的に回避できる。

## [0.1.10] - 2026-04-03

### Fixed

- 1Password agent socket の検索で `~/.ssh/agent-1password.sock` を優先するよう変更。macOS の TCC プライバシーダイアログ（`~/Library/Group Containers/` アクセス時）を回避できる。ユーザーは以下のシンボリックリンクを作成推奨:
  ```
  ln -s ~/Library/Group\ Containers/2BUA8C4S2C.com.1password/t/agent.sock ~/.ssh/agent-1password.sock
  ```

## [0.1.9] - 2026-04-03

### Added

- Apple codesign + Hardened Runtime + Notarization for macOS binaries
- Auto-tag release via GitHub Actions (no manual tag push needed)
- just push recipe with quality gate (check + test before push)
- pre-push-check hook blocks direct push, forces just push
- ensure-clean check before release
- musl build targets (x86_64 + aarch64)
- op_account config field for multi-account 1Password

### Fixed

- Logs to stderr (fixes run --print-config piping)
- Security protections only during run (not config/service/version)
- Homebrew tap diff check (no redundant commits)
- claude -p for non-interactive CHANGELOG update
- filter.ensure_loaded() in WardProxy (fixes github/keyfile filters)
- Share op_state across all WardProxy instances
- Include PATH in launchd plist for op CLI access
- Register calls unregister first for clean restart

## [0.1.8] - 2026-04-03

### Fixed

- Fix APPLE_ID for notarization (was developer@, should be kawaz@)


## [0.1.7] - 2026-04-03

### Fixed

- Fix release workflow: remove invalid secrets conditional in if statements
- CI/CD secrets saved to 1Password for reproducibility


## [0.1.6] - 2026-04-03

### Added

- Apple codesign + Hardened Runtime + Notarization for macOS binaries
- musl build targets (x86_64 + aarch64) for Alpine Linux

### Fixed

- Homebrew tap: only commit when formula actually changes


## [0.1.5] - 2026-04-03

### Added

- op_account config field for multi-account 1Password setups
- op_account embedded in launchd plist EnvironmentVariables on service register

### Fixed

- PKCS#8 parser: added design rationale comment for 1Password compatibility


## [0.1.4] - 2026-04-03

### Fixed

- register now calls unregister first to ensure clean process restart
- Aligned justfile with jj-worktree/stable-which style


## [0.1.3] - 2026-04-03

### Fixed

- Support OP_ACCOUNT environment variable for multi-account 1Password setups
- All op CLI calls now use centralized op_command() helper with account selection

## [0.1.2] - 2026-04-03

### Fixed

- Include user's PATH in launchd plist so `op` CLI is accessible when running as a service
- Call `filter.ensure_loaded()` in WardProxy (fixes github= and keyfile= filters not working)
- Share op_state across all WardProxy instances (single TouchID for multiple sockets)
- Validate op item_id before passing to CLI (prevent option injection)
- OpState::Failed auto-retries after 60 seconds (no longer requires restart)

## [0.1.1] - 2026-04-03

### Added

- **SSH agent proxy** -- Forward requests to upstream SSH agent with key filtering (authsock-filter compatible)
- **op:// source** -- 1Password integration via op CLI for local signing with warden-managed timeouts
- **Multiple source types** -- `agent:`, `op://`, `file:` members in source groups
- **Source groups** -- Bundle multiple key sources under one name (`--source work=op://,agent:PATH`)
- **Per-socket key filtering** -- comment, fingerprint, keytype, pubkey, keyfile, github filters with AND/OR logic
- **Process-aware access control** -- Restrict key usage by connecting process identity (PID + process tree)
- **4-state key lifecycle** -- Not Loaded -> Active -> Locked -> Forgotten
- **Per-key timeout/forget** -- Independent timeout and forget_after settings per key
- **Memory protection** -- Private keys zeroized on drop, mlock, ptrace denial, core dump disabled
- **Private key caching** -- First sign fetches from 1Password, subsequent signs use cached key
- **Hybrid key discovery** -- Disk cache + 1Password agent socket + op item get fallback
- **Agent socket refresh** -- Detects new keys from 1Password agent on every REQUEST_IDENTITIES
- **CLI** -- `run`, `config`, `service`, `completion`, `version` subcommands
- **Config file** -- TOML format with source groups, socket definitions, per-key policies
- **Config-less mode** -- `--source` and `--socket` CLI args for quick usage without config file
- **Shell completion** -- Dynamic completion for bash, zsh, fish, powershell
- **Security hardening** -- DYLD_INSERT_LIBRARIES detection, ptrace(PT_DENY_ATTACH), core dump disabling
- **OS service** -- launchd (macOS) and systemd (Linux) service management
- **E2E tests** -- Integration tests with mock SSH agent
- **Cross-platform** -- macOS (primary) and Linux support
