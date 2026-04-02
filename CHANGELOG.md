# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
