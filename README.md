# authsock-warden

SSH agent proxy with key filtering, process-aware access control, and 1Password integration.

The "warden" (guardian) of your `SSH_AUTH_SOCK` -- controls which keys are visible, which processes can sign, and when keys should be forgotten.

## Features

- **Multiple key sources** -- Aggregate keys from 1Password (`op://`), SSH agent sockets, and local files through a single socket
- **1Password local signing** -- Fetch keys via `op` CLI, sign locally with warden-managed timeouts (independent of 1Password's app-wide timeout)
- **Per-socket key filtering** -- comment, fingerprint, key type, public key, keyfile, GitHub user filters with AND/OR logic
- **Process-aware access control** -- Restrict key usage by connecting process identity (PID + process tree walking)
- **Per-key timeouts** -- Independent timeout and forget-after settings per key
- **4-state key lifecycle** -- Not Loaded -> Active -> Locked -> Forgotten
- **Remote re-auth** -- Unlock locked keys via external command (Passkey, push notification) without TouchID
- **Memory protection** -- Private keys zeroized on drop, mlocked, ptrace/core dumps denied
- **Smart key discovery** -- Disk cache + 1Password agent fast path + op CLI fallback (typically ~5s first run, instant thereafter)
- **OS service** -- Register as launchd (macOS) or systemd (Linux) service

## Architecture

```
                          +----------------------+
SSH clients --> socket A -|                      |-> 1Password SSH agent
SSH clients --> socket B -|  authsock-warden     |-> op CLI (1Password)
SSH clients --> socket C -|                      |-> Local key files
                          +----------------------+
                           Filters + Process check
                           + Key lifecycle + Timeout
```

## Installation

```bash
# From source
cargo install --path .

# Homebrew (coming soon)
# brew install kawaz/tap/authsock-warden
```

## Quick Start

```bash
# Simplest: proxy $SSH_AUTH_SOCK with no filtering
authsock-warden run --socket /tmp/authsock-warden.sock

# Use 1Password local signing (warden manages key timeouts)
authsock-warden run --source op:// --socket /tmp/authsock-warden.sock

# With filters
authsock-warden run \
  --source op://emerada \
  --socket /tmp/work.sock comment=*@work* type=ed25519

# Use the proxy
export SSH_AUTH_SOCK=/tmp/authsock-warden.sock
ssh-add -L
```

## Configuration

Create `~/.config/authsock-warden/config.toml`:

```toml
# 1Password account (required if multiple accounts configured)
# op_account = "kawaz.1password.com"

# Source groups bundle multiple key sources under one name
[[sources]]
name = "work"
members = [
    "op://emerada",           # 1Password vault (warden signs locally)
    "agent:~/.ssh/agent.sock", # SSH agent proxy (upstream signs)
]

# Socket definitions
[sockets.work]
path = "$XDG_RUNTIME_DIR/authsock-warden/work.sock"
source = "work"
filters = ["comment=~@work", "type=ed25519"]
allowed_processes = ["git", "ssh", "jj"]

[sockets.all]
path = "/tmp/authsock-warden.sock"
source = "work"

# Per-key policies (optional)
[[keys]]
public_key = "ssh-ed25519 AAAA..."
timeout = "4h"
on_timeout = "lock"       # Keep in memory but require re-auth
forget_after = "24h"      # Zeroize after 24h regardless
allowed_processes = ["ssh", "git", "jj"]
```

### Source Member Types

| Member | Mode | Description |
|---|---|---|
| `op://` | Local signing | All 1Password SSH keys |
| `op://vault` | Local signing | Keys in a specific vault |
| `op://vault/item` | Local signing | A specific key |
| `agent:PATH` | Proxy | Forward to SSH agent socket |
| `file:PATH` | Local signing | Load private key from file |
| `PATH` | Auto-detect | Socket -> agent, file -> key |

### Filter Types

| Filter | Example | Description |
|---|---|---|
| `comment=` | `comment=*@work*` | Glob, `~regex`, or exact match |
| `fingerprint=` | `fingerprint=SHA256:xxx` | SHA256 or MD5 fingerprint |
| `type=` | `type=ed25519` | Key type (ed25519, rsa, ecdsa, dsa) |
| `github=` | `github=kawaz` | Keys from github.com/user.keys |
| `pubkey=` | `pubkey=ssh-ed25519 AAAA...` | Full public key match |
| `keyfile=` | `keyfile=~/.ssh/allowed` | Keys from authorized_keys file |
| `not-*` | `not-type=dsa` | Negate any filter |

See `examples/` for more configuration examples.

## Service Management

```bash
# Register as OS service (launchd on macOS, systemd on Linux)
authsock-warden service register

# Check status
authsock-warden service status

# View logs
authsock-warden log --since 5m
authsock-warden log --follow

# Unregister
authsock-warden service unregister
```

## Configuration Management

```bash
# Show config file contents
authsock-warden config show

# Open in editor
authsock-warden config edit

# Print config file path
authsock-warden config path
```

## Comparison with 1Password SSH Agent

authsock-warden complements (not replaces) 1Password's SSH agent:

| Feature | 1Password | authsock-warden |
|---|---|---|
| Per-key timeout | App-wide only | Per-key configurable |
| Remote re-auth | TouchID only | External command (Passkey, etc.) |
| Multiple sources | Own keys only | 1Password + files + other agents |
| Per-socket filtering | Single socket | Multiple sockets with filters |
| Process restriction | GUI approval | Automatic process tree matching |
| Local signing | N/A | Warden fetches key, signs locally |

## Shell Completion

```bash
# Bash
source <(authsock-warden completion bash)

# Zsh
source <(authsock-warden completion zsh)

# Fish
authsock-warden completion fish | source
```

## Environment Variables

| Variable | Description |
|---|---|
| `SSH_AUTH_SOCK` | Default upstream agent (when no `--source`) |
| `AUTHSOCK_WARDEN_CONFIG` | Config file path override |
| `XDG_CONFIG_HOME` | Config directory (default: `~/.config`) |
| `XDG_RUNTIME_DIR` | Runtime directory for sockets |
| `XDG_CACHE_HOME` | Cache directory (default: `~/.cache`) |

## License

MIT License -- Yoshiaki Kawazu (@kawaz)
