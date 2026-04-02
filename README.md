# authsock-warden

SSH agent proxy with key filtering, process-aware access control, and 1Password integration.

The "warden" (guardian) of your `SSH_AUTH_SOCK` — controls which keys are visible, which processes can sign, and when keys should be forgotten.

## Features

- **Multiple key sources** — Aggregate keys from 1Password SSH agent, `op` CLI, and local files through a single socket
- **Per-socket key filtering** — Control which SSH keys are visible on each socket using comment, fingerprint, key type, public key, keyfile, or GitHub user filters
- **Process-aware access control** — Restrict key usage based on the connecting process identity (PID + process tree walking)
- **Per-key timeouts** — Independent timeout and forget-after settings per key (what 1Password doesn't offer)
- **4-state key lifecycle** — Not Loaded → Active → Locked → Forgotten, with configurable on-timeout behavior
- **Remote re-auth** — When locked, keys can be unlocked via external command (Passkey, push notification, etc.) without TouchID
- **Memory protection** — Secrets are zeroized on drop, mlocked to prevent swap, ptrace/core dumps denied
- **3-layer policy** — Key policies (ceiling) intersected with socket policies (restriction) for defense in depth

## Architecture

```
                          ┌──────────────────────┐
SSH clients ──► socket A ─┤                      ├─► 1Password SSH agent
SSH clients ──► socket B ─┤  authsock-warden     ├─► op CLI (1Password)
SSH clients ──► socket C ─┤                      ├─► Local key files
                          └──────────────────────┘
                           Filters + Process check
                           + Key lifecycle + Timeout
```

## Getting Started

### Install

```bash
cargo install --path .
```

### Configure

Create `~/.config/authsock-warden/config.toml`:

```toml
# Proxy all keys from 1Password SSH agent
[[sources]]
name = "1password"
members = ["~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"]

[sockets.default]
path = "/tmp/authsock-warden.sock"
source = "1password"
```

### Run

```bash
# Start the proxy
authsock-warden run

# Or without a config file:
authsock-warden run --socket /tmp/authsock-warden.sock

# In another terminal, use the proxy
export SSH_AUTH_SOCK=/tmp/authsock-warden.sock
ssh-add -L  # Lists keys from 1Password, filtered by warden
```

### Advanced Configuration

```toml
# Source group: bundle multiple key sources
[[sources]]
name = "work"
members = [
    "op://emerada",           # 1Password vault (warden signs locally)
    "agent:~/.ssh/agent.sock", # SSH agent proxy (upstream signs)
    "file:~/.ssh/id_work",    # Local key file
]

# Filter keys per socket
[sockets.work]
path = "/tmp/authsock-warden-work.sock"
source = "work"
filters = ["comment=~@work", "type=ed25519"]
allowed_processes = ["git", "ssh", "jj"]
timeout = "1h"

# Per-key policy
[[keys]]
public_key = "ssh-ed25519 AAAA..."
timeout = "4h"
on_timeout = "lock"       # Keep in memory but require re-auth
forget_after = "24h"      # Zeroize after 24h regardless
allowed_processes = ["ssh", "git", "jj"]
```

See `examples/` for more configuration examples.

## Comparison with 1Password SSH Agent

authsock-warden complements (not replaces) 1Password's SSH agent:

| Feature | 1Password | authsock-warden |
|---|---|---|
| Per-key timeout | App-wide only | Per-key configurable |
| Remote re-auth | TouchID only | External command (Passkey, etc.) |
| Multiple sources | Own keys only | 1Password + files + other agents |
| Per-socket filtering | Single socket | Multiple sockets with filters |
| Process restriction | GUI approval | Automatic process tree matching |

## Status

Under active development. The proxy mode (agent source type) is functional. 1Password managed signing and file-based keys are in progress.

## License

MIT License -- Yoshiaki Kawazu (@kawaz)
