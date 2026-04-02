# authsock-warden

SSH agent proxy with key filtering, process-aware access control, and 1Password integration.

## Features

- **Key filtering** — Control which SSH keys are visible per socket (from [authsock-filter](https://github.com/kawaz/authsock-filter))
- **Process-aware access control** — Restrict key usage based on connecting process identity
- **1Password integration** — Lazy key fetching from 1Password with per-key timeouts
- **Memory protection** — Secrets are mlocked, zeroized on drop, and protected from debugging

## Status

Under development.

## License

MIT License — Yoshiaki Kawazu (@kawaz)
