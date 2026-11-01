# scope

> **Network scope enforcement layer for authorized security testing.**  
> Sits between your tool and the network — every outbound connection is checked against a policy before it leaves.

[![Go 1.22+](https://img.shields.io/badge/Go-1.22%2B-blue)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## Quick Start — Auto Mode

```bash
# Automatically fetch scope from all bug-bounty platforms, then run the tool
scope run nmap example.com
scope run subfinder example.com -silent
scope run nuclei example.com -t cves/
scope run httpx example.com -status-code
scope run curl example.com
```

`scope` searches **HackerOne, Bugcrowd, Intigriti, and YesWeHack** for programs
that include `example.com`, merges the scope, starts an enforcement proxy, then
executes the tool with `HTTP_PROXY` injected automatically.

If the domain is **not found** in any program → the tool is **blocked** (fail-closed).

---

## Manual Mode — Supply Your Own Policy

```bash
# Validate a policy file
scope policy validate my_policy.yaml

# Check a single URL against a policy
scope check https://api.example.com --program my_policy.yaml

# Run a tool under policy enforcement
scope run --program my_policy.yaml --level 2 -- nmap -sV api.example.com

# Dry-run (print decisions, don't execute)
scope run --program my_policy.yaml --dry-run -- curl https://api.example.com
```

---

## Installation

```bash
git clone https://github.com/vulnquest58/scope
cd scope
go build -o scope ./cmd/scope
# Optional: move to PATH
mv scope /usr/local/bin/
```

**Requirements:** Go 1.22+

---

## Policy File Format

```yaml
program: "ACME Corp Bug Bounty"
fetched: "2026-01-01T00:00:00Z"
expires: "2027-01-01T00:00:00Z"

levels:
  max: 2           # 0=low 1=medium 2=high 3=critical

windows:           # Optional: restrict testing hours
  - days: ["mon", "tue", "wed", "thu", "fri"]
    hours: ["09:00-18:00"]
    timezone: "Europe/London"

rate:
  per_host_rps: 5
  global_rps: 20
  burst: 10

allow:
  - "*.example.com"
  - "api.example.com"
  - "203.0.113.0/24"

deny:
  - reason: "production payment endpoint"
    match: ["pay.example.com"]
  - reason: "out-of-scope third-party"
    match: ["cdn.cloudflare.com"]
```

---

## Environment Variables

| Variable | Description |
|---|---|
| `HACKERONE_API_USER` | HackerOne username |
| `HACKERONE_API_TOKEN` | HackerOne API token |
| `BUGCROWD_API_TOKEN` | Bugcrowd API token |
| `INTIGRITI_API_TOKEN` | Intigriti API token |
| `YESWEHACK_TOKEN` | YesWeHack JWT token |
| `SCOPE_PLATFORMS` | Comma-separated filter: `hackerone,bugcrowd,intigriti,yeswehack` |

Without API keys, only **public programs** are searched.

---

## Architecture

```
scope run <tool> <domain>
     │
     ├─ platform.Resolver → searches 4 platforms concurrently
     │                       → merges scope into Policy
     │
     ├─ decide.Engine     → evaluates every connection:
     │                       1. Policy loaded?
     │                       2. Policy not expired?
     │                       3. Within time window?
     │                       4. Not rate-limited?
     │                       5. Not explicit deny?
     │                       6. Not third-party CDN?
     │                       7. Matches allow list?
     │
     ├─ enforce.Proxy     → L7 HTTP/HTTPS proxy (CONNECT support)
     │
     ├─ log.Journal       → append-only JSONL log, Ed25519-signed,
     │                       SHA-256 chain per entry
     │
     └─ enforce.Runner    → executes tool with HTTP_PROXY injected
```

---

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success / allowed |
| 1 | Command failed / denied |
| 2 | Usage error |
| 3 | Policy or log load failed |
| 4 | Enforcement layer failed |

---

## Commands Reference

```
scope run <tool> <domain> [tool-args...]          # auto platform lookup
scope run --domain <host> -- <cmd>                # lookup by domain, run cmd
scope run --program <file> -- <cmd>               # manual policy
scope run --program <file> --dry-run -- <cmd>     # dry-run (no execution)

scope check <url|host> --program <file>           # check single target
scope check <url|host> --program <file> --json    # JSON output

scope policy validate <file>                      # validate policy YAML
scope policy show <file>                          # show policy summary

scope journal tail --path <file> --n 20           # tail audit log
scope verify-log <path>                           # verify log chain
```

---

## Security Properties

- **Fail-closed:** Every error path → Deny. No silent pass-through.
- **Deny before allow:** Explicit deny rules checked before allow list.
- **Immutable log:** Each journal entry is signed with Ed25519 and chained with SHA-256.
- **No root required:** Runs as a regular user via L7 proxy injection.
- **No credential storage:** API keys via environment variables only.

---

## Disclaimer

**Authorised use only.** This tool enforces a policy you supplied; it does not verify your authorisation. The operator is solely responsible for ensuring they have permission to test the targets in their policy.

---

## License

MIT © 2026 vulnquest58
