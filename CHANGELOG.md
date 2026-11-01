# Changelog

All notable changes to scope are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.1.0] — 2026-11-01

### Added
- `internal/policy` — Policy model (YAML), 12-step ordered validation, wildcard/CIDR matching, 19-provider third-party detection
- `internal/decide` — Decision engine with 16-step ordered algorithm; fail-closed on every error path
- `internal/decide.RateLimiter` — Per-host and global token-bucket rate limiter
- `internal/log` — Append-only JSONL journal with Ed25519 per-entry signatures and SHA-256 hash chaining
- `internal/enforce/proxy` — L7 HTTP/HTTPS forward proxy (M2)
- `internal/enforce/dns` — L3 local DNS resolver returning NXDOMAIN for denied names (M3)
- `internal/enforce/runner` — Command runner with proxy environment injection
- `internal/cli` — Subcommands: `run`, `check`, `policy validate`, `policy show`, `verify-log`, `journal tail`
- `testdata/policy_valid.yaml` — Working policy example
- `testdata/policy_expired.yaml` — Expired policy for error-path testing
- `testdata/policy_bad_syntax.yaml` — Malformed YAML for validation testing
- `docs/SPEC.md` — Full executable specification
- `docs/reasons.md` — All 12 denial reason codes documented
- `docs/limits.md` — Known limits and what scope does not protect against

### Architecture decisions
- Fail-closed: every error path ends in Deny
- Deny rules evaluated before allow rules
- Cache TTL fixed at 300 s; failed resolutions never cached
- Journal write failure is fatal (stops the process)
- No external proxy or DNS libraries — stdlib only

