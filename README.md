# scope

> Network scope enforcement layer for security testing.  
> Enforces a bug-bounty policy between your tool and the network.

**Authorised use only. This tool enforces a policy you supplied; it does not verify your authorisation.**

---

## What it does

scope sits between any security tool and the network. For every outbound
packet it decides: **allowed** or **denied**, according to a policy file you
supply. Every decision is recorded in a signed, append-only evidence journal.

```
your tool  →  scope (L7 proxy / L3 DNS)  →  target
                     ↓
              evidence journal (JSONL + Ed25519)
```

## What it does NOT do

| ❌ Will not | Reason |
|------------|--------|
| Discover scope automatically | It enforces policy, not produces it |
| Scan targets itself | It is not a scanner |
| Modify passing requests | That would break tool trust |
| Allow on doubt | Fail-closed always |
| Require root/admin | M2 runs as a normal user |
| Store platform credentials | You export the YAML |

See [docs/limits.md](docs/limits.md) for a full list of known limits.

---

## Quick start

```bash
# 1. Validate your policy
scope policy validate testdata/policy_valid.yaml

# 2. Dry-run: see decisions without executing
scope run --program testdata/policy_valid.yaml --level 1 --dry-run -- curl https://api.example.com

# 3. Real run: proxy all traffic through scope
scope run --program testdata/policy_valid.yaml --level 1 -- nmap -sV api.example.com

# 4. Check a single target
scope check https://api.example.com --program testdata/policy_valid.yaml

# 5. Verify the evidence journal
scope verify-log .scope/runs/2026-11-01T12-00-00Z.jsonl
```

---

## Policy file format

```yaml
program: "ACME Bug Bounty"           # Required
fetched: "2026-01-01T00:00:00Z"      # Required — when the policy was exported
expires: "2027-01-01T00:00:00Z"      # Required — must be after fetched

levels:
  max: 2                             # 0..3 — max test intensity

windows:
  - days: ["mon", "tue", "wed", "thu", "fri"]
    hours: ["09:00-18:00"]
    timezone: "UTC"

rate:
  per_host_rps: 5.0                  # 0 = unlimited
  global_rps: 20.0
  burst: 10

allow:
  - "*.example.com"
  - "203.0.113.0/24"

deny:
  - reason: "Admin panel out of scope"
    match: ["admin.example.com"]
```

See `testdata/policy_valid.yaml` for a working example.

---

## CLI reference

| Command | Description |
|---------|-------------|
| `scope run --program <file> [--level N] [--dry-run] -- <cmd>` | Run a command under scope enforcement |
| `scope check <host\|url> --program <file>` | Evaluate a single target |
| `scope policy validate <file>` | Validate a policy file |
| `scope policy show <file>` | Print parsed policy |
| `scope verify-log <path>` | Verify journal integrity |
| `scope journal tail --path <path>` | Print last 20 journal entries |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Command succeeded / target allowed |
| 1 | Command failed / target denied |
| 2 | Usage error |
| 3 | Policy or journal load failed |
| 4 | Enforcement layer failed to start |

---

## Architecture

```
cmd/scope/main.go          Entry point
internal/policy/           Policy model, validation, matching (wildcard/CIDR/provider)
internal/decide/           Decision engine — 16-step ordered algorithm
internal/enforce/          L7 proxy (HTTP/HTTPS), L3 DNS resolver, command runner
internal/log/              Append-only signed JSONL journal (Ed25519)
internal/cli/              Subcommand handlers
```

### Decision algorithm (ordered)

1. Policy not loaded → `policy-missing`
2. Validation failed → `policy-invalid`
3. `now > expires` → `policy-expired`
4. `now < fetched` → `policy-expired` (clock skew)
5. Outside time window → `outside-window`
6. Rate limit exceeded → `rate-limited`
7. `level > levels.max` → `level-too-high`
8. DNS resolution fails → `unresolvable`
9. `denyExact` match → `explicit-deny`
10. `denyWild` match → `explicit-deny`
11. `denyNets` match → `explicit-deny`
12. CNAME → third-party, no explicit exception → `third-party-host`
13. `allowExact` match → ✅ allow
14. `allowWild` match → ✅ allow
15. `allowNets` match → ✅ allow
16. No match → `outside-wildcard`

---

## Security design

- **Fail-closed everywhere** — every error path denies
- **Deny before allow** — explicit deny always checked first
- **Signed journal** — Ed25519 per-entry signatures with SHA-256 hash chain
- **No root required** — M2 runs as a normal user process
- **No platform credentials stored** — you export YAML

---

## Known limits

See [docs/limits.md](docs/limits.md).

## Reason codes

See [docs/reasons.md](docs/reasons.md).

---

## Build & test

```bash
go build ./...
go test -race ./...
go vet ./...
```

**Coverage targets:** `internal/decide` ≥ 95%, overall ≥ 85%.

---

## License

MIT — see [LICENSE](LICENSE).

