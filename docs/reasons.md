# Denial Reason Codes — Reference

> Every decision that is not `allow` is a denial. This document explains each
> reason code: when it appears, what it means, and how to resolve it.

---

## `allow`

**Not a denial.** The target matched an entry in the `allow` list and passed
all other checks.

---

## `policy-missing`

**When:** No policy file has been loaded (e.g. `--program` was not given, or
the file does not exist).

**What it means:** The engine has no policy to evaluate against. Every request
is denied until a valid policy is loaded.

**How to fix:** Provide `--program <file>` pointing to a valid YAML policy.

---

## `policy-expired`

**When:** The current wall-clock time is after `expires`, or before `fetched`
(clock skew).

**What it means:** The policy's validity window has ended. All traffic is
denied until the policy is refreshed.

**How to fix:** Export a fresh policy from your bug-bounty platform and
re-run.  If the clock is skewed, fix the system time.

---

## `policy-invalid`

**When:** The policy YAML is malformed, or a required field is missing or
out-of-range.

**What it means:** The policy failed schema validation. See the accompanying
error message for the specific field and line number.

**How to fix:** Fix the named field in your YAML file and re-run
`scope policy validate <file>` to confirm.

---

## `outside-window`

**When:** The current time (in the window's timezone) falls outside every
`windows` entry.

**What it means:** Testing is only permitted during the configured time
windows. The request arrived outside those hours.

**How to fix:** Wait until the allowed window, or remove the `windows`
constraint if testing should be unrestricted (not recommended for production
programmes).

---

## `rate-limited`

**When:** The per-host or global token-bucket limiter has been exhausted.

**What it means:** The tool is generating requests faster than the policy
allows. The request is dropped to protect the target.

**How to fix:** Slow down the tool (reduce concurrency, add delays), or
increase `per_host_rps` / `global_rps` in the policy if the programme
permits higher rates.

---

## `unresolvable`

**When:** DNS resolution of the target hostname failed.

**What it means:** The engine could not determine the IP address of the
target. This is fail-closed — an unresolvable name is never allowed.

**How to fix:** Check that the hostname is spelled correctly and that your
network can resolve it. Temporary DNS failures will retry on the next
request (failures are not cached).

---

## `explicit-deny`

**When:** The normalised hostname or resolved IP matched a `deny` rule before
any `allow` rule was consulted.

**What it means:** The programme explicitly excludes this target.

**How to fix:** Do not test this target. If you believe it should be in
scope, contact the programme owner.

---

## `third-party-host`

**When:** The CNAME chain of the target ends at a known third-party hosting
provider (Cloudfront, Heroku, Shopify, etc.) and the original hostname is
**not** in the explicit `allow` list.

**What it means:** The target appears to be hosted on infrastructure owned by
a third party. Testing it without explicit authorisation from that provider
is out of scope.

**How to fix:** If the programme explicitly allows this target, add it as an
exact entry to the `allow` list:

```yaml
allow:
  - "status.example.com"   # explicit exception — CNAME to statuspage.io
```

---

## `outside-wildcard`

**When:** The target did not match any `deny` rule, but also did not match any
`allow` rule.

**What it means:** Default-deny. If it is not explicitly allowed, it is
forbidden.

**How to fix:** Add the target to the `allow` list if the programme covers
it.

---

## `level-too-high`

**When:** The `--level` flag value exceeds `levels.max` in the policy.

**What it means:** The requested test intensity is higher than the programme
permits.

**How to fix:** Lower `--level` to at most `levels.max`, or ask the programme
owner to raise the limit.

---

## `engine-error`

**When:** An unexpected internal error occurred in the decision engine.

**What it means:** A bug in scope. All requests are denied until the process
is restarted.

**How to fix:** File a bug report with the full log output. Do not attempt to
work around this error.

