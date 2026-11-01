# Known Limits — What scope Does Not Protect Against

> **Read this before you test.** scope enforces the policy you supply. It does
> not verify that you are authorised to test. Understanding its limits is part
> of responsible use.

---

## L7 (HTTP/HTTPS Proxy) Limits — M2

| Limit | Detail |
|-------|--------|
| **HTTPS body is not inspected** | In CONNECT mode, scope evaluates the `Host` header only. The TLS payload is tunnelled without inspection. A tool that resolves DNS itself and then connects to an IP directly will bypass L7. |
| **No TLS termination** | scope does not act as a MITM proxy. It sees the hostname, not the request path or body. |
| **Tools that bypass the proxy** | Any tool that does not honour `HTTP_PROXY`/`HTTPS_PROXY` environment variables will not route through scope. Inject the proxy explicitly for such tools. |
| **IPv6 literal targets** | A tool that connects to `[2001:db8::1]` directly (no hostname) will be evaluated by address only, not by hostname policy. |

## L3 (DNS) Limits — M3

| Limit | Detail |
|-------|--------|
| **Tools with hardcoded resolvers** | Tools that send DNS queries to `8.8.8.8` directly (not the system resolver) bypass the local DNS server. |
| **DNS-over-HTTPS (DoH)** | DoH bypasses the local DNS port. scope does not intercept HTTPS-based DNS. |
| **Only A/AAAA filtered** | Other record types (MX, TXT, SRV, …) are `REFUSED`, not `NXDOMAIN`. This is correct but may confuse some tools. |

## L4 (Connect Shim) Limits — M4 (not yet implemented)

| Limit | Detail |
|-------|--------|
| **Not implemented in M2** | L4 enforcement requires `LD_PRELOAD` or WFP callouts. Deferred to M4. |
| **Kernel bypass** | Raw sockets and DPDK-based tools bypass the kernel TCP stack and therefore bypass L4 shims. |

## General Limits

| Limit | Detail |
|-------|--------|
| **Policy is read at startup only** | Changes to the YAML file while scope is running have no effect until the next invocation. |
| **No authorisation verification** | scope enforces the policy you give it. It cannot verify that you have permission to test the targets. You are responsible for obtaining authorisation before testing. |
| **Resolver cache TTL is fixed at 300s** | A target that changes DNS during a run may be evaluated against a stale address for up to 5 minutes. |
| **Journal key not persisted** | Ed25519 signing keys are generated fresh on each run. Cross-run log chain verification requires exporting the public key. |
| **No rate-limit on deny decisions** | Deny decisions do not consume rate-limiter tokens. A tool that rapidly probes out-of-scope hosts will not be slowed by the rate limiter. |

---

> **Authorised use only.** This tool enforces a policy you supplied;
> it does not verify your authorisation.

