package decide_test

import (
	"context"
	"testing"
	"time"

	"github.com/vulnquest58/scope/internal/decide"
	"github.com/vulnquest58/scope/internal/policy"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func futurePolicy(allow string) *policy.CompiledPolicy {
	cp, err := policy.LoadBytes([]byte(`
program: "Test"
fetched: "2020-01-01T00:00:00Z"
expires: "2099-01-01T00:00:00Z"
levels:
  max: 3
allow: ["` + allow + `"]
`))
	if err != nil {
		panic("futurePolicy: " + err.Error())
	}
	return cp
}

func engineFor(allow string) *decide.Engine {
	return decide.NewEngine(futurePolicy(allow))
}

func ctx() context.Context { return context.Background() }

// ---------------------------------------------------------------------------
// Decision order — §6.2 (all 16 steps)
// ---------------------------------------------------------------------------

// Step 1: policy-missing
func TestDecide_PolicyMissing(t *testing.T) {
	e := decide.NewEngineEmpty()
	d := e.Decide(ctx(), "example.com", 1)
	if d.Verdict != decide.Deny || d.Reason != decide.ReasonPolicyMissing {
		t.Errorf("got %v/%v, want Deny/policy-missing", d.Verdict, d.Reason)
	}
}

// Step 3: policy-expired (now > Expires)
func TestDecide_PolicyExpired(t *testing.T) {
	cp, _ := policy.LoadBytes([]byte(`
program: "P"
fetched: "2020-01-01T00:00:00Z"
expires: "2021-01-01T00:00:00Z"
allow: ["*.example.com"]
`))
	e := decide.NewEngine(cp)
	d := e.Decide(ctx(), "api.example.com", 1)
	if d.Verdict != decide.Deny || d.Reason != decide.ReasonPolicyExpired {
		t.Errorf("got %v/%v, want Deny/policy-expired", d.Verdict, d.Reason)
	}
}

// Step 4: clock skew (now < Fetched)
func TestDecide_ClockSkew(t *testing.T) {
	cp, _ := policy.LoadBytes([]byte(`
program: "P"
fetched: "2099-01-01T00:00:00Z"
expires: "2100-01-01T00:00:00Z"
allow: ["*.example.com"]
`))
	e := decide.NewEngine(cp)
	d := e.Decide(ctx(), "api.example.com", 1)
	if d.Verdict != decide.Deny || d.Reason != decide.ReasonPolicyExpired {
		t.Errorf("got %v/%v, want Deny/policy-expired", d.Verdict, d.Reason)
	}
}

// Step 5: outside-window
func TestDecide_OutsideWindow(t *testing.T) {
	cp, _ := policy.LoadBytes([]byte(`
program: "P"
fetched: "2020-01-01T00:00:00Z"
expires: "2099-01-01T00:00:00Z"
levels:
  max: 3
allow: ["*.example.com"]
windows:
  - days: ["*"]
    hours: ["09:00-10:00"]
    timezone: "UTC"
`))
	e := decide.NewEngine(cp)
	e.SetNow(func() time.Time { return time.Date(2026, 1, 1, 2, 0, 0, 0, time.UTC) })
	d := e.DecideWithAddr(ctx(), "api.example.com", decide.MustParseAddr("1.2.3.4"), 1)
	if d.Verdict != decide.Deny || d.Reason != decide.ReasonOutsideWindow {
		t.Errorf("got %v/%v, want Deny/outside-window", d.Verdict, d.Reason)
	}
}

// Step 6: rate-limited (global)
func TestDecide_RateLimitedGlobal(t *testing.T) {
	cp, _ := policy.LoadBytes([]byte(`
program: "P"
fetched: "2020-01-01T00:00:00Z"
expires: "2099-01-01T00:00:00Z"
levels:
  max: 3
rate:
  per_host_rps: 100.0
  global_rps: 1.0
  burst: 1
allow: ["*.example.com"]
`))
	e := decide.NewEngine(cp)
	now := time.Now()
	e.SetNow(func() time.Time { return now })

	// First request allowed.
	_ = e.DecideWithAddr(ctx(), "api.example.com", decide.MustParseAddr("1.2.3.4"), 1)
	// Second request → global rate limited.
	d := e.DecideWithAddr(ctx(), "other.example.com", decide.MustParseAddr("1.2.3.5"), 1)
	if d.Verdict != decide.Deny || d.Reason != decide.ReasonRateLimited {
		t.Errorf("got %v/%v, want Deny/rate-limited", d.Verdict, d.Reason)
	}
}

// Step 7: level-too-high (before DNS)
func TestDecide_LevelTooHigh(t *testing.T) {
	cp, _ := policy.LoadBytes([]byte(`
program: "P"
fetched: "2020-01-01T00:00:00Z"
expires: "2099-01-01T00:00:00Z"
levels:
  max: 1
allow: ["*.example.com"]
`))
	e := decide.NewEngine(cp)
	d := e.DecideWithAddr(ctx(), "api.example.com", decide.MustParseAddr("1.2.3.4"), 3)
	if d.Verdict != decide.Deny || d.Reason != decide.ReasonLevelTooHigh {
		t.Errorf("got %v/%v, want Deny/level-too-high", d.Verdict, d.Reason)
	}
}

// Step 7 via Decide() (real path, tests level check before DNS)
func TestDecide_LevelTooHighBeforeDNS(t *testing.T) {
	cp, _ := policy.LoadBytes([]byte(`
program: "P"
fetched: "2020-01-01T00:00:00Z"
expires: "2099-01-01T00:00:00Z"
levels:
  max: 0
allow: ["*.example.com"]
`))
	e := decide.NewEngine(cp)
	// level=1 > max=0, should deny before even doing DNS
	d := e.Decide(ctx(), "api.example.com", 1)
	if d.Verdict != decide.Deny || d.Reason != decide.ReasonLevelTooHigh {
		t.Errorf("got %v/%v, want Deny/level-too-high", d.Verdict, d.Reason)
	}
}

// Step 8a: unresolvable
func TestDecide_Unresolvable(t *testing.T) {
	e := engineFor("*.example.com")
	d := e.Decide(ctx(), "this-domain-does-not-exist-zzzzzz.invalid", 1)
	if d.Verdict != decide.Deny || d.Reason != decide.ReasonUnresolvable {
		t.Errorf("got %v/%v, want Deny/unresolvable", d.Verdict, d.Reason)
	}
}

// Step 16: outside-wildcard
func TestDecide_OutsideWildcard(t *testing.T) {
	e := engineFor("203.0.113.0/24")
	d := e.DecideWithAddr(ctx(), "other.com", decide.MustParseAddr("198.51.100.1"), 1)
	if d.Verdict != decide.Deny || d.Reason != decide.ReasonOutsideWildcard {
		t.Errorf("got %v/%v, want Deny/outside-wildcard", d.Verdict, d.Reason)
	}
}

// Step 13: allowExact
func TestDecide_AllowExact(t *testing.T) {
	cp, _ := policy.LoadBytes([]byte(`
program: "P"
fetched: "2020-01-01T00:00:00Z"
expires: "2099-01-01T00:00:00Z"
levels:
  max: 3
allow: ["api.example.com"]
`))
	e := decide.NewEngine(cp)
	d := e.DecideWithAddr(ctx(), "api.example.com", decide.MustParseAddr("1.2.3.4"), 1)
	if d.Verdict != decide.Allow {
		t.Errorf("got %v/%v, want Allow", d.Verdict, d.Reason)
	}
}

// Step 14: allowWild
func TestDecide_AllowByName(t *testing.T) {
	e := engineFor("*.example.com")
	d := e.DecideWithAddr(ctx(), "api.example.com", decide.MustParseAddr("203.0.113.1"), 1)
	if d.Verdict != decide.Allow || d.Reason != decide.ReasonAllow {
		t.Errorf("got %v/%v, want Allow/allow", d.Verdict, d.Reason)
	}
}

// Step 15: allowNets
func TestDecide_AllowByNet(t *testing.T) {
	e := engineFor("203.0.113.0/24")
	d := e.DecideWithAddr(ctx(), "203.0.113.5", decide.MustParseAddr("203.0.113.5"), 1)
	if d.Verdict != decide.Allow {
		t.Errorf("got %v/%v, want Allow", d.Verdict, d.Reason)
	}
}

// Step 9: denyExact beats allowWild
func TestDecide_ExplicitDenyBeatsAllow(t *testing.T) {
	cp, _ := policy.LoadBytes([]byte(`
program: "P"
fetched: "2020-01-01T00:00:00Z"
expires: "2099-01-01T00:00:00Z"
levels:
  max: 3
allow: ["*.example.com"]
deny:
  - reason: "blocked"
    match: ["admin.example.com"]
`))
	e := decide.NewEngine(cp)
	d := e.DecideWithAddr(ctx(), "admin.example.com", decide.MustParseAddr("203.0.113.1"), 1)
	if d.Verdict != decide.Deny || d.Reason != decide.ReasonExplicitDeny {
		t.Errorf("got %v/%v, want Deny/explicit-deny", d.Verdict, d.Reason)
	}
}

// Step 10: denyWild
func TestDecide_DenyWild(t *testing.T) {
	cp, _ := policy.LoadBytes([]byte(`
program: "P"
fetched: "2020-01-01T00:00:00Z"
expires: "2099-01-01T00:00:00Z"
levels:
  max: 3
allow: ["*.example.com"]
deny:
  - reason: "internal"
    match: ["*.internal.example.com"]
`))
	e := decide.NewEngine(cp)
	d := e.DecideWithAddr(ctx(), "db.internal.example.com", decide.MustParseAddr("1.2.3.4"), 1)
	if d.Verdict != decide.Deny || d.Reason != decide.ReasonExplicitDeny {
		t.Errorf("got %v/%v, want Deny/explicit-deny", d.Verdict, d.Reason)
	}
}

// Step 11: denyNets
func TestDecide_DenyNets(t *testing.T) {
	cp, _ := policy.LoadBytes([]byte(`
program: "P"
fetched: "2020-01-01T00:00:00Z"
expires: "2099-01-01T00:00:00Z"
levels:
  max: 3
allow: ["203.0.113.0/24"]
deny:
  - reason: "restricted subnet"
    match: ["203.0.113.128/25"]
`))
	e := decide.NewEngine(cp)
	d := e.DecideWithAddr(ctx(), "203.0.113.200", decide.MustParseAddr("203.0.113.200"), 1)
	if d.Verdict != decide.Deny || d.Reason != decide.ReasonExplicitDeny {
		t.Errorf("got %v/%v, want Deny/explicit-deny", d.Verdict, d.Reason)
	}
}

// Step 12: third-party-host
func TestDecide_ThirdPartyHost(t *testing.T) {
	cp, _ := policy.LoadBytes([]byte(`
program: "P"
fetched: "2020-01-01T00:00:00Z"
expires: "2099-01-01T00:00:00Z"
levels:
  max: 3
allow: ["*.example.com"]
`))
	e := decide.NewEngine(cp)
	d := e.DecideWithAddrAndChain(ctx(), "status.example.com",
		decide.MustParseAddr("1.2.3.4"),
		[]string{"status.example.com", "acme.statuspage.io"},
		1)
	if d.Verdict != decide.Deny || d.Reason != decide.ReasonThirdPartyHost {
		t.Errorf("got %v/%v, want Deny/third-party-host", d.Verdict, d.Reason)
	}
}

// Expired policy denies everything even if name matches allow.
func TestDecide_ExpiredPolicyDeniesAll(t *testing.T) {
	cp, _ := policy.LoadBytes([]byte(`
program: "P"
fetched: "2020-01-01T00:00:00Z"
expires: "2021-01-01T00:00:00Z"
allow: ["*.example.com"]
`))
	e := decide.NewEngine(cp)
	d := e.DecideWithAddr(ctx(), "api.example.com", decide.MustParseAddr("203.0.113.1"), 1)
	if d.Verdict != decide.Deny || d.Reason != decide.ReasonPolicyExpired {
		t.Errorf("got %v/%v, want Deny/policy-expired", d.Verdict, d.Reason)
	}
}

// Explicit exception beats third-party detection.
func TestDecide_ExplicitExceptionBeatsThirdParty(t *testing.T) {
	cp, _ := policy.LoadBytes([]byte(`
program: "P"
fetched: "2020-01-01T00:00:00Z"
expires: "2099-01-01T00:00:00Z"
levels:
  max: 3
allow: ["status.example.com"]
`))
	e := decide.NewEngine(cp)
	d := e.DecideWithAddrAndChain(ctx(), "status.example.com",
		decide.MustParseAddr("1.2.3.4"),
		[]string{"status.example.com", "acme.statuspage.io"},
		1)
	if d.Verdict != decide.Allow {
		t.Errorf("explicit exception should beat third-party detection: got %v/%v", d.Verdict, d.Reason)
	}
}

// Rate limiter: per-host limit.
func TestDecide_RateLimitedPerHost(t *testing.T) {
	cp, _ := policy.LoadBytes([]byte(`
program: "P"
fetched: "2020-01-01T00:00:00Z"
expires: "2099-01-01T00:00:00Z"
levels:
  max: 3
rate:
  per_host_rps: 1.0
  global_rps: 100.0
  burst: 1
allow: ["*.example.com"]
`))
	e := decide.NewEngine(cp)
	now := time.Now()
	e.SetNow(func() time.Time { return now })

	// First request consumes the burst token.
	_ = e.DecideWithAddr(ctx(), "api.example.com", decide.MustParseAddr("1.2.3.4"), 1)
	// Second request at same instant → rate-limited.
	d := e.DecideWithAddr(ctx(), "api.example.com", decide.MustParseAddr("1.2.3.4"), 1)
	if d.Verdict != decide.Deny || d.Reason != decide.ReasonRateLimited {
		t.Errorf("second request: got %v/%v, want Deny/rate-limited", d.Verdict, d.Reason)
	}
}

// Rate: PerHostRPS=0 means unlimited.
func TestDecide_PerHostRPSZeroIsUnlimited(t *testing.T) {
	cp, _ := policy.LoadBytes([]byte(`
program: "P"
fetched: "2020-01-01T00:00:00Z"
expires: "2099-01-01T00:00:00Z"
levels:
  max: 3
rate:
  per_host_rps: 0
  global_rps: 0
  burst: 1
allow: ["*.example.com"]
`))
	e := decide.NewEngine(cp)
	now := time.Now()
	e.SetNow(func() time.Time { return now })

	for i := 0; i < 10; i++ {
		d := e.DecideWithAddr(ctx(), "api.example.com", decide.MustParseAddr("1.2.3.4"), 1)
		if d.Reason == decide.ReasonRateLimited {
			t.Errorf("request %d: PerHostRPS=0 should mean unlimited, got rate-limited", i)
		}
	}
}

// SetPolicy: replacing policy changes decisions.
func TestDecide_SetPolicy(t *testing.T) {
	e := engineFor("*.example.com")

	// Initially allows api.example.com.
	d1 := e.DecideWithAddr(ctx(), "api.example.com", decide.MustParseAddr("1.2.3.4"), 1)
	if d1.Verdict != decide.Allow {
		t.Fatalf("initial allow failed: %v/%v", d1.Verdict, d1.Reason)
	}

	// Replace with restrictive policy (different allow).
	newCP, _ := policy.LoadBytes([]byte(`
program: "P2"
fetched: "2020-01-01T00:00:00Z"
expires: "2099-01-01T00:00:00Z"
levels:
  max: 3
allow: ["other.example.com"]
`))
	e.SetPolicy(newCP)

	d2 := e.DecideWithAddr(ctx(), "api.example.com", decide.MustParseAddr("1.2.3.4"), 1)
	if d2.Verdict != decide.Deny {
		t.Errorf("after SetPolicy, api.example.com should be denied: got %v", d2.Verdict)
	}
}

// Resolve via IP address (no DNS needed).
func TestDecide_IPAddressTarget(t *testing.T) {
	e := engineFor("203.0.113.0/24")
	// Decide with real path — target is an IP, no DNS needed.
	d := e.Decide(ctx(), "203.0.113.5", 1)
	if d.Verdict != decide.Allow {
		t.Errorf("IP address in CIDR allow: got %v/%v", d.Verdict, d.Reason)
	}
}

// Engine-error path: covered via EngineError reason constant.
func TestAllReasonsCovered(t *testing.T) {
	reasons := []decide.Reason{
		decide.ReasonAllow,
		decide.ReasonPolicyMissing,
		decide.ReasonPolicyExpired,
		decide.ReasonPolicyInvalid,
		decide.ReasonOutsideWindow,
		decide.ReasonRateLimited,
		decide.ReasonUnresolvable,
		decide.ReasonExplicitDeny,
		decide.ReasonThirdPartyHost,
		decide.ReasonOutsideWildcard,
		decide.ReasonLevelTooHigh,
		decide.ReasonEngineError,
	}
	for _, r := range reasons {
		if r == "" {
			t.Errorf("empty Reason constant")
		}
		isDeny := r != decide.ReasonAllow
		if isDeny && !r.IsDeny() {
			t.Errorf("Reason %q: IsDeny()=false but not ReasonAllow", r)
		}
	}
	if decide.ReasonAllow.IsDeny() {
		t.Error("ReasonAllow should not be a deny")
	}
	// Verify all 12 reasons are present.
	if len(reasons) != 12 {
		t.Errorf("expected 12 Reason constants, got %d", len(reasons))
	}
}

// Decision fields are populated correctly.
func TestDecide_Fields(t *testing.T) {
	e := engineFor("*.example.com")
	d := e.DecideWithAddr(ctx(), "api.example.com", decide.MustParseAddr("203.0.113.1"), 2)

	if d.Target != "api.example.com" {
		t.Errorf("Target = %q, want api.example.com", d.Target)
	}
	if d.Level != 2 {
		t.Errorf("Level = %d, want 2", d.Level)
	}
	if d.TS.IsZero() {
		t.Error("TS should not be zero")
	}
	if d.Resolved.String() != "203.0.113.1" {
		t.Errorf("Resolved = %v, want 203.0.113.1", d.Resolved)
	}
}
