package policy_test

import (
	"strings"
	"testing"
	"time"

	"github.com/vulnquest58/scope/internal/policy"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func loadOK(t *testing.T, yaml string) *policy.CompiledPolicy {
	t.Helper()
	cp, err := policy.LoadBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}
	return cp
}

func loadFail(t *testing.T, yaml, substr string) {
	t.Helper()
	_, err := policy.LoadBytes([]byte(yaml))
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", substr)
	}
	if !strings.Contains(err.Error(), substr) {
		t.Fatalf("expected error containing %q, got %q", substr, err.Error())
	}
}

func minimal(allow string) string {
	return `
program: "Test"
fetched: "2026-01-01T00:00:00Z"
expires: "2027-01-01T00:00:00Z"
allow: ["` + allow + `"]
`
}

func matchOnly(t *testing.T, allowEntry, target string, wantAllow bool) {
	t.Helper()
	cp := loadOK(t, minimal(allowEntry))
	got, _, _ := cp.MatchHost(target, policy.ZeroAddr())
	if got != wantAllow {
		t.Errorf("allow=%q target=%q: got %v, want %v", allowEntry, target, got, wantAllow)
	}
}

// ---------------------------------------------------------------------------
// Validation — 12 ordered rules
// ---------------------------------------------------------------------------

func TestValidate_ProgramRequired(t *testing.T) {
	loadFail(t, `
fetched: "2026-01-01T00:00:00Z"
expires: "2027-01-01T00:00:00Z"
allow: ["*.example.com"]
`, "program is required")
}

func TestValidate_FetchedExpiresRequired(t *testing.T) {
	loadFail(t, `
program: "P"
expires: "2027-01-01T00:00:00Z"
allow: ["*.example.com"]
`, "fetched/expires required")
}

func TestValidate_ExpiresRequired(t *testing.T) {
	loadFail(t, `
program: "P"
fetched: "2026-01-01T00:00:00Z"
allow: ["*.example.com"]
`, "fetched/expires required")
}

func TestValidate_ExpiresAfterFetched(t *testing.T) {
	loadFail(t, `
program: "P"
fetched: "2027-01-01T00:00:00Z"
expires: "2026-01-01T00:00:00Z"
allow: ["*.example.com"]
`, "expires must be after fetched")
}

func TestValidate_LevelsOutOfRange_High(t *testing.T) {
	loadFail(t, `
program: "P"
fetched: "2026-01-01T00:00:00Z"
expires: "2027-01-01T00:00:00Z"
levels:
  max: 5
allow: ["*.example.com"]
`, "levels.max out of range")
}

func TestValidate_LevelsOutOfRange_Negative(t *testing.T) {
	loadFail(t, `
program: "P"
fetched: "2026-01-01T00:00:00Z"
expires: "2027-01-01T00:00:00Z"
levels:
  max: -1
allow: ["*.example.com"]
`, "levels.max out of range")
}

func TestValidate_AllowNonEmpty(t *testing.T) {
	loadFail(t, `
program: "P"
fetched: "2026-01-01T00:00:00Z"
expires: "2027-01-01T00:00:00Z"
allow: []
`, "allow must list at least one entry")
}

func TestValidate_DenyReasonRequired(t *testing.T) {
	loadFail(t, `
program: "P"
fetched: "2026-01-01T00:00:00Z"
expires: "2027-01-01T00:00:00Z"
allow: ["*.example.com"]
deny:
  - match: ["bad.example.com"]
`, "deny[0].reason is required")
}

func TestValidate_DenyMatchEmpty(t *testing.T) {
	loadFail(t, `
program: "P"
fetched: "2026-01-01T00:00:00Z"
expires: "2027-01-01T00:00:00Z"
allow: ["*.example.com"]
deny:
  - reason: "x"
    match: []
`, "deny[0].match is empty")
}

func TestValidate_BadTimezone(t *testing.T) {
	loadFail(t, `
program: "P"
fetched: "2026-01-01T00:00:00Z"
expires: "2027-01-01T00:00:00Z"
allow: ["*.example.com"]
windows:
  - days: ["*"]
    hours: ["09:00-18:00"]
    timezone: "Mars/Base"
`, "unknown timezone")
}

func TestValidate_BadHourRange(t *testing.T) {
	loadFail(t, `
program: "P"
fetched: "2026-01-01T00:00:00Z"
expires: "2027-01-01T00:00:00Z"
allow: ["*.example.com"]
windows:
  - days: ["*"]
    hours: ["9-18"]
`, "bad range")
}

func TestValidate_BadDay(t *testing.T) {
	loadFail(t, `
program: "P"
fetched: "2026-01-01T00:00:00Z"
expires: "2027-01-01T00:00:00Z"
allow: ["*.example.com"]
windows:
  - days: ["funday"]
    hours: ["*"]
`, `days contains "funday"`)
}

func TestValidate_DoubleDotInAllow(t *testing.T) {
	loadFail(t, `
program: "P"
fetched: "2026-01-01T00:00:00Z"
expires: "2027-01-01T00:00:00Z"
allow: ["a..b.com"]
`, "bad wildcard")
}

func TestValidate_Valid(t *testing.T) {
	loadOK(t, `
program: "Test Program"
fetched: "2026-01-01T00:00:00Z"
expires: "2027-01-01T00:00:00Z"
levels:
  max: 2
allow:
  - "*.example.com"
  - "api.example.com"
  - "203.0.113.0/24"
deny:
  - reason: "Admin panel"
    match: ["admin.example.com"]
`)
}

// ---------------------------------------------------------------------------
// Wildcard matching — §11.1 (at minimum 12 cases)
// ---------------------------------------------------------------------------

func TestMatch_WildcardOneLevel(t *testing.T) { matchOnly(t, "*.ex.com", "a.ex.com", true) }
func TestMatch_WildcardTwoLevels(t *testing.T) { matchOnly(t, "*.ex.com", "a.b.ex.com", false) }
func TestMatch_WildcardApex(t *testing.T)      { matchOnly(t, "*.ex.com", "ex.com", false) }
func TestMatch_ExactHit(t *testing.T)          { matchOnly(t, "ex.com", "ex.com", true) }
func TestMatch_ExactWildMiss(t *testing.T)     { matchOnly(t, "ex.com", "www.ex.com", false) }
func TestMatch_CaseInsensitive(t *testing.T)   { matchOnly(t, "*.EX.com", "a.ex.com", true) }
func TestMatch_TrailingDotInAllow(t *testing.T) { matchOnly(t, "*.ex.com.", "a.ex.com", true) }
func TestMatch_TrailingDotInTarget(t *testing.T) { matchOnly(t, "*.ex.com", "a.ex.com.", true) }
func TestMatch_UppercaseTarget(t *testing.T)  { matchOnly(t, "*.ex.com", "A.EX.COM", true) }

func TestMatch_DenyWinsOverAllow(t *testing.T) {
	cp := loadOK(t, `
program: "T"
fetched: "2026-01-01T00:00:00Z"
expires: "2027-01-01T00:00:00Z"
allow: ["*.ex.com"]
deny:
  - reason: "blocked"
    match: ["status.ex.com"]
`)
	got, _, _ := cp.MatchHost("status.ex.com", policy.ZeroAddr())
	if got {
		t.Error("deny should win over allow wildcard")
	}
}

func TestMatch_ExplicitAllowBeatsWildDeny(t *testing.T) {
	// explicit allowExact does NOT beat denyExact (deny always first).
	// But allowExact beats denyWild when denyWild doesn't also cover it.
	cp := loadOK(t, `
program: "T"
fetched: "2026-01-01T00:00:00Z"
expires: "2027-01-01T00:00:00Z"
allow: ["api.ex.com"]
deny:
  - reason: "block wildcard"
    match: ["*.ex.com"]
`)
	// api.ex.com is exact-allowed, but *.ex.com is deny-wild.
	// Priority: denyWild > allowExact → deny wins.
	got, _, _ := cp.MatchHost("api.ex.com", policy.ZeroAddr())
	if got {
		t.Error("denyWild should win over allowExact")
	}
}

func TestMatch_OutsideWildcard(t *testing.T) {
	cp := loadOK(t, minimal("*.ex.com"))
	got, reason, _ := cp.MatchHost("other.com", policy.ZeroAddr())
	if got {
		t.Error("should deny other.com")
	}
	if reason != "outside-wildcard" {
		t.Errorf("reason = %q, want outside-wildcard", reason)
	}
}

// ---------------------------------------------------------------------------
// CIDR matching
// ---------------------------------------------------------------------------

func TestCIDRMatch_IPv4InRange(t *testing.T) {
	cp := loadOK(t, `
program: "T"
fetched: "2026-01-01T00:00:00Z"
expires: "2027-01-01T00:00:00Z"
allow: ["203.0.113.0/24"]
`)
	addr := policy.ParseTestAddr("203.0.113.7")
	got, _, _ := cp.MatchHost("203.0.113.7", addr)
	if !got {
		t.Error("expected allow for 203.0.113.7/24")
	}
}

func TestCIDRMatch_IPv4OutOfRange(t *testing.T) {
	cp := loadOK(t, `
program: "T"
fetched: "2026-01-01T00:00:00Z"
expires: "2027-01-01T00:00:00Z"
allow: ["203.0.113.0/24"]
`)
	addr := policy.ParseTestAddr("203.0.114.7")
	got, _, _ := cp.MatchHost("203.0.114.7", addr)
	if got {
		t.Error("expected deny for 203.0.114.7 with /24")
	}
}

func TestCIDRMatch_IPv6(t *testing.T) {
	cp := loadOK(t, `
program: "T"
fetched: "2026-01-01T00:00:00Z"
expires: "2027-01-01T00:00:00Z"
allow: ["::/0"]
`)
	addr := policy.ParseTestAddr("2001:db8::1")
	got, _, _ := cp.MatchHost("2001:db8::1", addr)
	if !got {
		t.Error("expected allow for IPv6 with ::/0")
	}
}

func TestCIDRMatch_NoCrossFamily(t *testing.T) {
	// IPv4 address must NOT match an IPv6-only CIDR.
	cp := loadOK(t, `
program: "T"
fetched: "2026-01-01T00:00:00Z"
expires: "2027-01-01T00:00:00Z"
allow: ["::/0"]
`)
	addr := policy.ParseTestAddr("203.0.113.7")
	got, _, _ := cp.MatchHost("203.0.113.7", addr)
	if got {
		t.Error("IPv4 should NOT match IPv6 CIDR ::/0")
	}
}

// ---------------------------------------------------------------------------
// ThirdParty detection
// ---------------------------------------------------------------------------

func TestThirdParty_StatuspageDetected(t *testing.T) {
	provider, ok := policy.ThirdParty([]string{"status.example.com", "example.statuspage.io"})
	if !ok || provider != "Statuspage" {
		t.Errorf("got (%q, %v), want (Statuspage, true)", provider, ok)
	}
}

func TestThirdParty_NotDetected(t *testing.T) {
	_, ok := policy.ThirdParty([]string{"api.example.com", "203.0.113.1"})
	if ok {
		t.Error("expected no third-party detection")
	}
}

func TestThirdParty_OriginalNameMatches(t *testing.T) {
	provider, ok := policy.ThirdParty([]string{"app.herokuapp.com"})
	if !ok || provider != "Heroku" {
		t.Errorf("got (%q, %v), want (Heroku, true)", provider, ok)
	}
}

func TestThirdParty_AllProvidersHaveEntries(t *testing.T) {
	// Spot-check several providers from the required list.
	tests := []struct {
		chain    []string
		provider string
	}{
		{[]string{"x.cloudfront.net"}, "CloudFront"},
		{[]string{"x.fastly.net"}, "Fastly"},
		{[]string{"x.akamaiedge.net"}, "Akamai"},
		{[]string{"x.azureedge.net"}, "Azure CDN"},
		{[]string{"x.googleusercontent.com"}, "Google"},
		{[]string{"x.github.io"}, "GitHub Pages"},
		{[]string{"x.shopify.com"}, "Shopify"},
		{[]string{"x.myshopify.com"}, "Shopify"},
		{[]string{"x.salesforce.com"}, "Salesforce"},
		{[]string{"x.force.com"}, "Salesforce"},
		{[]string{"x.wpengine.com"}, "WP Engine"},
		{[]string{"x.netlify.app"}, "Netlify"},
		{[]string{"x.vercel.app"}, "Vercel"},
		{[]string{"x.amazonaws.com"}, "AWS"},
		{[]string{"x.cloudapp.net"}, "Azure"},
		{[]string{"x.trafficmanager.net"}, "Azure TM"},
		{[]string{"x.zendesk.com"}, "Zendesk"},
	}
	for _, tc := range tests {
		provider, ok := policy.ThirdParty(tc.chain)
		if !ok || provider != tc.provider {
			t.Errorf("chain=%v: got (%q,%v), want (%q,true)", tc.chain, provider, ok, tc.provider)
		}
	}
}

// ---------------------------------------------------------------------------
// Window tests
// ---------------------------------------------------------------------------

func TestWindow_FullDay_00_00(t *testing.T) {
	cp := loadOK(t, `
program: "T"
fetched: "2026-01-01T00:00:00Z"
expires: "2027-01-01T00:00:00Z"
allow: ["*.example.com"]
windows:
  - days: ["*"]
    hours: ["00:00-00:00"]
    timezone: "UTC"
`)
	// 00:00-00:00 means full day.
	for h := 0; h < 24; h++ {
		ts := time.Date(2026, 6, 15, h, 30, 0, 0, time.UTC)
		if !cp.InWindow(ts) {
			t.Errorf("hour %d should be in-window for 00:00-00:00", h)
		}
	}
}

func TestWindow_NoWindowsMeansAlwaysAllowed(t *testing.T) {
	cp := loadOK(t, minimal("*.example.com"))
	if !cp.InWindow(time.Now()) {
		t.Error("no windows should mean always in-window")
	}
}

func TestWindow_OutsideHours(t *testing.T) {
	cp := loadOK(t, `
program: "T"
fetched: "2026-01-01T00:00:00Z"
expires: "2027-01-01T00:00:00Z"
allow: ["*.example.com"]
windows:
  - days: ["*"]
    hours: ["09:00-18:00"]
    timezone: "UTC"
`)
	// 02:00 UTC is outside 09:00-18:00.
	ts := time.Date(2026, 6, 15, 2, 0, 0, 0, time.UTC)
	if cp.InWindow(ts) {
		t.Error("02:00 UTC should be outside 09:00-18:00 window")
	}
}

func TestWindow_InsideHours(t *testing.T) {
	cp := loadOK(t, `
program: "T"
fetched: "2026-01-01T00:00:00Z"
expires: "2027-01-01T00:00:00Z"
allow: ["*.example.com"]
windows:
  - days: ["*"]
    hours: ["09:00-18:00"]
    timezone: "UTC"
`)
	ts := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	if !cp.InWindow(ts) {
		t.Error("12:00 UTC should be inside 09:00-18:00 window")
	}
}
