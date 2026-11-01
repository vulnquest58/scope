// Package decide contains the decision engine for the scope enforcement layer.
package decide

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/vulnquest58/scope/internal/policy"
)

// Verdict indicates whether a request is allowed or denied.
type Verdict int

const (
	// Allow indicates the request is permitted.
	Allow Verdict = iota
	// Deny indicates the request is not permitted.
	Deny
)

// Decision is the outcome of a single Engine.Decide call.
type Decision struct {
	Verdict  Verdict
	Reason   Reason
	Rule     string
	Target   string
	Resolved netip.Addr
	Level    int
	TS       time.Time
}

// resolverCache caches DNS resolution results.
type resolverCache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	ttl     time.Duration // 300s fixed
}

type cacheEntry struct {
	addrs  []netip.Addr
	chain  []string
	expiry time.Time
}

// Engine is the scope decision engine.
type Engine struct {
	mu      sync.RWMutex
	cp      *policy.CompiledPolicy
	limiter *RateLimiter
	cache   *resolverCache
	now     func() time.Time // injectable for testing
}

// NewEngine creates a new Engine with the given compiled policy.
// NewEngine returns a ready-to-use Engine.
func NewEngine(cp *policy.CompiledPolicy) *Engine {
	p := cp.GetPolicy()
	limiter := NewRateLimiter(p.Rate.PerHostRPS, p.Rate.GlobalRPS, p.Rate.Burst)
	return &Engine{
		cp:      cp,
		limiter: limiter,
		cache: &resolverCache{
			entries: make(map[string]cacheEntry),
			ttl:     300 * time.Second,
		},
		now: time.Now,
	}
}

// NewEngineEmpty creates an Engine with no policy loaded (all decisions → policy-missing).
// NewEngineEmpty is useful for testing.
func NewEngineEmpty() *Engine {
	return &Engine{
		cache: &resolverCache{
			entries: make(map[string]cacheEntry),
			ttl:     300 * time.Second,
		},
		now: time.Now,
	}
}

// SetPolicy replaces the current policy. It is safe for concurrent use.
// SetPolicy rebuilds the rate limiter with the new policy's rate settings.
func (e *Engine) SetPolicy(cp *policy.CompiledPolicy) {
	p := cp.GetPolicy()
	limiter := NewRateLimiter(p.Rate.PerHostRPS, p.Rate.GlobalRPS, p.Rate.Burst)
	e.mu.Lock()
	e.cp = cp
	e.limiter = limiter
	e.mu.Unlock()
}

// Decide evaluates target at the given level and returns a Decision.
// Decide never returns an error; all failures are expressed as Deny with an appropriate Reason.
func (e *Engine) Decide(ctx context.Context, target string, level int) Decision {
	now := e.now()
	base := Decision{
		Target: target,
		Level:  level,
		TS:     now,
	}

	deny := func(r Reason, rule string) Decision {
		d := base
		d.Verdict = Deny
		d.Reason = r
		d.Rule = rule
		return d
	}
	allowD := func(rule string, addr netip.Addr) Decision {
		d := base
		d.Verdict = Allow
		d.Reason = ReasonAllow
		d.Rule = rule
		d.Resolved = addr
		return d
	}

	// 1. Policy not loaded.
	e.mu.RLock()
	cp := e.cp
	limiter := e.limiter
	e.mu.RUnlock()
	if cp == nil {
		return deny(ReasonPolicyMissing, "")
	}

	// 2. Validation — re-validate to catch any runtime corruption (fail-closed).
	p := cp.GetPolicy()
	if err := policy.Validate(p); err != nil {
		return deny(ReasonPolicyInvalid, err.Error())
	}

	// 3. Expires check.
	if now.After(p.Expires) {
		return deny(ReasonPolicyExpired, "expires")
	}

	// 4. Clock skew check (now < Fetched).
	if now.Before(p.Fetched) {
		return deny(ReasonPolicyExpired, "fetched-skew")
	}

	// 5. Outside window.
	if !cp.InWindow(now) {
		return deny(ReasonOutsideWindow, "window")
	}

	// 6. Rate limit — normalize host for rate key.
	normHost := normalizeTarget(target)
	if !limiter.Allow(normHost, now) {
		return deny(ReasonRateLimited, "rate")
	}

	// 7. Level check.
	if level > p.Levels.Max {
		return deny(ReasonLevelTooHigh, fmt.Sprintf("levels.max=%d", p.Levels.Max))
	}

	// 8. Resolve name.
	addrs, chain, err := e.resolve(ctx, normHost)
	if err != nil || len(addrs) == 0 {
		return deny(ReasonUnresolvable, "dns")
	}
	addr := addrs[0]

	// 9–11. Deny checks (exact, wild, nets).
	ok, denyReason, rule := cp.MatchHost(normHost, addr)
	if !ok {
		switch denyReason {
		case "outside-wildcard":
			return deny(ReasonOutsideWildcard, rule)
		default:
			return deny(ReasonExplicitDeny, rule)
		}
	}

	// 12. CNAME chain third-party check.
	// Explicit exception (allowExact) wins over provider detection.
	if !cp.IsAllowExact(normHost) {
		if provider, isThird := policy.ThirdParty(chain); isThird {
			return deny(ReasonThirdPartyHost, provider)
		}
	}

	// 13–15. Allow (already determined in MatchHost step above).
	d := allowD(rule, addr)
	d.Resolved = addr
	return d
}

// resolve resolves a hostname using the system resolver with a 300s cache.
func (e *Engine) resolve(ctx context.Context, host string) ([]netip.Addr, []string, error) {
	// Check cache first.
	e.cache.mu.RLock()
	entry, found := e.cache.entries[host]
	e.cache.mu.RUnlock()
	if found && time.Now().Before(entry.expiry) {
		return entry.addrs, entry.chain, nil
	}

	// Try to parse as IP address directly.
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr}, []string{host}, nil
	}

	// Resolve using system resolver.
	resolver := &net.Resolver{}
	ips, err := resolver.LookupHost(ctx, host)
	if err != nil {
		return nil, nil, err
	}

	var addrs []netip.Addr
	for _, ip := range ips {
		a, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		addrs = append(addrs, a)
	}
	if len(addrs) == 0 {
		return nil, nil, fmt.Errorf("no valid addresses for %s", host)
	}

	// Resolve CNAME chain.
	chain := []string{host}
	cname, err := resolver.LookupCNAME(ctx, host)
	if err == nil {
		cname = normalizeName(cname)
		if cname != host {
			chain = append(chain, cname)
		}
	}

	// Cache successful results only.
	e.cache.mu.Lock()
	e.cache.entries[host] = cacheEntry{
		addrs:  addrs,
		chain:  chain,
		expiry: time.Now().Add(e.cache.ttl),
	}
	e.cache.mu.Unlock()

	return addrs, chain, nil
}

// normalizeTarget lowercases and strips trailing dots from the target.
func normalizeTarget(s string) string {
	n := normalizeName(s)
	return n
}

// normalizeName lowercases and strips trailing dots (package-level helper).
func normalizeName(s string) string {
	for len(s) > 0 && s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	result := make([]byte, len(s))
	for i := range s {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		result[i] = c
	}
	return string(result)
}

// SetNow replaces the engine's clock function (for testing).
func (e *Engine) SetNow(fn func() time.Time) {
	e.mu.Lock()
	e.now = fn
	e.mu.Unlock()
}

// MustParseAddr parses an IP address string and panics on error (for tests).
func MustParseAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic("MustParseAddr: " + err.Error())
	}
	return a
}

// DecideWithAddr evaluates target using a pre-resolved addr, bypassing DNS (for testing).
func (e *Engine) DecideWithAddr(ctx context.Context, target string, addr netip.Addr, level int) Decision {
	return e.DecideWithAddrAndChain(ctx, target, addr, []string{target}, level)
}

// DecideWithAddrAndChain evaluates target with a pre-resolved addr and CNAME chain (for testing).
func (e *Engine) DecideWithAddrAndChain(ctx context.Context, target string, addr netip.Addr, chain []string, level int) Decision {
	now := e.now()
	base := Decision{Target: target, Level: level, TS: now}
	deny := func(r Reason, rule string) Decision {
		d := base
		d.Verdict = Deny
		d.Reason = r
		d.Rule = rule
		return d
	}
	allowD := func(rule string) Decision {
		d := base
		d.Verdict = Allow
		d.Reason = ReasonAllow
		d.Rule = rule
		d.Resolved = addr
		return d
	}

	e.mu.RLock()
	cp := e.cp
	limiter := e.limiter
	e.mu.RUnlock()
	if cp == nil {
		return deny(ReasonPolicyMissing, "")
	}

	p := cp.GetPolicy()
	if err := policy.Validate(p); err != nil {
		return deny(ReasonPolicyInvalid, err.Error())
	}
	if now.After(p.Expires) {
		return deny(ReasonPolicyExpired, "expires")
	}
	if now.Before(p.Fetched) {
		return deny(ReasonPolicyExpired, "fetched-skew")
	}
	if !cp.InWindow(now) {
		return deny(ReasonOutsideWindow, "window")
	}

	normHost := normalizeTarget(target)
	if !limiter.Allow(normHost, now) {
		return deny(ReasonRateLimited, "rate")
	}
	if level > p.Levels.Max {
		return deny(ReasonLevelTooHigh, fmt.Sprintf("levels.max=%d", p.Levels.Max))
	}

	// Deny checks.
	ok, denyReason, rule := cp.MatchHost(normHost, addr)
	if !ok {
		switch denyReason {
		case "outside-wildcard":
			return deny(ReasonOutsideWildcard, rule)
		default:
			return deny(ReasonExplicitDeny, rule)
		}
	}

	// Third-party check (skipped if explicit exception).
	if !cp.IsAllowExact(normHost) {
		if provider, isThird := policy.ThirdParty(chain); isThird {
			return deny(ReasonThirdPartyHost, provider)
		}
	}

	return allowD(rule)
}
