package policy

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// wildcard represents a compiled *.suffix pattern.
type wildcard struct {
	suffix string // e.g. ".example.com" (with leading dot)
}

// newWildcard parses a "*.example.com" pattern.
// newWildcard returns an error if the pattern is malformed.
func newWildcard(pattern string) (wildcard, error) {
	norm := normalizeName(pattern)
	if !strings.HasPrefix(norm, "*.") {
		return wildcard{}, fmt.Errorf("not a wildcard pattern: %q", pattern)
	}
	suffix := norm[1:] // ".example.com"
	if suffix == "." || suffix == "" {
		return wildcard{}, fmt.Errorf("invalid wildcard pattern: %q", pattern)
	}
	return wildcard{suffix: suffix}, nil
}

// matches reports whether the normalized host matches this wildcard.
// A wildcard *.example.com matches exactly one label prepended to the suffix.
func (w wildcard) matches(host string) bool {
	host = normalizeName(host)
	if !strings.HasSuffix(host, w.suffix) {
		return false
	}
	prefix := host[:len(host)-len(w.suffix)]
	// prefix must be a single label (no dots, non-empty)
	if prefix == "" || strings.ContainsRune(prefix, '.') {
		return false
	}
	return true
}

// MatchHost evaluates a hostname (and optional resolved addr) against a compiled policy.
// MatchHost returns (allow=true, rule) or (allow=false, reason, rule).
// Priority: denyExact > denyWild > denyNets > allowExact > allowWild > allowNets > outside-wildcard.
func (cp *CompiledPolicy) MatchHost(host string, addr netip.Addr) (allow bool, denyReason string, rule string) {
	norm := normalizeName(host)

	// 1. denyExact
	if reason, ok := cp.denyExact[norm]; ok {
		return false, reason, fmt.Sprintf("deny[exact]:%s", norm)
	}

	// 2. denyWild
	for i, wc := range cp.denyWild {
		if wc.matches(norm) {
			return false, "explicit-deny", fmt.Sprintf("deny[%d].wild", i)
		}
	}

	// 3. denyNets
	if addr.IsValid() {
		for i, prefix := range cp.denyNets {
			if prefixMatchesAddr(prefix, addr) {
				return false, "explicit-deny", fmt.Sprintf("deny[%d].net", i)
			}
		}
	}

	// 4. allowExact
	if _, ok := cp.allowExact[norm]; ok {
		return true, "", "allow[exact]"
	}

	// 5. allowWild
	for i, wc := range cp.allowWild {
		if wc.matches(norm) {
			return true, "", fmt.Sprintf("allow[%d].wild", i)
		}
	}

	// 6. allowNets
	if addr.IsValid() {
		for i, prefix := range cp.allowNets {
			if prefixMatchesAddr(prefix, addr) {
				return true, "", fmt.Sprintf("allow[%d].net", i)
			}
		}
	}

	// 7. nothing → outside-wildcard
	return false, "outside-wildcard", ""
}

// IsAllowExact reports whether host is in the allowExact map.
// IsAllowExact is used to check explicit exceptions for third-party detection.
func (cp *CompiledPolicy) IsAllowExact(host string) bool {
	_, ok := cp.allowExact[normalizeName(host)]
	return ok
}

// prefixMatchesAddr checks CIDR membership with cross-family prevention.
func prefixMatchesAddr(prefix netip.Prefix, addr netip.Addr) bool {
	// Unmap IPv4-in-IPv6 for clean comparison.
	addr = addr.Unmap()
	prefixAddr := prefix.Addr().Unmap()

	// No cross-family matching.
	addrIs4 := addr.Is4()
	prefixIs4 := prefixAddr.Is4()
	if addrIs4 != prefixIs4 {
		return false
	}
	// Rebuild prefix with unmaped addr if needed.
	if prefixAddr != prefix.Addr() {
		var err error
		prefix, err = prefixAddr.Prefix(prefix.Bits())
		if err != nil {
			return false
		}
	}
	return prefix.Contains(addr)
}

// InWindow reports whether t is within any of the policy windows.
// InWindow returns true if there are no windows (unrestricted).
func (cp *CompiledPolicy) InWindow(t time.Time) bool {
	if len(cp.policy.Windows) == 0 {
		return true
	}
	for _, w := range cp.policy.Windows {
		if windowContains(w, t) {
			return true
		}
	}
	return false
}

// windowContains reports whether time t falls within window w.
func windowContains(w Window, t time.Time) bool {
	tz := w.Timezone
	if tz == "" {
		tz = "UTC"
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return false // fail-closed
	}
	local := t.In(loc)

	// Check days.
	dayOK := false
	weekday := strings.ToLower(local.Weekday().String()[:3])
	for _, d := range w.Days {
		dl := strings.ToLower(d)
		if dl == "*" || dl == weekday {
			dayOK = true
			break
		}
	}
	if !dayOK {
		return false
	}

	// Check hours.
	if len(w.Hours) == 0 {
		return true
	}
	for _, h := range w.Hours {
		if h == "*" {
			return true
		}
		if hourRangeContains(h, local) {
			return true
		}
	}
	return false
}

// hourRangeContains checks if the time-of-day falls in "HH:MM-HH:MM".
// "00:00-00:00" means full day.
func hourRangeContains(rangeStr string, t time.Time) bool {
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return false
	}
	startH, startM, ok1 := parseHHMM(parts[0])
	endH, endM, ok2 := parseHHMM(parts[1])
	if !ok1 || !ok2 {
		return false
	}

	// 00:00-00:00 means full day.
	if startH == 0 && startM == 0 && endH == 0 && endM == 0 {
		return true
	}

	curMin := t.Hour()*60 + t.Minute()
	startMin := startH*60 + startM
	endMin := endH*60 + endM

	if startMin <= endMin {
		return curMin >= startMin && curMin < endMin
	}
	// Wrap-around (e.g. 22:00-06:00)
	return curMin >= startMin || curMin < endMin
}

// parseHHMM parses "HH:MM" and returns (hour, minute, ok).
func parseHHMM(s string) (int, int, bool) {
	if len(s) != 5 || s[2] != ':' {
		return 0, 0, false
	}
	h := int(s[0]-'0')*10 + int(s[1]-'0')
	m := int(s[3]-'0')*10 + int(s[4]-'0')
	return h, m, true
}
