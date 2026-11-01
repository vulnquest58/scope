// Package platform provides clients for bug-bounty platform scope APIs.
// It fetches program scope from HackerOne, Bugcrowd, Intigriti, and YesWeHack,
// then converts it to a scope policy.Policy ready for enforcement.
package platform

import (
	"time"

	"github.com/vulnquest58/scope/internal/policy"
)

// ProgramScope holds the resolved scope for a single bug-bounty program.
type ProgramScope struct {
	Platform    string    // "hackerone" | "bugcrowd" | "intigriti" | "yeswehack"
	Handle      string    // program slug / handle
	Name        string    // human-readable program name
	URL         string    // program URL
	Allow       []string  // in-scope wildcards, hostnames, CIDRs
	Deny        []string  // explicitly out-of-scope
	MaxSeverity string    // "critical" | "high" | "medium" | "low" | "informational"
	FetchedAt   time.Time
}

// Provider is implemented by each platform client.
type Provider interface {
	// Name returns the platform identifier.
	Name() string
	// FindByDomain searches for programs whose scope includes domain.
	// domain should be a bare hostname, e.g. "api.example.com".
	FindByDomain(domain string) ([]ProgramScope, error)
}

// All returns a slice of all built-in providers, authenticated where env vars
// are set. Providers are tried concurrently by Resolver.
func All() []Provider {
	return []Provider{
		NewHackerOne(),
		NewBugcrowd(),
		NewIntigriti(),
		NewYesWeHack(),
	}
}

// ToPolicy converts a ProgramScope to a compilable policy.Policy.
// ToPolicy sets Fetched = now, Expires = now + 24h.
func ToPolicy(ps ProgramScope) policy.Policy {
	now := time.Now().UTC()

	// Map MaxSeverity to Levels.Max.
	levelMax := 2
	switch ps.MaxSeverity {
	case "critical":
		levelMax = 3
	case "high":
		levelMax = 2
	case "medium":
		levelMax = 1
	case "low", "informational":
		levelMax = 0
	}

	allow := ps.Allow
	if len(allow) == 0 {
		allow = []string{"0.0.0.0/32"} // effectively deny-all if no scope
	}

	var deny []policy.DenyRule
	if len(ps.Deny) > 0 {
		deny = append(deny, policy.DenyRule{
			Reason: "Explicitly out of scope per " + ps.Platform,
			Match:  ps.Deny,
		})
	}

	return policy.Policy{
		Program: ps.Name + " (" + ps.Platform + ":" + ps.Handle + ")",
		Fetched: now,
		Expires: now.Add(24 * time.Hour),
		Levels:  policy.Levels{Max: levelMax},
		Rate: policy.Rate{
			PerHostRPS: 5,
			GlobalRPS:  20,
			Burst:      10,
		},
		Allow: allow,
		Deny:  deny,
	}
}

// MergeScopes merges multiple ProgramScope entries into one combined policy.
// MergeScopes is used when a domain appears in multiple programs.
func MergeScopes(scopes []ProgramScope) policy.Policy {
	if len(scopes) == 0 {
		return policy.Policy{}
	}
	if len(scopes) == 1 {
		return ToPolicy(scopes[0])
	}

	// Collect all allow/deny, take the most permissive level.
	var allowAll []string
	var denyAll []string
	levelMax := 0
	names := ""
	now := time.Now().UTC()

	for i, s := range scopes {
		allowAll = append(allowAll, s.Allow...)
		denyAll = append(denyAll, s.Deny...)
		l := severityToLevel(s.MaxSeverity)
		if l > levelMax {
			levelMax = l
		}
		if i > 0 {
			names += " + "
		}
		names += s.Name
	}

	if len(allowAll) == 0 {
		allowAll = []string{"0.0.0.0/32"}
	}

	var deny []policy.DenyRule
	if len(denyAll) > 0 {
		deny = append(deny, policy.DenyRule{
			Reason: "Out of scope across merged programs",
			Match:  unique(denyAll),
		})
	}

	return policy.Policy{
		Program: names,
		Fetched: now,
		Expires: now.Add(24 * time.Hour),
		Levels:  policy.Levels{Max: levelMax},
		Rate:    policy.Rate{PerHostRPS: 5, GlobalRPS: 20, Burst: 10},
		Allow:   unique(allowAll),
		Deny:    deny,
	}
}

func severityToLevel(s string) int {
	switch s {
	case "critical":
		return 3
	case "high":
		return 2
	case "medium":
		return 1
	default:
		return 0
	}
}

func unique(ss []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, s := range ss {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

