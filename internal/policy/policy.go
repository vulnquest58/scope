// Package policy implements the scope policy model, loading, validation and matching.
package policy

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Policy is the top-level structure loaded from a scope policy YAML file.
type Policy struct {
	Program string     `yaml:"program"`
	Fetched time.Time  `yaml:"fetched"`
	Expires time.Time  `yaml:"expires"`
	Levels  Levels     `yaml:"levels"`
	Windows []Window   `yaml:"windows"`
	Rate    Rate       `yaml:"rate"`
	Allow   []string   `yaml:"allow"`
	Deny    []DenyRule `yaml:"deny"`
}

// Levels holds the maximum severity level permitted by the policy.
type Levels struct {
	Max int `yaml:"max"`
}

// Window defines a time window in which testing is permitted.
type Window struct {
	Days     []string `yaml:"days"`
	Hours    []string `yaml:"hours"`
	Timezone string   `yaml:"timezone"`
}

// Rate holds token-bucket parameters for the rate limiter.
type Rate struct {
	PerHostRPS float64 `yaml:"per_host_rps"`
	GlobalRPS  float64 `yaml:"global_rps"`
	Burst      int     `yaml:"burst"`
}

// DenyRule is an explicit deny entry in the policy.
type DenyRule struct {
	Reason string   `yaml:"reason"`
	Match  []string `yaml:"match"`
}

// CompiledPolicy is the exported compiled form of a Policy.
type CompiledPolicy struct {
	policy     Policy
	allowExact map[string]struct{}
	allowWild  []wildcard
	allowNets  []netip.Prefix
	denyWild   []wildcard
	denyNets   []netip.Prefix
	denyExact  map[string]string // host -> reason
	location   *time.Location
}

// GetPolicy returns the underlying Policy struct.
// GetPolicy is used to access raw policy fields.
func (cp *CompiledPolicy) GetPolicy() *Policy {
	return &cp.policy
}

// Load reads a policy YAML file from disk and returns a CompiledPolicy.
// Load validates the policy and returns an error if it is invalid.
func Load(path string) (*CompiledPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy-missing: %w", err)
	}
	return LoadBytes(data)
}

// LoadBytes parses and validates a policy from raw YAML bytes.
// LoadBytes returns a CompiledPolicy or a validation error.
func LoadBytes(data []byte) (*CompiledPolicy, error) {
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("policy-invalid: yaml: %s", err.Error())
	}
	if err := Validate(&p); err != nil {
		return nil, err
	}
	return Compile(&p)
}

// Compile builds a CompiledPolicy from a validated Policy.
// Compile returns an error if the allow/deny entries are malformed.
func Compile(p *Policy) (*CompiledPolicy, error) {
	cp := &CompiledPolicy{
		policy:     *p,
		allowExact: make(map[string]struct{}),
		denyExact:  make(map[string]string),
		location:   time.UTC,
	}

	// Set location from first window that has a timezone.
	for _, w := range p.Windows {
		if w.Timezone != "" {
			l, err := time.LoadLocation(w.Timezone)
			if err == nil {
				cp.location = l
				break
			}
		}
	}

	// Parse allow list.
	for _, entry := range p.Allow {
		norm := normalizeName(entry)
		if strings.ContainsRune(norm, '/') {
			// CIDR.
			prefix, err := netip.ParsePrefix(norm)
			if err != nil {
				return nil, fmt.Errorf("policy-invalid: allow: bad CIDR %q: %w", entry, err)
			}
			cp.allowNets = append(cp.allowNets, prefix)
		} else if strings.HasPrefix(norm, "*.") {
			wc, err := newWildcard(norm)
			if err != nil {
				return nil, fmt.Errorf("policy-invalid: allow: bad wildcard %q", entry)
			}
			cp.allowWild = append(cp.allowWild, wc)
		} else {
			cp.allowExact[norm] = struct{}{}
		}
	}

	// Parse deny list.
	for i, dr := range p.Deny {
		for _, m := range dr.Match {
			norm := normalizeName(m)
			if strings.ContainsRune(norm, '/') {
				prefix, err := netip.ParsePrefix(norm)
				if err != nil {
					return nil, fmt.Errorf("policy-invalid: deny[%d]: bad CIDR %q", i, m)
				}
				cp.denyNets = append(cp.denyNets, prefix)
			} else if strings.HasPrefix(norm, "*.") {
				wc, err := newWildcard(norm)
				if err != nil {
					return nil, fmt.Errorf("policy-invalid: deny[%d]: bad wildcard %q", i, m)
				}
				cp.denyWild = append(cp.denyWild, wc)
			} else {
				// exact deny
				cp.denyExact[norm] = dr.Reason
			}
		}
	}

	return cp, nil
}

// normalizeName lowercases a hostname/CIDR and removes a trailing dot.
func normalizeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimRight(s, ".")
	return s
}
