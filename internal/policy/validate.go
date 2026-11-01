package policy

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// validDays is the set of valid day names plus the wildcard.
var validDays = map[string]struct{}{
	"*":   {},
	"mon": {},
	"tue": {},
	"wed": {},
	"thu": {},
	"fri": {},
	"sat": {},
	"sun": {},
}

// Validate checks a Policy in the exact order specified and returns the first error.
// Validate returns nil if the policy is valid.
func Validate(p *Policy) error {
	// 2. program non-empty
	if p.Program == "" {
		return fmt.Errorf("policy-invalid: program is required")
	}

	// 3. fetched + expires present (zero value means missing)
	if p.Fetched.IsZero() || p.Expires.IsZero() {
		return fmt.Errorf("policy-invalid: fetched/expires required")
	}

	// 4. expires > fetched
	if !p.Expires.After(p.Fetched) {
		return fmt.Errorf("policy-invalid: expires must be after fetched")
	}

	// 5. levels.max 0..3
	if p.Levels.Max < 0 || p.Levels.Max > 3 {
		return fmt.Errorf("policy-invalid: levels.max out of range")
	}

	// 6. allow non-empty
	if len(p.Allow) == 0 {
		return fmt.Errorf("policy-invalid: allow must list at least one entry")
	}

	// 7. each allow entry parseable
	for i, entry := range p.Allow {
		norm := normalizeName(entry)
		if strings.Contains(norm, "..") {
			return fmt.Errorf("policy-invalid: allow[%d]: bad wildcard %q", i, entry)
		}
		if strings.ContainsRune(norm, '/') {
			if _, err := netip.ParsePrefix(norm); err != nil {
				return fmt.Errorf("policy-invalid: allow[%d]: bad wildcard %q", i, entry)
			}
		} else if strings.HasPrefix(norm, "*.") {
			if _, err := newWildcard(norm); err != nil {
				return fmt.Errorf("policy-invalid: allow[%d]: bad wildcard %q", i, entry)
			}
		} else if norm == "*" {
			// wildcard-all: allowed but log warning (caller logs)
			_ = norm
		} else {
			// Exact hostname — validate it's not pathologically bad.
			// Double-dots already checked above.
			_ = norm
		}
	}

	// 8. each deny[i].reason non-empty
	for i, dr := range p.Deny {
		if dr.Reason == "" {
			return fmt.Errorf("policy-invalid: deny[%d].reason is required", i)
		}
		// 9. each deny[i].match non-empty
		if len(dr.Match) == 0 {
			return fmt.Errorf("policy-invalid: deny[%d].match is empty", i)
		}
	}

	// 10. timezone valid (per window)
	for _, w := range p.Windows {
		tz := w.Timezone
		if tz == "" {
			tz = "UTC"
		}
		if _, err := time.LoadLocation(tz); err != nil {
			return fmt.Errorf("policy-invalid: unknown timezone %q", w.Timezone)
		}
	}

	// 11. hours format HH:MM-HH:MM
	for _, w := range p.Windows {
		for i, h := range w.Hours {
			if h == "*" {
				continue
			}
			if err := validateHourRange(h); err != nil {
				return fmt.Errorf("policy-invalid: hours[%d]: bad range %q", i, h)
			}
		}
	}

	// 12. days from known set
	for _, w := range p.Windows {
		for _, d := range w.Days {
			dl := strings.ToLower(d)
			if _, ok := validDays[dl]; !ok {
				return fmt.Errorf("policy-invalid: days contains %q", d)
			}
		}
	}

	return nil
}

// validateHourRange checks that a string is in HH:MM-HH:MM format.
func validateHourRange(s string) error {
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return fmt.Errorf("bad format")
	}
	if err := validateHHMM(parts[0]); err != nil {
		return err
	}
	if err := validateHHMM(parts[1]); err != nil {
		return err
	}
	return nil
}

// validateHHMM checks that a string is HH:MM format.
func validateHHMM(s string) error {
	if len(s) != 5 || s[2] != ':' {
		return fmt.Errorf("not HH:MM")
	}
	for i, c := range s {
		if i == 2 {
			continue
		}
		if c < '0' || c > '9' {
			return fmt.Errorf("not digit")
		}
	}
	h := int(s[0]-'0')*10 + int(s[1]-'0')
	m := int(s[3]-'0')*10 + int(s[4]-'0')
	if h > 23 || m > 59 {
		return fmt.Errorf("out of range")
	}
	return nil
}
