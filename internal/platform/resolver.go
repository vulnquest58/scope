package platform

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/vulnquest58/scope/internal/policy"
)

// Result is the outcome of a platform search for a domain.
type Result struct {
	Scopes   []ProgramScope
	Errors   map[string]error // platform name → error
	Domain   string
	Duration time.Duration
}

// Found reports whether at least one program was found for the domain.
func (r *Result) Found() bool { return len(r.Scopes) > 0 }

// Policy compiles the merged scope into an enforceable CompiledPolicy.
// Policy returns an error if the merged scope is invalid.
func (r *Result) Policy() (*policy.CompiledPolicy, error) {
	if len(r.Scopes) == 0 {
		return nil, fmt.Errorf("no programs found for domain %q", r.Domain)
	}
	p := MergeScopes(r.Scopes)
	return policy.Compile(&p)
}

// Summary returns a human-readable summary of the search result.
func (r *Result) Summary() string {
	if !r.Found() {
		return fmt.Sprintf("⚠  %s not found in any active bug-bounty program", r.Domain)
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("✅ Found %d program(s) for %s:\n", len(r.Scopes), r.Domain))
	for _, s := range r.Scopes {
		sb.WriteString(fmt.Sprintf("   • [%s] %s (%s)\n", strings.ToUpper(s.Platform), s.Name, s.URL))
		sb.WriteString(fmt.Sprintf("     In-scope: %d entries, Out-of-scope: %d entries\n",
			len(s.Allow), len(s.Deny)))
	}
	if len(r.Errors) > 0 {
		sb.WriteString("   Warnings:\n")
		for p, err := range r.Errors {
			sb.WriteString(fmt.Sprintf("   ⚠ %s: %v\n", p, err))
		}
	}
	return sb.String()
}

// Resolver searches multiple providers concurrently for a domain.
type Resolver struct {
	providers []Provider
}

// NewResolver creates a Resolver with the given providers.
// NewResolver uses All() if providers is nil.
func NewResolver(providers []Provider) *Resolver {
	if providers == nil {
		providers = All()
	}
	return &Resolver{providers: providers}
}

// Search queries all providers concurrently for programs covering domain.
// Search returns a Result containing all matches and any per-provider errors.
func (r *Resolver) Search(domain string) *Result {
	start := time.Now()
	result := &Result{
		Domain: domain,
		Errors: make(map[string]error),
	}

	type providerResult struct {
		name   string
		scopes []ProgramScope
		err    error
	}

	ch := make(chan providerResult, len(r.providers))
	var wg sync.WaitGroup

	for _, p := range r.providers {
		wg.Add(1)
		go func(prov Provider) {
			defer wg.Done()
			scopes, err := prov.FindByDomain(domain)
			ch <- providerResult{name: prov.Name(), scopes: scopes, err: err}
		}(p)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	var mu sync.Mutex
	for pr := range ch {
		mu.Lock()
		if pr.err != nil {
			result.Errors[pr.name] = pr.err
		} else {
			result.Scopes = append(result.Scopes, pr.scopes...)
		}
		mu.Unlock()
	}

	result.Duration = time.Since(start)
	return result
}

// FilterByPlatforms returns a new Resolver limited to specific platform names.
// FilterByPlatforms accepts comma-separated names like "hackerone,bugcrowd".
func FilterByPlatforms(names string) *Resolver {
	wanted := make(map[string]struct{})
	for _, n := range strings.Split(names, ",") {
		wanted[strings.TrimSpace(strings.ToLower(n))] = struct{}{}
	}
	var filtered []Provider
	for _, p := range All() {
		if _, ok := wanted[p.Name()]; ok {
			filtered = append(filtered, p)
		}
	}
	return NewResolver(filtered)
}
