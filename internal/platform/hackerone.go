package platform

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// HackerOne fetches scope from the HackerOne public directory API.
// Set HACKERONE_API_USER + HACKERONE_API_TOKEN for authenticated access
// (required for private programs).
type HackerOne struct {
	apiUser  string
	apiToken string
	client   *http.Client
}

// NewHackerOne creates a HackerOne provider.
// NewHackerOne reads HACKERONE_API_USER and HACKERONE_API_TOKEN from env.
func NewHackerOne() *HackerOne {
	return &HackerOne{
		apiUser:  os.Getenv("HACKERONE_API_USER"),
		apiToken: os.Getenv("HACKERONE_API_TOKEN"),
		client:   &http.Client{Timeout: 15 * time.Second},
	}
}

// Name returns the provider identifier.
func (h *HackerOne) Name() string { return "hackerone" }

// h1Program is a partial HackerOne program structure from the directory API.
type h1Program struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		Handle             string `json:"handle"`
		Name               string `json:"name"`
		URL                string `json:"url"`
		OffersBounties     bool   `json:"offers_bounties"`
		SubmissionState    string `json:"submission_state"`
		ResponseEfficiency string `json:"response_efficiency_percentage"`
	} `json:"attributes"`
	Relationships struct {
		StructuredScopes struct {
			Data []struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			} `json:"data"`
		} `json:"structured_scopes"`
	} `json:"relationships"`
}

type h1DirectoryResp struct {
	Data  []h1Program `json:"data"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
}

type h1ScopeAsset struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		AssetType       string `json:"asset_type"`
		AssetIdentifier string `json:"asset_identifier"`
		EligibleForBounty bool `json:"eligible_for_bounty"`
		EligibleForSubmission bool `json:"eligible_for_submission"`
		Instruction     string `json:"instruction"`
		MaxSeverity     string `json:"max_severity"`
		OutOfScope      bool   `json:"out_of_scope"`
	} `json:"attributes"`
}

type h1ScopeResp struct {
	Data []h1ScopeAsset `json:"data"`
}

// FindByDomain searches HackerOne public programs for those that include domain.
// FindByDomain returns a slice of matching ProgramScope entries.
func (h *HackerOne) FindByDomain(domain string) ([]ProgramScope, error) {
	// Fetch programs from directory. We search by domain suffix matching.
	// Use the public /programs endpoint (no auth needed for public programs).
	baseURL := "https://api.hackerone.com/v1/hackers/programs?page[size]=100"
	if h.apiUser != "" && h.apiToken != "" {
		baseURL += "&submission_state=open"
	}

	var matches []ProgramScope
	nextURL := baseURL

	for nextURL != "" {
		programs, next, err := h.fetchProgramPage(nextURL)
		if err != nil {
			return nil, fmt.Errorf("hackerone: fetch programs: %w", err)
		}

		for _, prog := range programs {
			if prog.Attributes.SubmissionState != "open" {
				continue
			}
			scope, err := h.fetchProgramScope(prog.Attributes.Handle)
			if err != nil {
				continue // skip on error
			}
			ps := h.matchDomain(domain, prog, scope)
			if ps != nil {
				matches = append(matches, *ps)
			}
		}

		// Limit to first page for anonymous access to avoid rate limits.
		if h.apiUser == "" {
			break
		}
		nextURL = next
	}

	return matches, nil
}

func (h *HackerOne) fetchProgramPage(url string) ([]h1Program, string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/json")
	if h.apiUser != "" && h.apiToken != "" {
		req.SetBasicAuth(h.apiUser, h.apiToken)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, "", fmt.Errorf("hackerone: authentication required (set HACKERONE_API_USER + HACKERONE_API_TOKEN)")
	}
	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("hackerone: HTTP %d for %s", resp.StatusCode, url)
	}

	var result h1DirectoryResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, "", err
	}
	return result.Data, result.Links.Next, nil
}

func (h *HackerOne) fetchProgramScope(handle string) ([]h1ScopeAsset, error) {
	url := fmt.Sprintf("https://api.hackerone.com/v1/hackers/programs/%s/structured_scopes?page[size]=100", handle)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if h.apiUser != "" && h.apiToken != "" {
		req.SetBasicAuth(h.apiUser, h.apiToken)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("scope HTTP %d", resp.StatusCode)
	}

	var result h1ScopeResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Data, nil
}

func (h *HackerOne) matchDomain(domain string, prog h1Program, assets []h1ScopeAsset) *ProgramScope {
	var allow, deny []string
	maxSeverity := "medium"
	found := false

	for _, a := range assets {
		typ := a.Attributes.AssetType
		ident := normalizeScopeEntry(a.Attributes.AssetIdentifier)

		// Only consider URL/WILDCARD/DOMAIN assets.
		if typ != "URL" && typ != "WILDCARD" && typ != "DOMAIN" && typ != "url" {
			continue
		}

		host := extractHostFromEntry(ident)
		if host == "" {
			continue
		}

		if a.Attributes.OutOfScope || !a.Attributes.EligibleForSubmission {
			deny = append(deny, host)
			continue
		}

		allow = append(allow, host)
		if domainMatchesEntry(domain, host) {
			found = true
		}
		if a.Attributes.MaxSeverity != "" {
			maxSeverity = a.Attributes.MaxSeverity
		}
	}

	if !found {
		return nil
	}

	return &ProgramScope{
		Platform:    "hackerone",
		Handle:      prog.Attributes.Handle,
		Name:        prog.Attributes.Name,
		URL:         "https://hackerone.com/" + prog.Attributes.Handle,
		Allow:       allow,
		Deny:        deny,
		MaxSeverity: maxSeverity,
		FetchedAt:   time.Now(),
	}
}

// normalizeScopeEntry lowercases and strips trailing slashes.
func normalizeScopeEntry(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimRight(s, "/")
	return s
}

// extractHostFromEntry extracts a hostname/wildcard from a scope entry.
// e.g. "https://api.example.com/v1" → "api.example.com"
// "*.example.com" → "*.example.com"
func extractHostFromEntry(entry string) string {
	// Remove protocol.
	entry = strings.TrimPrefix(entry, "https://")
	entry = strings.TrimPrefix(entry, "http://")
	// Take only the host part.
	if idx := strings.Index(entry, "/"); idx >= 0 {
		entry = entry[:idx]
	}
	// Remove port.
	if idx := strings.LastIndex(entry, ":"); idx >= 0 && idx > strings.LastIndex(entry, ".") {
		entry = entry[:idx]
	}
	return entry
}

// domainMatchesEntry checks if domain falls under entry (exact, wildcard, or parent).
func domainMatchesEntry(domain, entry string) bool {
	domain = strings.ToLower(strings.TrimRight(domain, "."))
	entry = strings.ToLower(strings.TrimRight(entry, "."))

	if entry == domain {
		return true
	}
	// Wildcard: *.example.com matches api.example.com and example.com.
	if strings.HasPrefix(entry, "*.") {
		suffix := entry[1:] // ".example.com"
		return strings.HasSuffix(domain, suffix) || domain == entry[2:]
	}
	// Parent domain: "example.com" covers "api.example.com".
	if strings.HasSuffix(domain, "."+entry) {
		return true
	}
	return false
}

