package platform

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// Bugcrowd fetches scope from the Bugcrowd public program API.
// Set BUGCROWD_API_TOKEN for authenticated access.
type Bugcrowd struct {
	apiToken string
	client   *http.Client
}

// NewBugcrowd creates a Bugcrowd provider.
func NewBugcrowd() *Bugcrowd {
	return &Bugcrowd{
		apiToken: os.Getenv("BUGCROWD_API_TOKEN"),
		client:   &http.Client{Timeout: 15 * time.Second},
	}
}

// Name returns the provider identifier.
func (b *Bugcrowd) Name() string { return "bugcrowd" }

type bcProgram struct {
	Code        string `json:"code"`
	Name        string `json:"name"`
	ProgramURL  string `json:"program_url"`
	TagLine     string `json:"tagline"`
	MaxPayout   int    `json:"max_payout"`
	Targets     struct {
		InScope  []bcTarget `json:"in_scope"`
		OutOfScope []bcTarget `json:"out_of_scope"`
	} `json:"targets"`
}

type bcTarget struct {
	Name string `json:"name"`
	URI  string `json:"uri"`
	Type string `json:"type"` // "website","api","mobile","other"
}

type bcListResp struct {
	Programs []bcProgram `json:"programs"`
}

// FindByDomain searches Bugcrowd programs for those covering domain.
func (b *Bugcrowd) FindByDomain(domain string) ([]ProgramScope, error) {
	url := "https://bugcrowd.com/programs.json?sort[]=promoted-desc&hidden[]=false&page[number]=1&page[size]=100"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "scope-enforcement/0.1")
	if b.apiToken != "" {
		req.Header.Set("Authorization", "Token "+b.apiToken)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bugcrowd: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("bugcrowd: HTTP %d", resp.StatusCode)
	}

	var result bcListResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("bugcrowd: decode: %w", err)
	}

	var matches []ProgramScope
	for _, prog := range result.Programs {
		ps := b.matchDomain(domain, prog)
		if ps != nil {
			matches = append(matches, *ps)
		}
	}
	return matches, nil
}

func (b *Bugcrowd) matchDomain(domain string, prog bcProgram) *ProgramScope {
	var allow, deny []string
	found := false

	for _, t := range prog.Targets.InScope {
		if t.Type != "website" && t.Type != "api" && t.Type != "" {
			continue
		}
		host := extractHostFromEntry(normalizeScopeEntry(t.URI))
		if host == "" {
			host = extractHostFromEntry(normalizeScopeEntry(t.Name))
		}
		if host == "" {
			continue
		}
		allow = append(allow, host)
		if domainMatchesEntry(domain, host) {
			found = true
		}
	}

	for _, t := range prog.Targets.OutOfScope {
		host := extractHostFromEntry(normalizeScopeEntry(t.URI))
		if host == "" {
			host = extractHostFromEntry(normalizeScopeEntry(t.Name))
		}
		if host != "" {
			deny = append(deny, host)
		}
	}

	if !found {
		return nil
	}

	return &ProgramScope{
		Platform:    "bugcrowd",
		Handle:      prog.Code,
		Name:        prog.Name,
		URL:         "https://bugcrowd.com/" + prog.Code,
		Allow:       allow,
		Deny:        deny,
		MaxSeverity: "high",
		FetchedAt:   time.Now(),
	}
}

// ─────────────────────────────────────────────────────────────────────────────

// Intigriti fetches scope from the Intigriti public API.
// Set INTIGRITI_API_TOKEN for authenticated access.
type Intigriti struct {
	apiToken string
	client   *http.Client
}

// NewIntigriti creates an Intigriti provider.
func NewIntigriti() *Intigriti {
	return &Intigriti{
		apiToken: os.Getenv("INTIGRITI_API_TOKEN"),
		client:   &http.Client{Timeout: 15 * time.Second},
	}
}

// Name returns the provider identifier.
func (i *Intigriti) Name() string { return "intigriti" }

type intigritiProgram struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Handle      string `json:"handle"`
	CompanyName string `json:"companyName"`
	Domains     []struct {
		Endpoint string `json:"endpoint"`
		Type     string `json:"type"` // "url","cidr","other"
		InScope  bool   `json:"inScope"`
		Bounty   bool   `json:"bounty"`
	} `json:"domains"`
	MaxBounty   float64 `json:"maxBounty"`
	MinBounty   float64 `json:"minBounty"`
	Status      string  `json:"status"` // "open","closed"
}

// FindByDomain searches Intigriti programs for those covering domain.
func (i *Intigriti) FindByDomain(domain string) ([]ProgramScope, error) {
	url := "https://api.intigriti.com/core/public/programs?limit=100&status=open"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "scope-enforcement/0.1")
	if i.apiToken != "" {
		req.Header.Set("Authorization", "Bearer "+i.apiToken)
	}

	resp, err := i.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("intigriti: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("intigriti: HTTP %d", resp.StatusCode)
	}

	var programs []intigritiProgram
	if err := json.NewDecoder(resp.Body).Decode(&programs); err != nil {
		return nil, fmt.Errorf("intigriti: decode: %w", err)
	}

	var matches []ProgramScope
	for _, prog := range programs {
		ps := i.matchDomain(domain, prog)
		if ps != nil {
			matches = append(matches, *ps)
		}
	}
	return matches, nil
}

func (i *Intigriti) matchDomain(domain string, prog intigritiProgram) *ProgramScope {
	var allow, deny []string
	found := false

	for _, d := range prog.Domains {
		if d.Type == "other" {
			continue
		}
		host := extractHostFromEntry(normalizeScopeEntry(d.Endpoint))
		if host == "" {
			continue
		}
		if !d.InScope {
			deny = append(deny, host)
			continue
		}
		allow = append(allow, host)
		if domainMatchesEntry(domain, host) {
			found = true
		}
	}

	if !found {
		return nil
	}

	handle := prog.Handle
	if handle == "" {
		handle = strings.ToLower(strings.ReplaceAll(prog.Name, " ", "-"))
	}

	return &ProgramScope{
		Platform:    "intigriti",
		Handle:      handle,
		Name:        prog.Name,
		URL:         "https://app.intigriti.com/programs/" + handle,
		Allow:       allow,
		Deny:        deny,
		MaxSeverity: "high",
		FetchedAt:   time.Now(),
	}
}

// ─────────────────────────────────────────────────────────────────────────────

// YesWeHack fetches scope from the YesWeHack public API.
// Set YESWEHACK_TOKEN for authenticated access.
type YesWeHack struct {
	apiToken string
	client   *http.Client
}

// NewYesWeHack creates a YesWeHack provider.
func NewYesWeHack() *YesWeHack {
	return &YesWeHack{
		apiToken: os.Getenv("YESWEHACK_TOKEN"),
		client:   &http.Client{Timeout: 15 * time.Second},
	}
}

// Name returns the provider identifier.
func (y *YesWeHack) Name() string { return "yeswehack" }

type ywhProgram struct {
	Slug   string `json:"slug"`
	Title  string `json:"title"`
	Status string `json:"status"` // "public","private"
	Scopes []struct {
		Scope     string `json:"scope"`
		ScopeType string `json:"scope_type"` // "web-application","api","mobile"
		OutOfScope bool  `json:"out_of_scope"`
	} `json:"scopes"`
	BountyRange struct {
		Min int `json:"min"`
		Max int `json:"max"`
	} `json:"bounty_range"`
}

type ywhListResp struct {
	Items []ywhProgram `json:"items"`
}

// FindByDomain searches YesWeHack programs for those covering domain.
func (y *YesWeHack) FindByDomain(domain string) ([]ProgramScope, error) {
	url := "https://api.yeswehack.com/programs?page=1&resultsPerPage=100&isPublic=1"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "scope-enforcement/0.1")
	if y.apiToken != "" {
		req.Header.Set("Authorization", "Bearer "+y.apiToken)
	}

	resp, err := y.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("yeswehack: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("yeswehack: HTTP %d", resp.StatusCode)
	}

	var result ywhListResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("yeswehack: decode: %w", err)
	}

	var matches []ProgramScope
	for _, prog := range result.Items {
		ps := y.matchDomain(domain, prog)
		if ps != nil {
			matches = append(matches, *ps)
		}
	}
	return matches, nil
}

func (y *YesWeHack) matchDomain(domain string, prog ywhProgram) *ProgramScope {
	var allow, deny []string
	found := false

	for _, s := range prog.Scopes {
		if s.ScopeType == "mobile" || s.ScopeType == "other" {
			continue
		}
		host := extractHostFromEntry(normalizeScopeEntry(s.Scope))
		if host == "" {
			continue
		}
		if s.OutOfScope {
			deny = append(deny, host)
			continue
		}
		allow = append(allow, host)
		if domainMatchesEntry(domain, host) {
			found = true
		}
	}

	if !found {
		return nil
	}

	return &ProgramScope{
		Platform:    "yeswehack",
		Handle:      prog.Slug,
		Name:        prog.Title,
		URL:         "https://yeswehack.com/programs/" + prog.Slug,
		Allow:       allow,
		Deny:        deny,
		MaxSeverity: "high",
		FetchedAt:   time.Now(),
	}
}
