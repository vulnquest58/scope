package policy

import "strings"

// ProviderSuffixes maps known third-party hosting suffixes to provider names.
var ProviderSuffixes = map[string]string{
	".zendesk.com":           "Zendesk",
	".statuspage.io":         "Statuspage",
	".herokuapp.com":         "Heroku",
	".cloudfront.net":        "CloudFront",
	".fastly.net":            "Fastly",
	".akamaiedge.net":        "Akamai",
	".azureedge.net":         "Azure CDN",
	".googleusercontent.com": "Google",
	".github.io":             "GitHub Pages",
	".shopify.com":           "Shopify",
	".myshopify.com":         "Shopify",
	".salesforce.com":        "Salesforce",
	".force.com":             "Salesforce",
	".wpengine.com":          "WP Engine",
	".netlify.app":           "Netlify",
	".vercel.app":            "Vercel",
	".amazonaws.com":         "AWS",
	".cloudapp.net":          "Azure",
	".trafficmanager.net":    "Azure TM",
}

// ThirdParty checks if any name in the CNAME chain (including the original)
// belongs to a known third-party hosting provider.
// ThirdParty returns (providerName, true) if found, ("", false) otherwise.
func ThirdParty(chain []string) (provider string, ok bool) {
	for _, name := range chain {
		norm := normalizeName(name)
		for suffix, prov := range ProviderSuffixes {
			if strings.HasSuffix(norm, suffix) {
				return prov, true
			}
		}
	}
	return "", false
}
