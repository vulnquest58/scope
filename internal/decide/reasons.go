// Package decide contains the decision engine for the scope enforcement layer.
package decide

// Reason is an enumerated denial or allow code.
type Reason string

const (
	// ReasonAllow indicates the request was permitted.
	ReasonAllow Reason = "allow"
	// ReasonPolicyMissing indicates no policy has been loaded.
	ReasonPolicyMissing Reason = "policy-missing"
	// ReasonPolicyExpired indicates the policy's Expires timestamp is in the past.
	ReasonPolicyExpired Reason = "policy-expired"
	// ReasonPolicyInvalid indicates the policy failed validation.
	ReasonPolicyInvalid Reason = "policy-invalid"
	// ReasonOutsideWindow indicates the request arrived outside the allowed time window.
	ReasonOutsideWindow Reason = "outside-window"
	// ReasonRateLimited indicates the per-host or global rate limit was exceeded.
	ReasonRateLimited Reason = "rate-limited"
	// ReasonUnresolvable indicates the target hostname could not be resolved.
	ReasonUnresolvable Reason = "unresolvable"
	// ReasonExplicitDeny indicates a deny rule matched.
	ReasonExplicitDeny Reason = "explicit-deny"
	// ReasonThirdPartyHost indicates the CNAME chain resolves to a third-party provider.
	ReasonThirdPartyHost Reason = "third-party-host"
	// ReasonOutsideWildcard indicates the target did not match any allow rule.
	ReasonOutsideWildcard Reason = "outside-wildcard"
	// ReasonLevelTooHigh indicates the requested level exceeds the policy maximum.
	ReasonLevelTooHigh Reason = "level-too-high"
	// ReasonEngineError indicates an internal engine failure.
	ReasonEngineError Reason = "engine-error"
)

// IsDeny reports whether r represents a denial. Every Reason except ReasonAllow is a denial.
func (r Reason) IsDeny() bool { return r != ReasonAllow }
