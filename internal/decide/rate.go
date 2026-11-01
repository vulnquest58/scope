// Package decide contains the decision engine for the scope enforcement layer.
package decide

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter implements a per-host and global token-bucket rate limiter.
type RateLimiter struct {
	mu         sync.Mutex
	perHostRPS float64
	globalRPS  float64
	burst      int
	global     *rate.Limiter
	hosts      map[string]*rate.Limiter
}

// NewRateLimiter creates a RateLimiter with the given per-host RPS, global RPS, and burst.
// NewRateLimiter returns a ready-to-use limiter.
func NewRateLimiter(perHostRPS, globalRPS float64, burst int) *RateLimiter {
	if burst <= 0 {
		burst = 1
	}
	var global *rate.Limiter
	if globalRPS > 0 {
		global = rate.NewLimiter(rate.Limit(globalRPS), burst)
	}
	return &RateLimiter{
		perHostRPS: perHostRPS,
		globalRPS:  globalRPS,
		burst:      burst,
		global:     global,
		hosts:      make(map[string]*rate.Limiter),
	}
}

// Allow reports whether a request to host is within the rate limits at time now.
// Allow returns false if either the per-host or global limit is exceeded.
// If PerHostRPS is 0, the per-host limit is unlimited (always allowed).
// Deny decisions should NOT call Allow (they don't consume tokens).
func (r *RateLimiter) Allow(host string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Global limiter check.
	if r.global != nil {
		if !r.global.AllowN(now, 1) {
			return false
		}
	}

	// Per-host limiter check. 0 means unlimited.
	if r.perHostRPS > 0 {
		lim, ok := r.hosts[host]
		if !ok {
			lim = rate.NewLimiter(rate.Limit(r.perHostRPS), r.burst)
			r.hosts[host] = lim
		}
		if !lim.AllowN(now, 1) {
			return false
		}
	}

	return true
}
