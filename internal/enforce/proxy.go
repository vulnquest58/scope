// Package enforce provides the L7 HTTP/HTTPS proxy enforcement layer.
package enforce

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/vulnquest58/scope/internal/decide"
	scopelog "github.com/vulnquest58/scope/internal/log"
)

// Proxy is an HTTP/HTTPS forward proxy that enforces scope decisions.
type Proxy struct {
	Engine  *decide.Engine
	Journal *scopelog.Journal
	Level   int
}

// denyResponse is the JSON body returned on a 403.
type denyResponse struct {
	Error  string `json:"error"`
	Reason string `json:"reason"`
	Rule   string `json:"rule"`
}

// ServeHTTP implements http.Handler. It evaluates every request against the
// engine and either forwards it (with X-Scope: allow) or returns 403.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// CONNECT (HTTPS tunnel): evaluate host from authority only.
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}

	// Plain HTTP: extract host from request URL.
	host := r.URL.Hostname()
	if host == "" {
		host = r.Host
	}

	d := p.Engine.Decide(r.Context(), host, p.Level)
	p.writeJournal(d)

	if d.Verdict == decide.Deny {
		p.writeDeny(w, d)
		return
	}

	// Forward the request.
	r.Header.Set("X-Scope", "allow")

	// Build upstream URL.
	target := &url.URL{
		Scheme: r.URL.Scheme,
		Host:   r.URL.Host,
	}
	if target.Scheme == "" {
		target.Scheme = "http"
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "scope-engine-error"})
	}
	proxy.ServeHTTP(w, r)
}

// handleConnect handles HTTPS CONNECT tunneling.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}

	d := p.Engine.Decide(r.Context(), host, p.Level)
	p.writeJournal(d)

	if d.Verdict == decide.Deny {
		p.writeDeny(w, d)
		return
	}

	// Establish upstream connection.
	upstream, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": "scope-engine-error"})
		return
	}
	defer upstream.Close()

	w.Header().Set("X-Scope", "allow")
	w.WriteHeader(http.StatusOK)

	// Hijack the connection for raw tunneling.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	// Pipe bidirectionally.
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(upstream, clientConn) //nolint:errcheck
		done <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, upstream) //nolint:errcheck
		done <- struct{}{}
	}()
	<-done
}

// writeDeny writes a 403 JSON response.
func (p *Proxy) writeDeny(w http.ResponseWriter, d decide.Decision) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	resp := denyResponse{
		Error:  "out-of-scope",
		Reason: string(d.Reason),
		Rule:   d.Rule,
	}
	json.NewEncoder(w).Encode(resp)
}

// writeJournal logs a decision to the journal if one is configured.
func (p *Proxy) writeJournal(d decide.Decision) {
	if p.Journal == nil {
		return
	}
	verdict := "deny"
	if d.Verdict == decide.Allow {
		verdict = "allow"
	}
	resolved := ""
	if d.Resolved.IsValid() {
		resolved = d.Resolved.String()
	}
	if err := p.Journal.Write(
		d.Target, resolved, verdict, string(d.Reason), d.Rule,
		d.Level, time.Now(),
	); err != nil {
		// Fatal: journal write failed — stop the proxy.
		panic(fmt.Sprintf("scope: journal write failed: %v", err))
	}
}

// ListenAndServe starts the proxy on addr and blocks.
// ListenAndServe returns an error if the server fails to start.
func (p *Proxy) ListenAndServe(addr string) error {
	srv := &http.Server{
		Addr:    addr,
		Handler: p,
	}
	return srv.ListenAndServe()
}

