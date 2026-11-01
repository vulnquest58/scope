// Package enforce provides the L4 connect shim (deferred to M4).
package enforce

import "github.com/vulnquest58/scope/internal/decide"

// ConnectShim represents the L4 syscall-level enforcement layer.
// ConnectShim is implemented via LD_PRELOAD (Linux/macOS) or WFP callout (Windows).
// This stub documents the interface; full implementation is deferred to M4.
//
// Protocol (Unix socket):
//
//	Client → server: "DECIDE <ip> <port>\n"
//	Server → client: "ALLOW\n" or "DENY <reason>\n"
type ConnectShim struct {
	// SocketPath is the Unix domain socket the shim connects to.
	SocketPath string
	// Engine is the decision engine consulted per connection.
	Engine *decide.Engine
}
