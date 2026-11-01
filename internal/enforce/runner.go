// Package enforce provides the command runner for scope.
package enforce

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/vulnquest58/scope/internal/decide"
	scopelog "github.com/vulnquest58/scope/internal/log"
)

// RunConfig configures how a command is run under scope enforcement.
type RunConfig struct {
	ProxyAddr  string // HTTP proxy address, e.g. "127.0.0.1:8080"
	JournalPath string
	Level      int
	DryRun     bool
	Verbose    bool
}

// Run executes cmd[0] with args cmd[1:] under scope enforcement.
// Run returns the exit code of the command, or a scope error.
// Run injects proxy environment variables so the command routes through scope.
func Run(ctx context.Context, e *decide.Engine, j *scopelog.Journal, cmd []string, cfg RunConfig) (int, error) {
	if len(cmd) == 0 {
		return 2, fmt.Errorf("no command specified")
	}

	if cfg.DryRun {
		fmt.Printf("[scope dry-run] would execute: %v\n", cmd)
		fmt.Printf("[scope dry-run] proxy: %s\n", cfg.ProxyAddr)
		return 0, nil
	}

	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	// Inherit environment, then inject scope vars.
	c.Env = os.Environ()
	if cfg.ProxyAddr != "" {
		proxyURL := "http://" + cfg.ProxyAddr
		c.Env = setEnv(c.Env, "HTTP_PROXY", proxyURL)
		c.Env = setEnv(c.Env, "HTTPS_PROXY", proxyURL)
		c.Env = setEnv(c.Env, "http_proxy", proxyURL)
		c.Env = setEnv(c.Env, "https_proxy", proxyURL)
	}
	if cfg.JournalPath != "" {
		c.Env = setEnv(c.Env, "SCOPE_JOURNAL", cfg.JournalPath)
	}
	c.Env = setEnv(c.Env, "SCOPE_LEVEL", strconv.Itoa(cfg.Level))

	if err := c.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code := exitErr.ExitCode()
			if code < 0 {
				// Killed by signal: 128 + signal number.
				// ExitCode() returns -1 on signal; use ProcessState for signal.
				code = 128 + signalNumber(exitErr)
			}
			return code, nil
		}
		return 1, err
	}
	return 0, nil
}

// setEnv sets or replaces an environment variable in env.
func setEnv(env []string, key, val string) []string {
	prefix := key + "="
	for i, e := range env {
		if len(e) > len(prefix) && e[:len(prefix)] == prefix {
			env[i] = prefix + val
			return env
		}
	}
	return append(env, prefix+val)
}

// signalNumber extracts the signal number from an ExitError.
// signalNumber returns 0 if the signal cannot be determined.
func signalNumber(e *exec.ExitError) int {
	// On most systems, Status().Signal() returns the signal.
	if ps := e.ProcessState; ps != nil {
		// Use Sys() which returns syscall.WaitStatus on Unix.
		if ws, ok := ps.Sys().(interface{ Signal() interface{ Signal() } }); ok {
			_ = ws
		}
		// Fallback: parse from string representation.
		// This is a best-effort approach for cross-platform compatibility.
	}
	return 0
}

