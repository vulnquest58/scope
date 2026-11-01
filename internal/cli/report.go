package cli

import (
	"fmt"
	"os"

	"github.com/vulnquest58/scope/internal/decide"
)

// FormatDecision formats a Decision for human-readable output.
// FormatDecision writes to w.
func FormatDecision(d decide.Decision) string {
	verdict := "DENY"
	if d.Verdict == decide.Allow {
		verdict = "ALLOW"
	}
	line := fmt.Sprintf("[%s] %s → %s", verdict, d.Target, d.Reason)
	if d.Rule != "" {
		line += fmt.Sprintf(" (%s)", d.Rule)
	}
	return line
}

// PrintDisclaimer prints the mandatory authorisation disclaimer to w.
// PrintDisclaimer must be called in every report output.
func PrintDisclaimer() {
	fmt.Fprintln(os.Stderr, "Authorised use only. This tool enforces a policy you supplied; it does not verify your authorisation.")
}

