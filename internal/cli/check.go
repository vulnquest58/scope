package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"

	"github.com/vulnquest58/scope/internal/decide"
	"github.com/vulnquest58/scope/internal/policy"
)

// checkResult is the JSON output of "scope check --json".
type checkResult struct {
	Target  string `json:"target"`
	Verdict string `json:"verdict"`
	Reason  string `json:"reason"`
	Rule    string `json:"rule"`
	Level   int    `json:"level"`
}

// CheckCmd implements the "scope check" subcommand.
// CheckCmd returns 0 if allowed, 1 if denied, 2 on usage error.
func CheckCmd(args []string) int {
	var programFlag, targetFlag string
	var levelFlag int
	var jsonFlag bool

	fs := flag.NewFlagSet("scope check", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&programFlag, "program", "", "policy file path")
	fs.IntVar(&levelFlag, "level", 1, "severity level 0..3")
	fs.BoolVar(&jsonFlag, "json", false, "output JSON")

	// Allow target as first positional arg OR after flags.
	// Separate the positional target from flag args.
	var flagArgs []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) > 0 && a[0] != '-' && targetFlag == "" {
			// First non-flag arg is the target.
			targetFlag = a
		} else {
			flagArgs = append(flagArgs, a)
		}
	}

	if err := fs.Parse(flagArgs); err != nil {
		return 2
	}
	// Also accept target as positional remaining arg.
	if targetFlag == "" && fs.NArg() > 0 {
		targetFlag = fs.Arg(0)
	}

	if targetFlag == "" {
		fmt.Fprintln(os.Stderr, "usage: scope check <url|host> [--program <file>] [--level N] [--json]")
		return 2
	}
	if programFlag == "" {
		fmt.Fprintln(os.Stderr, "scope: --program is required")
		return 2
	}

	// Extract host from URL if needed.
	host := extractHost(targetFlag)

	// Load policy.
	cp, err := policy.Load(programFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scope: %v\n", err)
		return 2
	}

	e := decide.NewEngine(cp)
	d := e.Decide(context.Background(), host, levelFlag)

	verdict := "deny"
	if d.Verdict == decide.Allow {
		verdict = "allow"
	}

	if jsonFlag {
		res := checkResult{
			Target:  targetFlag,
			Verdict: verdict,
			Reason:  string(d.Reason),
			Rule:    d.Rule,
			Level:   levelFlag,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(res) //nolint:errcheck
	} else {
		icon := "✅"
		if d.Verdict == decide.Deny {
			icon = "❌"
		}
		fmt.Printf("%s %s → %s (%s)\n", icon, targetFlag, verdict, d.Reason)
		if d.Rule != "" {
			fmt.Printf("   rule: %s\n", d.Rule)
		}
	}

	if d.Verdict == decide.Allow {
		return 0
	}
	return 1
}

// extractHost extracts the hostname from a URL or returns the input as-is.
func extractHost(target string) string {
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		if h := u.Hostname(); h != "" {
			return h
		}
	}
	return target
}
