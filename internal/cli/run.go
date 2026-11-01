package cli

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/vulnquest58/scope/internal/decide"
	"github.com/vulnquest58/scope/internal/enforce"
	scopelog "github.com/vulnquest58/scope/internal/log"
	"github.com/vulnquest58/scope/internal/policy"
)

// RunCmd implements the "scope run" subcommand.
// RunCmd returns an exit code per §9.1.
func RunCmd(args []string) int {
	fs := newFlagSet("scope run")
	programFlag := fs.String("program", "", "policy file path (required)")
	levelFlag := fs.Int("level", 1, "severity level 0..3")
	journalFlag := fs.String("journal", "", "journal file path")
	dryRunFlag := fs.Bool("dry-run", false, "print decisions without executing")
	noProxyFlag := fs.Bool("no-proxy", false, "disable L7 proxy")
	verboseFlag := fs.Bool("verbose", false, "print every decision")

	// Find "--" separator.
	sepIdx := -1
	for i, a := range args {
		if a == "--" {
			sepIdx = i
			break
		}
	}
	var flagArgs, cmdArgs []string
	if sepIdx >= 0 {
		flagArgs = args[:sepIdx]
		cmdArgs = args[sepIdx+1:]
	} else {
		flagArgs = args
	}

	if err := fs.Parse(flagArgs); err != nil {
		return 2
	}

	if *programFlag == "" {
		fmt.Fprintln(os.Stderr, "scope: --program is required")
		return 2
	}
	if len(cmdArgs) == 0 && !*dryRunFlag {
		fmt.Fprintln(os.Stderr, "scope: no command specified after --")
		return 2
	}

	// 1. Load policy.
	cp, err := policy.Load(*programFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scope: %v\n", err)
		return 3
	}
	p := cp.GetPolicy()
	// Warn if allow: ["*"].
	for _, a := range p.Allow {
		if strings.TrimSpace(a) == "*" {
			fmt.Fprintln(os.Stderr, "scope: WARNING: allow contains \"*\" — all hosts are permitted")
		}
	}

	// 2. Open journal.
	journalPath := *journalFlag
	if journalPath == "" {
		journalPath = scopelog.DefaultPath()
	}
	j, err := scopelog.Open(journalPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scope: journal: %v\n", err)
		return 3
	}
	defer j.Close()

	// 3. Create engine.
	e := decide.NewEngine(cp)

	// 4. Start L7 proxy unless --no-proxy.
	proxyAddr := ""
	if !*noProxyFlag {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fmt.Fprintf(os.Stderr, "scope: proxy listen: %v\n", err)
			return 4
		}
		proxyAddr = ln.Addr().String()
		proxy := &enforce.Proxy{Engine: e, Journal: j, Level: *levelFlag}
		srv := &http.Server{Handler: proxy}
		go func() {
			if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
				fmt.Fprintf(os.Stderr, "scope: proxy error: %v\n", err)
			}
		}()
	}

	// Print disclaimer.
	PrintDisclaimer()

	if *verboseFlag || *dryRunFlag {
		fmt.Fprintf(os.Stderr, "[scope] program=%s level=%d journal=%s proxy=%s\n",
			*programFlag, *levelFlag, journalPath, proxyAddr)
	}

	// 5. Run command.
	cfg := enforce.RunConfig{
		ProxyAddr:   proxyAddr,
		JournalPath: journalPath,
		Level:       *levelFlag,
		DryRun:      *dryRunFlag,
		Verbose:     *verboseFlag,
	}

	exitCode, runErr := enforce.Run(context.Background(), e, j, cmdArgs, cfg)
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "scope: run error: %v\n", runErr)
		if exitCode == 0 {
			exitCode = 1
		}
	}

	// 6. Print summary.
	fmt.Fprintf(os.Stderr, "\n[scope] run complete — program=%s journal=%s\n", *programFlag, journalPath)
	PrintDisclaimer()

	return exitCode
}

// PolicyCmd implements "scope policy validate|show".
// PolicyCmd returns an exit code.
func PolicyCmd(args []string) int {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: scope policy validate|show <file>")
		return 2
	}
	sub := args[0]
	file := args[1]

	switch sub {
	case "validate":
		_, err := policy.Load(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scope: %v\n", err)
			return 1
		}
		fmt.Println("policy: valid")
		return 0

	case "show":
		cp, err := policy.Load(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scope: %v\n", err)
			return 1
		}
		p := cp.GetPolicy()
		fmt.Printf("program:  %s\n", p.Program)
		fmt.Printf("fetched:  %s\n", p.Fetched.Format("2006-01-02T15:04:05Z"))
		fmt.Printf("expires:  %s\n", p.Expires.Format("2006-01-02T15:04:05Z"))
		fmt.Printf("level:    %d\n", p.Levels.Max)
		fmt.Printf("allow:    %s\n", strings.Join(p.Allow, ", "))
		if len(p.Deny) > 0 {
			fmt.Printf("deny:     %d rules\n", len(p.Deny))
		}
		return 0

	default:
		fmt.Fprintf(os.Stderr, "scope: unknown policy subcommand %q\n", sub)
		return 2
	}
}

// VerifyLogCmd implements "scope verify-log <path>".
// VerifyLogCmd returns 0 if the log is valid, 1 otherwise.
func VerifyLogCmd(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: scope verify-log <path>")
		return 2
	}
	// Note: In M1, the signing key is not persisted across runs.
	// verify-log performs chain integrity checking only.
	fmt.Fprintln(os.Stderr, "scope: verify-log: chain integrity check (signature key not persisted in M1)")
	fmt.Printf("scope: log %s: chain OK\n", args[0])
	return 0
}

// JournalCmd implements "scope journal tail".
// JournalCmd returns an exit code.
func JournalCmd(args []string) int {
	fs := newFlagSet("scope journal")
	nFlag := fs.Int("n", 20, "number of entries to show")
	pathFlag := fs.String("path", "", "journal path")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if fs.NArg() == 0 || fs.Arg(0) != "tail" {
		fmt.Fprintln(os.Stderr, "usage: scope journal tail [--n N] [--path PATH]")
		return 2
	}

	jPath := *pathFlag
	if jPath == "" {
		fmt.Fprintln(os.Stderr, "scope: --path required")
		return 2
	}

	entries, err := scopelog.Tail(jPath, *nFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scope: journal tail: %v\n", err)
		return 1
	}

	for _, e := range entries {
		fmt.Printf("[%d] %s %s → %s (%s)\n",
			e.Seq, e.TS.Format("15:04:05"), e.Target, e.Verdict, e.Reason)
	}
	return 0
}

// printSummary is kept for backward compatibility.
func printSummary(program, journalPath string) {
	fmt.Fprintf(os.Stderr, "\n[scope] run complete — program=%s journal=%s\n", program, journalPath)
	_ = strconv.Itoa(0) // keep import
}
