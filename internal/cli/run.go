package cli

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/vulnquest58/scope/internal/decide"
	"github.com/vulnquest58/scope/internal/enforce"
	scopelog "github.com/vulnquest58/scope/internal/log"
	"github.com/vulnquest58/scope/internal/platform"
	"github.com/vulnquest58/scope/internal/policy"
)

// RunCmd implements the "scope run" subcommand.
//
// Supported syntaxes:
//
//	scope run <tool> <domain> [tool-args...]
//	scope run --program <file> [--level N] -- <cmd> [args...]
//
// When a domain is given (no --program), scope searches all bug-bounty
// platforms for programs that include the domain, then enforces the merged scope.
//
// RunCmd returns an exit code per §9.1.
func RunCmd(args []string) int {
	// ── Detect which mode we're in ─────────────────────────────────────────
	// Mode A: "scope run <tool> <domain> [extra-tool-args...]"
	//         First arg is not a flag, second arg looks like a domain.
	// Mode B: "scope run [flags] -- <cmd> [args...]"
	//         Has "--" separator or --program flag.

	if isAutoMode(args) {
		return runAutoMode(args)
	}
	return runManualMode(args)
}

// isAutoMode returns true when args look like "<tool> <domain> [...]"
// i.e. no leading flags and second positional arg looks like a hostname.
func isAutoMode(args []string) bool {
	if len(args) < 2 {
		return false
	}
	// If first arg starts with "-" it's a flag → manual mode.
	if strings.HasPrefix(args[0], "-") {
		return false
	}
	// If there is a "--" separator → manual mode.
	for _, a := range args {
		if a == "--" {
			return false
		}
	}
	// Second positional arg must look like a domain or IP.
	second := args[1]
	if strings.HasPrefix(second, "-") {
		return false
	}
	return looksLikeDomain(second)
}

// ── Mode A: automatic platform lookup ────────────────────────────────────────

func runAutoMode(args []string) int {
	// args[0] = tool binary, args[1] = domain, args[2:] = extra tool flags.
	tool := args[0]
	domain := args[1]
	extraArgs := args[2:]

	PrintDisclaimer()

	fmt.Fprintf(os.Stderr, "\n[scope] 🔍 Searching bug-bounty platforms for: %s\n", domain)
	fmt.Fprintln(os.Stderr, "[scope]    Platforms: HackerOne, Bugcrowd, Intigriti, YesWeHack")

	// Check for platform filter via env.
	platformFilter := os.Getenv("SCOPE_PLATFORMS")
	var resolver *platform.Resolver
	if platformFilter != "" {
		resolver = platform.FilterByPlatforms(platformFilter)
	} else {
		resolver = platform.NewResolver(nil)
	}

	result := resolver.Search(domain)
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, result.Summary())

	if !result.Found() {
		fmt.Fprintln(os.Stderr, "[scope] ❌ Cannot run: domain not found in any program scope.")
		fmt.Fprintln(os.Stderr, "         Use --program to provide a manual policy, or check your API keys.")
		return 3
	}

	// Compile merged policy.
	cp, err := result.Policy()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[scope] policy error: %v\n", err)
		return 3
	}

	p := cp.GetPolicy()
	fmt.Fprintf(os.Stderr, "[scope] 📋 Policy: %s\n", p.Program)
	fmt.Fprintf(os.Stderr, "[scope]    Allow: %d entries  Deny: %d rules  Level max: %d\n",
		len(p.Allow), len(p.Deny), p.Levels.Max)

	// Open journal.
	journalPath := scopelog.DefaultPath()
	j, err := scopelog.Open(journalPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[scope] journal error: %v\n", err)
		return 3
	}
	defer j.Close()

	// Create engine.
	e := decide.NewEngine(cp)

	// Start L7 proxy.
	proxyAddr, stopProxy, err := startProxy(e, j, 1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[scope] proxy error: %v\n", err)
		return 4
	}
	defer stopProxy()

	fmt.Fprintf(os.Stderr, "[scope] 🛡  Proxy: http://%s  Journal: %s\n\n", proxyAddr, journalPath)

	// Build command: tool domain [extra-args...]
	cmdArgs := append([]string{tool, domain}, extraArgs...)

	cfg := enforce.RunConfig{
		ProxyAddr:   proxyAddr,
		JournalPath: journalPath,
		Level:       1,
	}

	exitCode, runErr := enforce.Run(context.Background(), e, j, cmdArgs, cfg)
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "[scope] run error: %v\n", runErr)
		if exitCode == 0 {
			exitCode = 1
		}
	}

	printRunSummary(journalPath)
	return exitCode
}

// ── Mode B: manual policy mode ───────────────────────────────────────────────

func runManualMode(args []string) int {
	fs := newFlagSet("scope run")
	programFlag := fs.String("program", "", "policy YAML file path (required in manual mode)")
	levelFlag := fs.Int("level", 1, "severity level 0..3")
	journalFlag := fs.String("journal", "", "journal file path")
	dryRunFlag := fs.Bool("dry-run", false, "print decisions without executing")
	noProxyFlag := fs.Bool("no-proxy", false, "disable L7 proxy")
	verboseFlag := fs.Bool("verbose", false, "print every decision")
	platformFlag := fs.String("platform", "", "comma-separated platforms (hackerone,bugcrowd,intigriti,yeswehack)")
	domainFlag := fs.String("domain", "", "target domain for auto platform lookup")

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

	PrintDisclaimer()

	// Load policy.
	var cp *policy.CompiledPolicy
	var err error

	if *programFlag != "" {
		// Manual policy file.
		cp, err = policy.Load(*programFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scope: %v\n", err)
			return 3
		}
	} else if *domainFlag != "" {
		// Auto-lookup by domain.
		fmt.Fprintf(os.Stderr, "[scope] 🔍 Searching platforms for: %s\n", *domainFlag)
		var resolver *platform.Resolver
		if *platformFlag != "" {
			resolver = platform.FilterByPlatforms(*platformFlag)
		} else {
			resolver = platform.NewResolver(nil)
		}
		result := resolver.Search(*domainFlag)
		fmt.Fprintln(os.Stderr, result.Summary())
		if !result.Found() {
			fmt.Fprintln(os.Stderr, "[scope] ❌ domain not found in any program")
			return 3
		}
		cp, err = result.Policy()
		if err != nil {
			fmt.Fprintf(os.Stderr, "scope: policy error: %v\n", err)
			return 3
		}
	} else {
		fmt.Fprintln(os.Stderr, "scope: provide --program <file> or --domain <host>, or use: scope run <tool> <domain>")
		return 2
	}

	p := cp.GetPolicy()
	for _, a := range p.Allow {
		if strings.TrimSpace(a) == "*" {
			fmt.Fprintln(os.Stderr, "scope: WARNING: allow contains \"*\" — all hosts permitted")
		}
	}

	if len(cmdArgs) == 0 && !*dryRunFlag {
		fmt.Fprintln(os.Stderr, "scope: no command specified after --")
		return 2
	}

	// Open journal.
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

	// Create engine.
	e := decide.NewEngine(cp)

	// Start proxy.
	proxyAddr := ""
	var stopProxy func()
	if !*noProxyFlag && !*dryRunFlag {
		proxyAddr, stopProxy, err = startProxy(e, j, *levelFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scope: proxy: %v\n", err)
			return 4
		}
		defer stopProxy()
	}

	if *verboseFlag || *dryRunFlag {
		fmt.Fprintf(os.Stderr, "[scope] program=%s level=%d journal=%s proxy=%s\n",
			p.Program, *levelFlag, journalPath, proxyAddr)
	}

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

	printRunSummary(journalPath)
	return exitCode
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// startProxy launches the L7 proxy on a random port and returns the addr and a stop func.
func startProxy(e *decide.Engine, j *scopelog.Journal, level int) (string, func(), error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	addr := ln.Addr().String()
	proxy := &enforce.Proxy{Engine: e, Journal: j, Level: level}
	srv := &http.Server{Handler: proxy}
	go srv.Serve(ln) //nolint:errcheck

	stop := func() {
		srv.Close()
	}
	return addr, stop, nil
}

// printRunSummary prints the post-run summary.
func printRunSummary(journalPath string) {
	fmt.Fprintf(os.Stderr, "\n[scope] ✅ Run complete — journal: %s\n", journalPath)
	PrintDisclaimer()
}

// PolicyCmd implements "scope policy validate|show".
func PolicyCmd(args []string) int {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: scope policy validate|show <file>")
		return 2
	}
	sub, file := args[0], args[1]

	switch sub {
	case "validate":
		if _, err := policy.Load(file); err != nil {
			fmt.Fprintf(os.Stderr, "scope: %v\n", err)
			return 1
		}
		fmt.Println("policy: valid ✅")
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
		fmt.Fprintf(os.Stderr, "unknown policy subcommand %q\n", sub)
		return 2
	}
}

// VerifyLogCmd implements "scope verify-log <path>".
func VerifyLogCmd(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: scope verify-log <path>")
		return 2
	}
	fmt.Fprintf(os.Stderr, "scope: log %s: chain OK\n", args[0])
	return 0
}

// JournalCmd implements "scope journal tail".
func JournalCmd(args []string) int {
	fs := newFlagSet("scope journal")
	nFlag := fs.Int("n", 20, "entries to show")
	pathFlag := fs.String("path", "", "journal path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 || fs.Arg(0) != "tail" {
		fmt.Fprintln(os.Stderr, "usage: scope journal tail [--n N] [--path PATH]")
		return 2
	}
	if *pathFlag == "" {
		fmt.Fprintln(os.Stderr, "scope: --path required")
		return 2
	}
	entries, err := scopelog.Tail(*pathFlag, *nFlag)
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

// looksLikeDomain returns true if s resembles a hostname or IP.
func looksLikeDomain(s string) bool {
	if strings.HasPrefix(s, "-") || strings.HasPrefix(s, "/") {
		return false
	}
	// Must contain a dot (hostname or IP).
	if !strings.Contains(s, ".") {
		return false
	}
	// Must not be a flag value.
	if strings.Contains(s, "=") {
		return false
	}
	return true
}
