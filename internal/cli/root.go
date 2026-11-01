// Package cli implements the scope command-line interface.
package cli

import (
	"flag"
	"fmt"
	"os"
)

// Run parses os.Args and dispatches to the appropriate subcommand.
// Run returns an exit code.
func Run(args []string) int {
	if len(args) < 1 {
		printUsage()
		return 2
	}

	sub := args[0]
	rest := args[1:]

	switch sub {
	case "run":
		return RunCmd(rest)
	case "check":
		return CheckCmd(rest)
	case "policy":
		return PolicyCmd(rest)
	case "verify-log":
		return VerifyLogCmd(rest)
	case "journal":
		return JournalCmd(rest)
	case "help", "--help", "-h":
		printUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "scope: unknown subcommand %q\n", sub)
		printUsage()
		return 2
	}
}

// printUsage prints the top-level usage to stderr.
func printUsage() {
	fmt.Fprintln(os.Stderr, `scope — network scope enforcement layer

Usage:
  scope run      --program <file> [--level N] [--journal PATH] [--dry-run] -- <cmd> [args...]
  scope check    <url|host> [--program <file>] [--level N] [--json]
  scope policy   validate|show <file>
  scope verify-log <path>
  scope journal  tail [--n N] [--path PATH]

Exit codes:
  0  success / allowed
  1  command failed / denied
  2  usage error
  3  policy or log load failed
  4  enforcement layer failed

Authorised use only. This tool enforces a policy you supplied; it does not verify your authorisation.`)
}

// mustFlag creates a FlagSet and returns it.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

