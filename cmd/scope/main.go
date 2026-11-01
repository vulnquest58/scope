// Command scope is the network scope enforcement tool.
// scope enforces a policy you supply; it does not verify your authorisation.
package main

import (
	"os"

	"github.com/vulnquest58/scope/internal/cli"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(cli.Run([]string{"help"}))
	}
	os.Exit(cli.Run(os.Args[1:]))
}

