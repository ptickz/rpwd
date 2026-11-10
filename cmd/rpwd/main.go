// Command rpwd is a password manager CLI.
package main

import (
	"os"

	"github.com/ptickz/rpwd/internal/cli"
)

func main() {
	os.Exit(
		cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr),
	)
}
