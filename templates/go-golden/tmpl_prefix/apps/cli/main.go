// Package main is the CLI composition root (apps/cli/).
//
// Allowed internal dependencies: foundation, domain, adapters.
package main

import (
	"fmt"
	"io"
	"os"

	"tmpl-prefix/adapters"
	"tmpl-prefix/domain"
	"tmpl-prefix/foundation"
)

func runCLI(out io.Writer) error {
	_ = foundation.Prefix
	_ = domain.WorkspaceName()
	name, err := adapters.WorkspaceName()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, name)
	return err
}

func main() {
	if err := runCLI(os.Stdout); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
