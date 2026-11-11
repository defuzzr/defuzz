package main

import (
	"bytes"
	"strings"
	"testing"

	"tmpl-prefix/foundation"
)

func TestRunCLIOutputsWorkspaceName(t *testing.T) {
	var buf bytes.Buffer
	if err := runCLI(&buf); err != nil {
		t.Fatalf("runCLI failed: %v", err)
	}
	if got := strings.TrimSpace(buf.String()); got != foundation.Name {
		t.Fatalf("runCLI output = %q, want %q", got, foundation.Name)
	}
}
