package domain

import (
	"testing"

	"tmpl-prefix/foundation"
)

func TestWorkspaceNameAndFormatBanner(t *testing.T) {
	if got := WorkspaceName(); got != foundation.Name {
		t.Fatalf("WorkspaceName() = %q, want %q", got, foundation.Name)
	}

	banner, err := FormatBanner("cli")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := foundation.Name + ":cli"; banner != want {
		t.Fatalf("FormatBanner() = %q, want %q", banner, want)
	}

	if _, err := FormatBanner("   "); err == nil {
		t.Fatalf("expected error for blank component name")
	}
}
