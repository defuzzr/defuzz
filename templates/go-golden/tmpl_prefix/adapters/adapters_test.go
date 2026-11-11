package adapters

import (
	"testing"

	"tmpl-prefix/foundation"
)

func TestAdaptersWorkspaceNameAndBanner(t *testing.T) {
	name, err := WorkspaceName()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != foundation.Name {
		t.Fatalf("WorkspaceName() = %q, want %q", name, foundation.Name)
	}

	banner, err := ResolveBanner("service")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := foundation.Name + ":service"; banner != want {
		t.Fatalf("ResolveBanner() = %q, want %q", banner, want)
	}
}
