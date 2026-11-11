package foundation

import "testing"

func TestWorkspaceConstants(t *testing.T) {
	if Name == "" || Prefix == "" || EnvPrefix == "" || PascalName == "" {
		t.Fatalf("workspace constants must not be empty")
	}
}

func TestErrorFormatting(t *testing.T) {
	err := NewError("invalid_input", "subject is empty")
	if got, want := err.Error(), "invalid_input: subject is empty"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	msgOnly := NewError("", "plain message")
	if got, want := msgOnly.Error(), "plain message"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	var nilErr *Error
	if got := nilErr.Error(); got != "" {
		t.Fatalf("expected empty string for nil *Error, got %q", got)
	}
}
