// Package domain contains pure business logic with no external I/O.
//
// Allowed internal dependencies: foundation.
package domain

import (
	"strings"

	"tmpl-prefix/foundation"
)

// WorkspaceName returns the canonical workspace name via the foundation layer.
func WorkspaceName() string {
	return foundation.Name
}

// FormatBanner formats a pure domain status banner for a component name.
func FormatBanner(component string) (string, error) {
	cleaned := strings.TrimSpace(component)
	if cleaned == "" {
		return "", foundation.NewError("empty_component", "component name must not be empty")
	}
	return foundation.Name + ":" + cleaned, nil
}
