// Package adapters provides external I/O and integration boundaries.
//
// Allowed internal dependencies: foundation, domain.
package adapters

import (
	"tmpl-prefix/domain"
	"tmpl-prefix/foundation"
)

// WorkspaceName verifies adapter wiring to the foundation and domain layers.
func WorkspaceName() (string, error) {
	name := domain.WorkspaceName()
	if name == "" {
		return "", foundation.NewError("empty_workspace", "workspace name is empty")
	}
	return name, nil
}

// ResolveBanner resolves a domain banner through the adapter boundary.
func ResolveBanner(component string) (string, error) {
	return domain.FormatBanner(component)
}
