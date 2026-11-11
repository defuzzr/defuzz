// Package foundation provides shared primitives and workspace error types.
//
// Allowed internal dependencies: none (lowest workspace layer).
package foundation

import "strings"

const (
	// Name is the canonical kebab-case workspace slug.
	Name = "tmpl-prefix"
	// Prefix is the canonical snake_case workspace identifier.
	Prefix = "tmpl_prefix"
	// EnvPrefix is the canonical SCREAMING_SNAKE_CASE environment prefix.
	EnvPrefix = "TMPL_PREFIX"
	// PascalName is the canonical PascalCase workspace identifier.
	PascalName = "TmplPrefix"
)

// Error represents a structured workspace error.
type Error struct {
	Code    string
	Message string
}

// NewError constructs a workspace Error with a code and message.
func NewError(code, message string) *Error {
	return &Error{
		Code:    strings.TrimSpace(code),
		Message: strings.TrimSpace(message),
	}
}

// Error implements the standard error interface.
func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Code == "" {
		return e.Message
	}
	return e.Code + ": " + e.Message
}
