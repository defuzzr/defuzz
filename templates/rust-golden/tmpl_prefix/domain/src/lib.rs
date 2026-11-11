//! Domain layer (`domain/`): pure business logic with no external I/O.
//!
//! Allowed internal dependencies: `foundation`.

/// Returns the canonical workspace name via the `foundation` layer.
pub const fn workspace_name() -> &'static str {
    tmpl_prefix_foundation::NAME
}
