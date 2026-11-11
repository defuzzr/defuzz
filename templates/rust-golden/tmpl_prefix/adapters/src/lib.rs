//! Adapters layer (`adapters/`): external I/O and integration boundaries.
//!
//! Allowed internal dependencies: `foundation`, `domain`.

use tmpl_prefix_foundation::Result;

/// Verifies wiring to the `foundation` and `domain` layers.
pub fn workspace_name() -> Result<&'static str> {
    Ok(tmpl_prefix_domain::workspace_name())
}
