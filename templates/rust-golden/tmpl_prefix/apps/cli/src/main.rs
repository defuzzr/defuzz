//! CLI composition root (`apps/cli/`).
//!
//! Allowed internal dependencies: `foundation`, `domain`, `adapters`.

use tmpl_prefix_adapters as adapters;
use tmpl_prefix_domain as domain;
use tmpl_prefix_foundation::Result;

fn main() -> Result<()> {
    let _ = domain::workspace_name();
    let name = adapters::workspace_name()?;
    println!("{name}");
    Ok(())
}
