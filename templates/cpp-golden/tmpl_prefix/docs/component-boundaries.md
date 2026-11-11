# Component boundaries

Keep reusable logic independent of CLI, filesystem, network and process
orchestration.
Keep runners thin; inject effects at the boundary and test logic with fixtures.
Record public APIs and purpose in COMPONENTS.md. Never begin componentize
automatically.

The current componentize AST gate is Python-only. This template documents
boundaries only; it does not claim Rust/TypeScript AST enforcement.
