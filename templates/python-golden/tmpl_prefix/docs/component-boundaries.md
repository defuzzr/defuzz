# Component boundaries

Keep reusable logic independent of CLI, filesystem, network and process
orchestration.
Keep runners thin; inject effects at the boundary and test logic with fixtures.
Record public APIs and purpose in COMPONENTS.md. Never begin componentize
automatically.

Python: `xtask componentize-gate <source.py> ...` uses the installed
hermes_audit architecture gate with role component. Missing optional gate prints
notice and exits zero; this is not completion evidence. Use
componentize/spec.example.json only after explicit user approval, with real
fixture paths and commands.
