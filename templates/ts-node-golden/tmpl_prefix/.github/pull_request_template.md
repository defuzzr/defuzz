# Summary

- Describe what changed and why.

## Architectural Checklist

- [ ] Layer dependency rules
  (`foundation <= domain <= adapters <= apps`) are respected.
- [ ] No `any`, non-null assertions (`!`), `enum`, `namespace`, or
  parameter properties were introduced.
- [ ] Configuration changes (if any) are validated in
  `tmpl-prefix-config` and
  documented in `.env.example`.
- [ ] `pnpm xtask ci` passes locally with zero warnings.
