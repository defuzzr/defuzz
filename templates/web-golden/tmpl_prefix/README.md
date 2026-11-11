# tmpl_prefix

A static website with plain HTML pages, TypeScript and Vite.

## Tools

Install Node.js and pnpm. Use `engines` and `packageManager` in
[package.json](package.json) for the required versions; `.nvmrc` selects Node.
For design files, see [Git LFS setup](design/sources/README.md).

## Commands

Run these from the project folder:

```bash
pnpm install --frozen-lockfile
pnpm dev
pnpm xtask ci
pnpm build
```

- Install downloads the dependencies recorded in `pnpm-lock.yaml`.
- Dev starts the local server and prints its address.
- CI checks formatting, code mistakes, types, individual parts and the
  built site.
  See [how the check works](docs/how-the-check-works.md).
- Build writes the files to publish into `dist/`.

[Browser tests](tests/e2e/README.md) run separately.

## Folders

- Site: [pages](src/pages/README.md), [components](src/components/README.md),
  [styles](src/styles/README.md), [assets](src/assets/README.md),
  [shared helpers](src/lib/README.md).
- Static files: [public](public/README.md), [fonts](public/fonts/README.md).
- Design: [sources](design/sources/README.md),
  [exports](design/exports/README.md),
  [specs](design/specs/README.md), [tokens](design/tokens/README.md).
- Checks: [unit tests](tests/unit/README.md),
  [browser tests](tests/e2e/README.md),
  [check runner](tools/xtask/README.md).
- [Scripts](scripts/README.md) and [project guides](docs/README.md).

## Licence

Started from the Defuzz website template (MIT, Copyright (c) 2026 defuzzr).
Choose a licence for your project and add a LICENSE file.
