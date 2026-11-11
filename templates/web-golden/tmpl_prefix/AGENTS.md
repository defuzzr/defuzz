# Rules for agents working in this project

- Work only inside this one project root. The only `package.json` below it
  is the locked `tools/xtask/package.json`; never add another. Files go here:

| Folder            | What goes there                                                                    |
| ----------------- | ---------------------------------------------------------------------------------- |
| `design/sources/` | handed-over design files, no code                                                  |
| `design/tokens/`  | design tokens: colour, type, space (`tokens.css`)                                  |
| `design/specs/`   | written specs and notes                                                            |
| `design/exports/` | exported images from design tools                                                  |
| `public/`         | files served as-is (favicon, robots.txt); README.md and .gitkeep are not published |
| `public/fonts/`   | self-hosted fonts only; may be empty; keep `.gitkeep`                              |
| `src/pages/`      | the HTML pages                                                                     |
| `src/components/` | HTML partials, the script entry `site.ts`, component TypeScript                    |
| `src/styles/`     | stylesheets (import the tokens; never redefine them)                               |
| `src/assets/`     | images the pages import                                                            |
| `src/lib/`        | small shared TypeScript helpers                                                    |
| `tests/unit/`     | unit tests, named `*.test.ts` (or `*.spec.ts`)                                     |
| `tests/e2e/`      | optional browser tests, `*.e2e.ts`; run with `pnpm xtask e2e`                      |
| `scripts/`        | helper scripts (`check-contrast.ts`; run with `pnpm contrast`)                     |
| `docs/`           | project docs (not README)                                                          |
| `tools/xtask/`    | the check runner (locked)                                                          |

- In HTML, reference `src` files as `/src/...`. Pull in partials from
  `src/components/` with `<!-- include: name.html -->`; mark the current page
  with `current=` on the header include.
- Never redefine `design/tokens/tokens.css` tokens in `src/styles/`. Colours:
  only `var(--color-*)`, but only system colours (Highlight) in `@media
  (forced-colors: active)`; full rules: tests/unit/stylesheet.test.ts top.
- Never load a remote URL at runtime: no CDN, remote font, or analytics. Ask
  before adding a dependency or moving or deleting files.
- Do not edit locked files without asking: `package.json`, `pnpm-lock.yaml`,
  `biome.json`, `tsconfig.json`, `vite.config.ts`, `playwright.config.ts`,
  `.nvmrc`, `.npmrc`, `.github/workflows/*`, `tools/xtask/**`.
- Never edit, move or commit the generated `.xtask-cache/`, `dist/` and
  `node_modules/`, or hand-edit the scaffolder's AGENTS.md, TOOLS.lock, .adopt/.
- Run `pnpm xtask ci` before you say work is done and report its real
  result. On failure its last `xtask:` line says what failed.
