# Browser tests

Name Playwright tests `*.e2e.ts`; they run separately from `pnpm xtask ci`.
From the project folder, download Chromium with
`pnpm exec playwright install chromium`.
Run `pnpm xtask e2e` to build and serve the site, then run matching tests.
