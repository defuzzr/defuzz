# Unit tests

Name tests `*.test.ts` or `*.spec.ts`; Vitest selects only this folder and
runs in Node.
From the project folder, run `pnpm test`; these tests also run in
`pnpm xtask ci`.
Project TypeScript imports need `.ts`; package and `node:` imports do not.
