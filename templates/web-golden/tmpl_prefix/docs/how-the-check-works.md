# How the check works

Run the check with:

```bash
pnpm xtask ci
```

It runs five steps in order and stops at the first one that fails. It
never changes your files and never needs the network, once
`pnpm xtask prepare-scaffold` has installed the tools.

## The steps

| Step                          | What it checks                 | To see more                         |
| ----------------------------- | ------------------------------ | ----------------------------------- |
| format and lint (biome ci)    | formatting and common mistakes | `pnpm lint`, fix with `pnpm format` |
| type check (tsc)              | TypeScript types               | `pnpm typecheck`                    |
| unit tests (vitest run)       | the tests in `tests/unit/`     | `pnpm test`                         |
| production build (vite build) | the site builds into `dist/`   | `pnpm build`                        |
| build output check (dist/)    | links and files in `dist/`     | `pnpm xtask check-dist`             |

Lint means a tool reads the code and reports common mistakes. The unit
tests also cover the colours: they list every colour pair the
stylesheet declares, check its contrast, and fail when a rule uses
colour in a way they cannot read. `pnpm contrast` prints the same pairs
as a table.

## What a failure looks like

The tool output of the failing step is shown first. Then a small table
lists all five steps as `PASS`, `FAIL` or `SKIPPED`. A step after the
failing one is `SKIPPED`: it did not run.

The very last line on the screen comes from pnpm, not from this
project: `[ELIFECYCLE] Command failed with exit code 1.` The line just
above it is the check's own sentence, starting with `xtask:`. It says
what failed and which command shows more. A real example, with a unit
test failing:

```text
-------------------------------+--------
 Step                          | Status
-------------------------------+--------
 format and lint (biome ci)    | PASS
 type check (tsc)              | PASS
 unit tests (vitest run)       | FAIL
 production build (vite build) | SKIPPED
 build output check (dist/)    | SKIPPED
-------------------------------+--------
xtask: the unit tests failed. Run "pnpm test" to see the details.
[ELIFECYCLE] Command failed with exit code 1.
```

The command exits with a non-zero code. Run the command named in the
xtask line to see the full details.

When every step passes, the last line is:

```text
xtask: all checks passed.
```

## Other messages

If a tool cannot start, is killed, or ends with exit code 126 or 127,
the last line names it and says how to repair the install. The same
happens when a step fails and the tool then fails even when asked only
for its version, or does not answer within 10 seconds (`--version`
reads none of your files, so this means
its installed files are broken or missing). The advice is to delete
`node_modules` first, because `pnpm install` alone does not bring back
files that are missing from it (printed as one line, wrapped here):

```text
xtask: <tool> could not run (<reason>). Reinstall: delete the
node_modules folder, then run "pnpm xtask prepare-scaffold".
```

If you press Ctrl-C, the running tool stops too, and the last line is:

```text
xtask: stopped by SIGINT.
```

`pnpm xtask help` lists the commands. A wrong command prints the usage
line `pnpm xtask <prepare-scaffold|ci|e2e|check-dist|help>`.

## When the tools are missing

If `node_modules` is missing, `pnpm xtask ci` lets pnpm install the
packages from `pnpm-lock.yaml` first, by itself, and then runs the
check. Only when the runner is started without pnpm, as
`node tools/xtask/main.ts ci`, or when pnpm cannot install, does the
check print (one line, wrapped here):

```text
xtask: the project's tools are not installed. Run
"pnpm xtask prepare-scaffold" first.
```

## Where the tools keep their files

During `pnpm xtask ci`, nothing is written outside the project. Inside
it, the tools keep their caches and temporary files in `.xtask-cache/`,
`node_modules/.vite-temp/` and `node_modules/.cache/`, and the tests
use `test-results/`. Git ignores all of them. Two exceptions:
`pnpm xtask e2e` lets the browser use the system temporary folder, and
pnpm keeps its package store outside the project.

Each run that starts a tool gets its own temporary folder,
`.xtask-cache/tmp/run-XXXXXX/`, and removes it when it ends, also after
a failure or Ctrl-C. So two runs at the same time do not disturb each
other. Before its first tool starts, a run also removes the folders of
runs that have ended (a run that was killed), and empties the compile
cache when it is larger than 20 MB. It never removes the folder of a
run that is still going.

Removing is best effort: read-only leftovers of a test are made
writable first, and what still cannot be removed never stops the
check. Then xtask prints one note, and you can remove the folder by
hand when no check is running:

```text
chmod -R u+rwx .xtask-cache && rm -rf .xtask-cache
```

You can delete `.xtask-cache/` and the other folders named above
whenever no command is running; the next run makes them again.

A known limit: keeping every file inside the project holds only for
`pnpm xtask ci`. The package scripts run directly (`pnpm test`,
`pnpm lint`, `pnpm format`, `pnpm typecheck`, `pnpm build`, `pnpm dev`
and `pnpm preview`) let the tools use the system temporary folder and
their own cache folder in your home folder. Vitest uses the temporary
folder, Biome uses its cache folder, and Node's compile cache (through
tsc and Vite) uses the temporary folder. `pnpm contrast` writes nothing.

## Rules for the build output

The last step reads every file in `dist/` and reports:

- a broken internal link: a link to a page or an `id` that does not
  exist;
- a missing local file: an image, script, style or font that is not
  in `dist/`;
- a remote address loaded at runtime: a script, style, font, image or
  fetch call from another website.

A plain link (`<a href>`) to an external page is allowed, because the
browser only goes there when someone clicks it.

## Known limits

- The build output check finds a remote address only when it is
  written as a plain string. An address that a script glues together
  while the page runs is not found.
- It reads HTML, CSS and JavaScript files only. A standalone `.svg`
  file is not scanned for remote addresses.
- The colour tests read only `src/styles/main.css` and
  `design/tokens/tokens.css`. Another stylesheet, a `style` attribute
  in a page and the colours inside an SVG file are not checked.
- The browser tests are optional and not part of the check.
- `pnpm dev` and `pnpm preview` do not show `404.html` for a missing
  address.
