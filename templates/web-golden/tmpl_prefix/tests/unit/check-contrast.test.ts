import { spawnSync } from "node:child_process";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";

// Runs scripts/check-contrast.ts as a user would, from another folder, on a copy of the
// files it needs. The copies go in test-results/, inside the project, which git and
// Biome ignore; nothing is written outside the project. (Not node_modules/: Node does
// not run TypeScript files there.) Each run of the tests gets its own folder, so that two
// runs at the same time do not remove each other's copies.
const projectDir = path.resolve(import.meta.dirname, "../..");
const resultsDir = path.join(projectDir, "test-results");
mkdirSync(resultsDir, { recursive: true });
const copiesDir = mkdtempSync(path.join(resultsDir, "check-contrast-test-"));
let copies = 0;

function copyProject(tokens?: (css: string) => string): string {
  copies++;
  const dir = path.join(copiesDir, `copy-${copies}`);
  mkdirSync(dir, { recursive: true });
  for (const part of ["scripts", "src/lib", "design/tokens"]) {
    cpSync(path.join(projectDir, part), path.join(dir, part), { recursive: true });
  }
  if (tokens !== undefined) {
    const file = path.join(dir, "design/tokens/tokens.css");
    writeFileSync(file, tokens(readFileSync(file, "utf8")));
  }
  return dir;
}

function run(dir: string): { status: number | null; output: string } {
  const result = spawnSync(process.execPath, [path.join(dir, "scripts/check-contrast.ts")], {
    cwd: path.parse(dir).root,
    encoding: "utf8",
  });
  return { status: result.status, output: `${result.stdout}${result.stderr}` };
}

// Codes that mean "another run or tool still uses the results folder"; anything else is a real
// problem and fails the run.
const IN_USE = new Set([
  "ENOTEMPTY", // Linux: other runs or tools still have files in it
  "EEXIST", // the same on some systems (POSIX allows either code)
  "ENOENT", // another run already removed it
  "EBUSY", // it is a mount point or open as another process's working folder (macOS)
]);

/** Removes dir only when it is empty and no one else uses it. */
function removeIfUnused(dir: string, rmdir: (dir: string) => void = rmdirSync): void {
  try {
    rmdir(dir);
  } catch (error: unknown) {
    if (!IN_USE.has((error as NodeJS.ErrnoException).code ?? "")) {
      throw error;
    }
  }
}

afterAll(() => {
  rmSync(copiesDir, { recursive: true, force: true });
  removeIfUnused(resultsDir);
});

describe("removeIfUnused", () => {
  const failWith = (code: string) => () => {
    throw Object.assign(new Error(`${code}: x`), { code });
  };
  it("ignores only the codes that mean another run is using the folder", () => {
    for (const code of IN_USE) {
      expect(() => removeIfUnused("x", failWith(code))).not.toThrow();
    }
    for (const code of ["EACCES", "EPERM", "EROFS", "EIO"]) {
      expect(() => removeIfUnused("x", failWith(code))).toThrow(code);
    }
  });
});

/** A failure is one plain line starting "check-contrast: ", exit code 1 and no stack trace. */
function expectOneLine(dir: string, message: RegExp): void {
  const { status, output } = run(dir);
  expect(output.trim().split("\n"), output).toHaveLength(1);
  expect(output.trim()).toMatch(/^check-contrast: /);
  expect(output.trim()).toMatch(message);
  expect(output).not.toMatch(/^\s*at /m);
  expect(status).toBe(1);
}

describe("scripts/check-contrast.ts", () => {
  it("passes from another working folder", () => {
    const { status, output } = run(copyProject());
    expect(output).toMatch(/check-contrast: all \d+ colour pairs pass WCAG AA\./);
    expect(status).toBe(0);
  });

  it("explains a token that is not a hex colour in one line", () => {
    const dir = copyProject((css) => css.replace("--color-link: #0a55c2;", "--color-link: blue;"));
    const { status, output } = run(dir);
    expect(output.trim()).toBe(
      'check-contrast: --color-link in design/tokens/tokens.css is "blue", which is not a hex colour such as #1a2b3c.',
    );
    expect(status).toBe(1);
  });

  it("explains a token missing from one theme in one line", () => {
    const dir = copyProject((css) =>
      css.replace(
        /(:root\[data-theme="dark"\] \{[\s\S]*?)\n {2}--color-link-visited: [^;]+;/,
        "$1",
      ),
    );
    expectOneLine(dir, /the dark theme does not define --color-link-visited\.$/);
  });

  it("explains a missing semicolon in one line", () => {
    const dir = copyProject((css) =>
      css.replace("--color-link: #0a55c2;", "--color-link: #0a55c2"),
    );
    expectOneLine(
      dir,
      /^check-contrast: the value of --color-link in design\/tokens\/tokens\.css could not be read \(is a ";" missing\?\): "#0a55c2 --color-link-hover: #073f91"\.$/,
    );
  });

  it("explains a missing theme rule in one line", () => {
    const dir = copyProject((css) => css.replace(':root[data-theme="dark"] {', ":root.dark {"));
    expectOneLine(dir, /no rule for :root\[data-theme="dark"\]/);
  });
});
