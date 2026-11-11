import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";

const PROJECT = path.resolve(import.meta.dirname, "../..");
// Written in two parts so that this file does not contain them itself.
const PLACEHOLDERS = [`<${"year"}>`, `<${"copyright holder"}>`];

/**
 * Folders that tools generate; they are not part of the project. The one list is the folder
 * lines of .gitignore (node_modules/, dist/, coverage/, test-results/, playwright-report/,
 * .xtask-cache/), plus .git itself. Other runs create and delete files in them at any time.
 */
function generatedFolders(project: string): Set<string> {
  const lines = readFileSync(path.join(project, ".gitignore"), "utf8").split(/\r?\n/);
  const folders = lines.filter((line) => /^[^#!*\s][^*]*\/$/.test(line.trim()));
  return new Set([".git", ...folders.map((line) => line.trim().replace(/\/$/, ""))]);
}

type Reader = {
  readdir: (dir: string) => { name: string; isDirectory(): boolean; isFile(): boolean }[];
  readFile: (file: string) => string;
};
const REAL: Reader = {
  readdir: (dir) => readdirSync(dir, { withFileTypes: true }),
  readFile: (file) => readFileSync(file, "latin1"),
};

/** null when the entry vanished between listing and reading (another run removed it). */
function unlessVanished<T>(read: () => T): T | null {
  try {
    return read();
  } catch (error: unknown) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ENOTDIR") {
      return null;
    }
    throw error;
  }
}

/** Every placeholder left in a project file, as "relative/path: mark". */
function placeholdersIn(project: string, skip: Set<string>, fs: Reader = REAL): string[] {
  const walk = (dir: string): string[] =>
    (unlessVanished(() => fs.readdir(dir)) ?? []).flatMap((entry) => {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        return skip.has(entry.name) ? [] : walk(full);
      }
      if (!entry.isFile()) {
        return [];
      }
      const text = unlessVanished(() => fs.readFile(full)) ?? "";
      return PLACEHOLDERS.filter((mark) => text.includes(mark)).map(
        (mark) => `${path.relative(project, full)}: ${mark}`,
      );
    });
  return walk(project);
}

describe("placeholdersIn", () => {
  const mark = `<${"year"}>`;
  function fakeTree(): string {
    const root = mkdtempSync(path.join(tmpdir(), "licence-walk-"));
    mkdirSync(path.join(root, "test-results", "run"), { recursive: true });
    writeFileSync(path.join(root, "test-results", "run", "copy.md"), mark);
    mkdirSync(path.join(root, "docs"));
    writeFileSync(path.join(root, "docs", "real.md"), mark);
    writeFileSync(path.join(root, "gone.md"), mark);
    return root;
  }

  it("skips generated folders and finds placeholders in real files", () => {
    const root = fakeTree();
    try {
      rmSync(path.join(root, "gone.md"));
      expect(placeholdersIn(root, new Set(["test-results"]))).toEqual([`docs/real.md: ${mark}`]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("skips a file or folder that vanishes between listing and reading; other errors fail", () => {
    const root = fakeTree();
    try {
      const vanishing: Reader = {
        readdir: (dir) => {
          const list = REAL.readdir(dir);
          if (dir === root) {
            rmSync(path.join(root, "gone.md"));
            rmSync(path.join(root, "test-results"), { recursive: true });
          }
          return list;
        },
        readFile: REAL.readFile,
      };
      expect(placeholdersIn(root, new Set(), vanishing)).toEqual([`docs/real.md: ${mark}`]);
      const denied: Reader = {
        readdir: REAL.readdir,
        readFile: () => {
          throw Object.assign(new Error("EACCES: denied"), { code: "EACCES" });
        },
      };
      expect(() => placeholdersIn(root, new Set(), denied)).toThrow(/EACCES/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("takes the generated folders from .gitignore", () => {
    const expected = [
      ".git",
      ".xtask-cache",
      "coverage",
      "dist",
      "node_modules",
      "playwright-report",
      "test-results",
    ];
    expect([...generatedFolders(PROJECT)].sort()).toEqual(expected);
  });
});

describe("licence", () => {
  it("leaves no unfilled licence placeholder in any project file", () => {
    expect(placeholdersIn(PROJECT, generatedFolders(PROJECT))).toEqual([]);
  });

  it("keeps the template licence attribution in the README", () => {
    const readme = readFileSync(path.join(PROJECT, "README.md"), "utf8");
    expect(readme).toMatch(/\bDefuzz\b/);
    expect(readme).toMatch(/\bMIT\b/);
    expect(readme).toMatch(/\bdefuzzr\b/);
  });
});
