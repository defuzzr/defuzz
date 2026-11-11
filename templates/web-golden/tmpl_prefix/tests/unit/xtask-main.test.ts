import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import {
  chmodSync,
  closeSync,
  copyFileSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import {
  CACHE_FOLDER,
  CheckFailure,
  COMPILE_CACHE_BUDGET,
  type Command,
  cacheFolders,
  childEnvironment,
  ciSteps,
  commandDisplay,
  crashReason,
  createAnsiStripper,
  createLineFilter,
  createOutput,
  type ExecResult,
  e2eSteps,
  HELP_TEXT,
  isEntryPoint,
  isProcessAlive,
  isRunFolderStale,
  isStackFrame,
  LEFTOVER_NOTE,
  main,
  OWNER_FILE,
  prepareRunFolders,
  RUN_PREFIX,
  type RunnerIo,
  type RunOwner,
  removeRunFolder,
  removeTree,
  renderSummary,
  runSteps,
  STALE_AGE_MS,
  type Step,
  type StreamId,
  sendSignal,
  summaryRows,
  toolEnvironment,
  tryMakeFolder,
  tryWriteAll,
  USAGE,
  unexpectedProblemMessage,
  VERSION_PROBE_TIMEOUT_MS,
  wantsColour,
} from "../../tools/xtask/main.ts";

const LABELS = ["format", "types", "unit tests", "build", "dist check"];
const PROJECT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const MAIN = path.join(PROJECT, "tools", "xtask", "main.ts");
// "pnpm install" does not repair files missing from an existing node_modules, so the
// advice is to delete it first.
const REINSTALL =
  'Reinstall: delete the node_modules folder, then run "pnpm xtask prepare-scaffold".';

// The failure sentences of "xtask ci", word for word: the docs quote them.
const CI_FAILURES = [
  'xtask: the format and lint check failed. Run "pnpm lint" to see the details, and "pnpm format" to fix formatting.',
  'xtask: the type check failed. Run "pnpm typecheck" to see the details.',
  'xtask: the unit tests failed. Run "pnpm test" to see the details.',
  'xtask: the production build failed. Run "pnpm build" to see the details.',
  'xtask: the build output check found problems in dist/. Run "pnpm xtask check-dist" to see the list.',
];

// The commands of "xtask ci" in order, grouped by step.
const CI_COMMANDS = [
  ["biome ci ."],
  ["tsc -p tsconfig.json", "tsc -p tools/xtask/tsconfig.json"],
  ["vitest run"],
  ["vite build"],
  ["check dist/"],
];

const OK: ExecResult = { code: 0, signal: null, startError: undefined };
const exited = (code: number): ExecResult => ({ code, signal: null, startError: undefined });

type Sink = (stream: StreamId, text: string) => void;
type FakeExec = (command: Command, sink: Sink) => ExecResult | Promise<ExecResult>;

interface Fake {
  readonly io: RunnerIo;
  /** Every command started, and "check dist/" for the build output check. */
  readonly calls: string[];
  /** The tools asked whether they can start at all (only after a failed command). */
  readonly probes: string[];
  readonly writes: Array<[StreamId, string]>;
  text(): string;
  lines(): string[];
  lastLine(): string;
  statuses(): string[];
}

function fakeIo(
  exec: FakeExec = () => OK,
  options: { colour?: boolean; distProblems?: string[]; broken?: readonly string[] } = {},
): Fake {
  const calls: string[] = [];
  const probes: string[] = [];
  const writes: Array<[StreamId, string]> = [];
  const text = (): string => writes.map(([, chunk]) => chunk).join("");
  const lines = (): string[] => text().replace(/\n$/, "").split("\n");
  return {
    io: {
      colour: options.colour ?? false,
      write: (stream, chunk) => {
        writes.push([stream, chunk]);
      },
      exec: async (command, sink) => {
        calls.push(commandDisplay(command));
        return exec(command, sink);
      },
      checkDist: async () => {
        calls.push("check dist/");
        return options.distProblems ?? [];
      },
      canStart: async (tool) => {
        probes.push(tool.label);
        return !(options.broken ?? []).includes(tool.label);
      },
    },
    calls,
    probes,
    writes,
    text,
    lines,
    lastLine: () => lines().at(-1) ?? "",
    statuses: () =>
      lines().flatMap((line) => {
        const match = / \| (PASS|FAIL|SKIPPED)$/.exec(line);
        return match?.[1] === undefined ? [] : [match[1]];
      }),
  };
}

const CI_OPTIONS = { success: "xtask: all checks passed.", command: "ci" };
const E2E_OPTIONS = { success: "xtask: all browser tests passed.", command: "e2e" };

function runCi(fake: Fake): Promise<number> {
  return runSteps(ciSteps(PROJECT), fake.io, CI_OPTIONS);
}

describe("runSteps with the steps of ci", () => {
  it("passes when every command passes: five PASS rows and the success line", async () => {
    const fake = fakeIo();
    expect(await runCi(fake)).toBe(0);
    expect(fake.statuses()).toEqual(["PASS", "PASS", "PASS", "PASS", "PASS"]);
    expect(fake.calls).toEqual(CI_COMMANDS.flat());
    expect(fake.lastLine()).toBe("xtask: all checks passed.");
    expect(fake.writes.at(-1)?.[0]).toBe(1);
  });

  for (const [index, failure] of CI_FAILURES.entries()) {
    const step = index + 1;
    it(`stops at step ${step} when it fails and ends with its sentence`, async () => {
      const failing = CI_COMMANDS[index]?.[0];
      const fake = fakeIo((command) => (commandDisplay(command) === failing ? exited(1) : OK), {
        distProblems: step === 5 ? ["dist/index.html: a problem"] : [],
      });
      expect(await runCi(fake)).toBe(1);
      expect(fake.statuses()).toEqual([
        ...Array<string>(index).fill("PASS"),
        "FAIL",
        ...Array<string>(4 - index).fill("SKIPPED"),
      ]);
      // Nothing after the failing command was started.
      expect(fake.calls).toEqual([...CI_COMMANDS.slice(0, index).flat(), failing]);
      expect(fake.lastLine()).toBe(failure);
      expect(fake.writes.at(-1)?.[0]).toBe(2);
    });
  }

  it("does not start the second type check when the first one fails", async () => {
    const fake = fakeIo((command) =>
      commandDisplay(command) === "tsc -p tsconfig.json" ? exited(2) : OK,
    );
    expect(await runCi(fake)).toBe(1);
    expect(fake.calls).toEqual(["biome ci .", "tsc -p tsconfig.json"]);
    expect(fake.lastLine()).toBe(CI_FAILURES[1]);
  });

  it("fails the step when the second type check fails", async () => {
    const fake = fakeIo((command) =>
      commandDisplay(command).includes("tools/xtask") ? exited(1) : OK,
    );
    expect(await runCi(fake)).toBe(1);
    expect(fake.statuses()).toEqual(["PASS", "FAIL", "SKIPPED", "SKIPPED", "SKIPPED"]);
    expect(fake.lastLine()).toBe(CI_FAILURES[1]);
  });

  it("treats any exit code other than 0 as a failure", async () => {
    for (const code of [1, 2, 3, 255]) {
      const fake = fakeIo((command) => (command.args[0] === "run" ? exited(code) : OK));
      expect(await runCi(fake)).toBe(1);
      expect(fake.statuses()).toEqual(["PASS", "PASS", "FAIL", "SKIPPED", "SKIPPED"]);
      expect(fake.lastLine()).toBe(CI_FAILURES[2]);
    }
  });

  it("echoes every command before its output", async () => {
    const fake = fakeIo((command, sink) => {
      sink(1, `output of ${commandDisplay(command)}\n`);
      return OK;
    });
    await runCi(fake);
    const lines = fake.lines();
    expect(lines.indexOf("+ vitest run")).toBeLessThan(lines.indexOf("output of vitest run"));
    expect(lines.indexOf("+ biome ci .")).toBe(0);
    expect(lines).toContain("+ check dist/");
    expect(lines).toContain("Build output check: no problems found in dist/.");
  });

  it("lists the build output problems before the summary", async () => {
    const fake = fakeIo(undefined, { distProblems: ["dist/a.html: one", "dist/b.css: two"] });
    expect(await runCi(fake)).toBe(1);
    const lines = fake.lines();
    expect(lines).toContain("dist/a.html: one");
    expect(lines).toContain("Build output check: 2 problem(s) found in dist/.");
    const header = lines.findIndex((line) => /^ Step +\| Status$/.test(line));
    expect(header).toBeGreaterThan(-1);
    expect(lines.indexOf("dist/b.css: two")).toBeLessThan(header);
  });
});

describe("runSteps when a tool could not run", () => {
  const cases: Array<[string, ExecResult, string]> = [
    [
      "a signal",
      { code: null, signal: "SIGKILL", startError: undefined },
      "it was stopped by signal SIGKILL",
    ],
    ["exit code 127", exited(127), "exit code 127: a program it needs was not found"],
    ["exit code 126", exited(126), "exit code 126: a program it needs cannot be run"],
    [
      "a start error",
      { code: null, signal: null, startError: "EACCES" },
      "it could not be started: EACCES",
    ],
    [
      "a missing program",
      { code: null, signal: null, startError: "ENOENT" },
      "it could not be started: ENOENT",
    ],
    [
      "no exit code",
      { code: null, signal: null, startError: undefined },
      "it stopped without an exit code",
    ],
  ];
  for (const [name, result, reason] of cases) {
    it(`blames the tool, not the check, for ${name}`, async () => {
      const fake = fakeIo((command) => (command.args[0] === "run" ? result : OK));
      expect(await runCi(fake)).toBe(1);
      expect(fake.statuses()).toEqual(["PASS", "PASS", "FAIL", "SKIPPED", "SKIPPED"]);
      expect(fake.calls).not.toContain("vite build");
      expect(fake.lastLine()).toBe(`xtask: vitest could not run (${reason}). ${REINSTALL}`);
    });
  }

  it("keeps the step's own sentence when a tool's stderr ends with Node's crash block", async () => {
    // The tool's output alone never decides: here the tool can still start (canStart), so
    // the crash block is treated as an error the check found.
    const fake = fakeIo((command, sink) => {
      if (command.kind === "tool" && command.args[0] === "ci") {
        sink(2, "node:internal/x:1\nError: spawnSync biome EACCES\n");
        sink(
          2,
          "    at spawnSync (node:child_process:900:24) {\n  errno: -13,\n  code: 'EACCES'\n}\n\nNode.js v26.12.1\n",
        );
        return exited(1);
      }
      return OK;
    });
    expect(await runCi(fake)).toBe(1);
    expect(fake.statuses()).toEqual(["FAIL", "SKIPPED", "SKIPPED", "SKIPPED", "SKIPPED"]);
    expect(fake.lastLine()).toBe(CI_FAILURES[0]);
    expect(fake.text()).not.toContain("could not run");
    // The tool's own error stays visible above the table, only the frame is left out.
    expect(fake.text()).toContain("Error: spawnSync biome EACCES\n");
    expect(fake.text()).toContain("  code: 'EACCES'");
    expect(fake.text()).not.toContain("at spawnSync");
  });

  const BROKEN =
    "it fails even when asked only for its version, so its installed files are broken or missing";

  it("blames a broken install when the failing tool cannot even print its version", async () => {
    const fake = fakeIo((command) => (command.args[0] === "ci" ? exited(1) : OK), {
      broken: ["biome"],
    });
    expect(await runCi(fake)).toBe(1);
    expect(fake.statuses()).toEqual(["FAIL", "SKIPPED", "SKIPPED", "SKIPPED", "SKIPPED"]);
    expect(fake.probes).toEqual(["biome"]);
    expect(fake.lastLine()).toBe(`xtask: biome could not run (${BROKEN}). ${REINSTALL}`);
  });

  it("asks whether the tool can start only after it failed, and keeps the step's sentence when it can", async () => {
    const passing = fakeIo();
    expect(await runCi(passing)).toBe(0);
    expect(passing.probes).toEqual([]);
    for (const [index, failing] of CI_COMMANDS.slice(0, 4).entries()) {
      const fake = fakeIo((command) => (commandDisplay(command) === failing[0] ? exited(1) : OK));
      expect(await runCi(fake)).toBe(1);
      expect(fake.probes).toEqual([["biome", "tsc", "vitest", "vite"][index]]);
      expect(fake.lastLine()).toBe(CI_FAILURES[index]);
    }
  });

  it("blames the broken tool for the unit tests and the build too", async () => {
    const vitest = fakeIo((command) => (command.args[0] === "run" ? exited(1) : OK), {
      broken: ["vitest"],
    });
    expect(await runCi(vitest)).toBe(1);
    expect(vitest.lastLine()).toBe(`xtask: vitest could not run (${BROKEN}). ${REINSTALL}`);
    const vite = fakeIo((command) => (command.args[0] === "build" ? exited(1) : OK), {
      broken: ["vite"],
    });
    expect(await runSteps(e2eSteps(), vite.io, E2E_OPTIONS)).toBe(1);
    expect(vite.lastLine()).toBe(`xtask: vite could not run (${BROKEN}). ${REINSTALL}`);
  });

  it("does not ask again when the tool already could not run", async () => {
    const fake = fakeIo((command) => (command.args[0] === "ci" ? exited(127) : OK), {
      broken: ["biome"],
    });
    expect(await runCi(fake)).toBe(1);
    expect(fake.probes).toEqual([]);
    expect(fake.lastLine()).toContain("exit code 127");
  });

  it("keeps the check's own sentence when Node.js vX is not the last line", async () => {
    const fake = fakeIo((command, sink) => {
      if (command.args[0] === "ci") {
        sink(2, "Node.js v26.12.1\nsrc/a.ts lint error\n");
        return exited(1);
      }
      return OK;
    });
    await runCi(fake);
    expect(fake.lastLine()).toBe(CI_FAILURES[0]);
  });

  // An uncaught error in the user's own plugin makes vite end with Node's crash block.
  const pluginCrash = (sink: Sink): ExecResult => {
    sink(1, "✓ built in 80ms\n");
    sink(2, 'file:///p/vite.config.ts:12\n        throw new Error("late failure in my plugin");\n');
    sink(2, "              ^\n\nError: late failure in my plugin\n");
    sink(2, "    at Timeout._onTimeout (file:///p/vite.config.ts:12:15)\n");
    sink(2, "    at listOnTimeout (node:internal/timers:605:17)\n\nNode.js v26.12.1\n");
    return exited(1);
  };

  it("reports an uncaught error in the user's vite plugin as a failed build in ci", async () => {
    const fake = fakeIo((command, sink) => (command.args[0] === "build" ? pluginCrash(sink) : OK));
    expect(await runCi(fake)).toBe(1);
    expect(fake.statuses()).toEqual(["PASS", "PASS", "PASS", "FAIL", "SKIPPED"]);
    expect(fake.lastLine()).toBe(CI_FAILURES[3]);
    expect(fake.text()).toContain("Error: late failure in my plugin\n");
    expect(fake.text()).not.toContain("could not run");
  });

  it("reports an uncaught error in the user's vite plugin as a failed build in e2e", async () => {
    const fake = fakeIo((command, sink) => (command.args[0] === "build" ? pluginCrash(sink) : OK));
    expect(await runSteps(e2eSteps(), fake.io, E2E_OPTIONS)).toBe(1);
    expect(fake.statuses()).toEqual(["FAIL", "SKIPPED"]);
    expect(fake.calls).toEqual(["vite build"]);
    expect(fake.lastLine()).toBe(CI_FAILURES[3]);
    expect(fake.text()).toContain("Error: late failure in my plugin\n");
  });

  it("turns a throwing runner into a failure with one plain line", async () => {
    const fake = fakeIo((command) => {
      if (command.args[0] === "build") {
        throw new Error("spawn exploded\n    at x (/a/b.js:1:2)");
      }
      return OK;
    });
    expect(await runCi(fake)).toBe(1);
    expect(fake.statuses()).toEqual(["PASS", "PASS", "PASS", "FAIL", "SKIPPED"]);
    expect(fake.lastLine()).toBe(
      `xtask: unexpected problem: spawn exploded. Run "node tools/xtask/main.ts ci" again; if it repeats, reinstall with "pnpm xtask prepare-scaffold".`,
    );
    expect(fake.text()).not.toMatch(/^\s+at /m);
  });

  it("turns a rejecting runner into a failure with one plain line", async () => {
    const fake = fakeIo((command) =>
      command.args[0] === "ci" ? Promise.reject(new Error("no such thing")) : OK,
    );
    expect(await runCi(fake)).toBe(1);
    expect(fake.statuses()).toEqual(["FAIL", "SKIPPED", "SKIPPED", "SKIPPED", "SKIPPED"]);
    expect(fake.calls).toEqual(["biome ci ."]);
    expect(fake.lastLine()).toMatch(/^xtask: unexpected problem: no such thing\. Run /);
  });

  it("uses a CheckFailure's own message", async () => {
    const fake = fakeIo((command) => {
      if (command.args[0] === "run") {
        throw new CheckFailure(
          'xtask: vitest is not installed. Run "pnpm xtask prepare-scaffold" first.',
        );
      }
      return OK;
    });
    expect(await runCi(fake)).toBe(1);
    expect(fake.lastLine()).toBe(
      'xtask: vitest is not installed. Run "pnpm xtask prepare-scaffold" first.',
    );
  });

  it("fails when the build output check cannot read dist/", async () => {
    const fake = fakeIo();
    const io: RunnerIo = {
      ...fake.io,
      checkDist: () => Promise.reject(new Error("Cannot find module 'dist-check.ts'")),
    };
    expect(await runSteps(ciSteps(PROJECT), io, CI_OPTIONS)).toBe(1);
    expect(fake.statuses()).toEqual(["PASS", "PASS", "PASS", "PASS", "FAIL"]);
    expect(fake.lastLine()).toMatch(
      /^xtask: unexpected problem: Cannot find module 'dist-check.ts'\./,
    );
  });
});

describe("runSteps with the steps of e2e", () => {
  it("builds, then runs the browser tests", async () => {
    const fake = fakeIo();
    expect(await runSteps(e2eSteps(), fake.io, E2E_OPTIONS)).toBe(0);
    expect(fake.calls).toEqual(["vite build", "playwright test"]);
    expect(fake.statuses()).toEqual(["PASS", "PASS"]);
    expect(fake.lastLine()).toBe("xtask: all browser tests passed.");
  });

  it("ends with the browser tests' sentence when they fail", async () => {
    const fake = fakeIo((command) => (command.args[0] === "test" ? exited(1) : OK));
    expect(await runSteps(e2eSteps(), fake.io, E2E_OPTIONS)).toBe(1);
    expect(fake.statuses()).toEqual(["PASS", "FAIL"]);
    expect(fake.lastLine()).toBe(
      'xtask: the browser tests failed. Run "pnpm exec playwright test" to see the details.',
    );
  });

  it("blames playwright when it is stopped by a signal", async () => {
    const killed: ExecResult = { code: null, signal: "SIGKILL", startError: undefined };
    const fake = fakeIo((command) => (command.args[0] === "test" ? killed : OK));
    expect(await runSteps(e2eSteps(), fake.io, E2E_OPTIONS)).toBe(1);
    expect(fake.lastLine()).toBe(
      `xtask: playwright could not run (it was stopped by signal SIGKILL). ${REINSTALL}`,
    );
  });
});

describe("runSteps with fake steps", () => {
  function steps(results: ReadonlyArray<boolean | Error>, log: string[]): Step[] {
    return results.map((result, index) => ({
      label: `step ${index + 1}`,
      failure: `step ${index + 1} failed.`,
      run: async () => {
        log.push(`step ${index + 1}`);
        if (result instanceof Error) {
          throw result;
        }
        return result ? { ok: true } : { ok: false };
      },
    }));
  }
  const options = { success: "all done.", command: "test" };

  it("runs every step when all pass", async () => {
    const log: string[] = [];
    const fake = fakeIo();
    expect(await runSteps(steps([true, true, true, true, true], log), fake.io, options)).toBe(0);
    expect(log).toHaveLength(5);
    expect(fake.statuses()).toEqual(["PASS", "PASS", "PASS", "PASS", "PASS"]);
    expect(fake.lastLine()).toBe("all done.");
  });

  for (let k = 1; k <= 5; k += 1) {
    it(`stops at a failing step ${k}`, async () => {
      const log: string[] = [];
      const fake = fakeIo();
      const results = [1, 2, 3, 4, 5].map((n) => n !== k);
      expect(await runSteps(steps(results, log), fake.io, options)).toBe(1);
      expect(log).toEqual([1, 2, 3, 4, 5].slice(0, k).map((n) => `step ${n}`));
      expect(fake.statuses()).toEqual(
        summaryRows(LABELS, results.slice(0, k)).map((r) => r.status),
      );
      expect(fake.lastLine()).toBe(`step ${k} failed.`);
    });
  }

  it("turns a thrown error into FAIL and one plain line", async () => {
    const log: string[] = [];
    const fake = fakeIo();
    const code = await runSteps(
      steps([true, new Error("bad\nsecond line")], log),
      fake.io,
      options,
    );
    expect(code).toBe(1);
    expect(fake.statuses()).toEqual(["PASS", "FAIL"]);
    expect(fake.lastLine()).toBe(
      'xtask: unexpected problem: bad. Run "node tools/xtask/main.ts test" again; if it repeats, reinstall with "pnpm xtask prepare-scaffold".',
    );
  });
});

describe("output", () => {
  it("ends tool output that lacks a newline before the next line of xtask", async () => {
    const fake = fakeIo((command, sink) => {
      if (command.args[0] === "ci") {
        sink(1, "no newline at end");
      }
      if (command.args[1] === "tsconfig.json") {
        sink(2, "nor here");
      }
      return OK;
    });
    await runCi(fake);
    expect(fake.text()).toContain("no newline at end\n+ tsc -p tsconfig.json\n");
    expect(fake.text()).toContain("nor here\n+ tsc -p tools/xtask/tsconfig.json\n");
    expect(fake.writes).toContainEqual([1, "\n"]);
    expect(fake.writes).toContainEqual([2, "\n"]);
  });

  it("removes colour codes when colours are off, also when split across pieces", async () => {
    const fake = fakeIo((command, sink) => {
      sink(2, "\u001b[31m[UNRESOLVED_IMPORT] \u001b[0mCould not resolve\n\u001b[38;5;");
      sink(2, "246m   ╭─\u001b[0m frame\n\u001b]8;;https://x.test\u0007link\u001b]8;;\u0007\n");
      return command.args[0] === "build" ? exited(1) : OK;
    });
    expect(await runCi(fake)).toBe(1);
    expect(fake.text()).not.toContain("\u001b");
    expect(fake.text()).toContain("[UNRESOLVED_IMPORT] Could not resolve\n   ╭─ frame\nlink\n");
  });

  it("keeps colour codes when colours are on", async () => {
    const fake = fakeIo(
      (_command, sink) => {
        sink(1, "\u001b[32mok\u001b[39m\n");
        return OK;
      },
      { colour: true },
    );
    await runCi(fake);
    expect(fake.text()).toContain("\u001b[32mok\u001b[39m\n");
  });

  it("leaves out stack frames and the empty error dump after them", async () => {
    const fake = fakeIo((command, sink) => {
      if (command.args[0] === "build") {
        sink(2, "Build failed with 1 error:\n[UNRESOLVED_IMPORT] Could not resolve './x.css'\n\n");
        sink(2, "    at aggregate (file:///p/node_modules/rolldown/dist/x.mjs:1:2)\n");
        sink(2, "    at async CAC.<anonymous> (file:///p/node_modules/vite/dist/cli.js:789:3) {\n");
        sink(2, "  errors: [Getter/Setter]\n}\n");
        return exited(1);
      }
      return OK;
    });
    await runCi(fake);
    const text = fake.text();
    expect(text).toContain("[UNRESOLVED_IMPORT] Could not resolve './x.css'\n");
    expect(text).not.toContain(" at ");
    expect(text).not.toContain("errors: [Getter/Setter]");
    expect(fake.lines()).not.toContain("}");
    expect(fake.lastLine()).toBe(CI_FAILURES[3]);
  });

  it("passes 5 MB of output through unchanged", async () => {
    const big = `${"x".repeat(99)}\n`.repeat(50_000);
    const fake = fakeIo((command, sink) => {
      if (command.args[0] === "run") {
        for (let i = 0; i < big.length; i += 65_536) {
          sink(1, big.slice(i, i + 65_536));
        }
      }
      return OK;
    });
    expect(await runCi(fake)).toBe(0);
    expect(fake.text()).toContain(`+ vitest run\n${big}+ vite build\n`);
  });

  it("createOutput writes xtask lines to the stream asked for", () => {
    const fake = fakeIo();
    const output = createOutput(fake.io);
    output.line(2, "to stderr");
    output.line(1, "to stdout");
    expect(fake.writes).toEqual([
      [2, "to stderr\n"],
      [1, "to stdout\n"],
    ]);
  });
});

describe("main", () => {
  async function runMain(argv: string[]): Promise<[number, Fake]> {
    const fake = fakeIo(() => {
      throw new Error("no command may run");
    });
    return [await main(argv, fake.io), fake];
  }

  it("prints the help text with exit code 0", async () => {
    for (const word of ["help", "--help", "-h"]) {
      const [code, fake] = await runMain([word]);
      expect(code).toBe(0);
      expect(fake.text()).toBe(`${HELP_TEXT}\n`);
    }
  });

  it("rejects a missing or unknown command with one line and exit code 1", async () => {
    const [code, fake] = await runMain(["bogus"]);
    expect(code).toBe(1);
    expect(fake.writes).toEqual([[2, `xtask: unknown command "bogus". Usage: ${USAGE}\n`]]);
    const [code2, fake2] = await runMain([]);
    expect(code2).toBe(1);
    expect(fake2.lastLine()).toBe(`xtask: no command given. Usage: ${USAGE}`);
  });

  it("rejects extra arguments", async () => {
    const [code, fake] = await runMain(["ci", "now"]);
    expect(code).toBe(1);
    expect(fake.lastLine()).toBe(`xtask: "ci" takes no extra arguments. Usage: ${USAGE}`);
    expect(fake.calls).toEqual([]);
  });

  it("blames a broken Biome when prepare-scaffold cannot format", async () => {
    const fake = fakeIo((command) => (command.kind === "tool" ? exited(1) : OK), {
      broken: ["biome"],
    });
    expect(await main(["prepare-scaffold"], fake.io)).toBe(1);
    expect(fake.calls).toEqual([
      "pnpm install --frozen-lockfile",
      "biome check --write --linter-enabled=false .",
    ]);
    expect(fake.lastLine()).toBe(
      `xtask: biome could not run (it fails even when asked only for its version, so its installed files are broken or missing). ${REINSTALL}`,
    );
    const working = fakeIo((command) => (command.kind === "tool" ? exited(1) : OK));
    expect(await main(["prepare-scaffold"], working.io)).toBe(1);
    expect(working.lastLine()).toMatch(/^xtask: formatting the project failed\./);
  });

  it("lists help in the usage line", () => {
    expect(USAGE).toBe("pnpm xtask <prepare-scaffold|ci|e2e|check-dist|help>");
  });
});

describe("the real runner (spawned)", () => {
  function runReal(args: string[]) {
    const result = spawnSync(process.execPath, [MAIN, ...args], {
      cwd: PROJECT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 30_000,
    });
    const lines = `${result.stdout}${result.stderr}`.trimEnd().split("\n");
    return {
      status: result.status,
      stdout: result.stdout,
      stderr: result.stderr,
      last: lines.at(-1),
    };
  }

  it("rejects an unknown command with exit code 1 and one plain line", () => {
    const result = runReal(["no-such-command"]);
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe(`xtask: unknown command "no-such-command". Usage: ${USAGE}\n`);
  });

  it("prints the help text with exit code 0", () => {
    const result = runReal(["help"]);
    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    expect(result.stdout).toBe(`${HELP_TEXT}\n`);
    expect(result.last).toContain("comes from pnpm, not from this project");
  });
});

describe("isEntryPoint", () => {
  const url = new URL("../../tools/xtask/main.ts", import.meta.url).href;

  it("is true for the file itself, also through another spelling of its path", () => {
    expect(isEntryPoint(MAIN, url)).toBe(true);
    expect(isEntryPoint(path.join(PROJECT, "tools", "xtask", "..", "xtask", "main.ts"), url)).toBe(
      true,
    );
  });

  it("is false when another program imports the file", () => {
    expect(isEntryPoint(undefined, url)).toBe(false);
    expect(isEntryPoint("", url)).toBe(false);
    expect(isEntryPoint(path.join(PROJECT, "node_modules", "vitest", "vitest.mjs"), url)).toBe(
      false,
    );
    expect(isEntryPoint(path.join(PROJECT, "no-such-file.ts"), url)).toBe(false);
  });
});

describe("main.ts imports", () => {
  it("imports only node: builtins statically, so that loading it cannot fail", () => {
    const source = readFileSync(MAIN, "utf8");
    const specifiers = [
      ...source.matchAll(/^(?:import|export)\s[^;]*?\bfrom\s+"([^"]+)";|^import\s+"([^"]+)";/gm),
    ].map((match) => match[1] ?? match[2]);
    expect(specifiers.length).toBeGreaterThan(0);
    expect(specifiers.filter((specifier) => !specifier?.startsWith("node:"))).toEqual([]);
    expect(source).toContain('await import("./dist-check.ts")');
  });
});

describe("crashReason", () => {
  it("is undefined for every exit code except 126 and 127", () => {
    for (const code of [0, 1, 2, 3, 13, 125, 128, 134, 255]) {
      expect(crashReason(exited(code))).toBeUndefined();
    }
  });

  it("names a start error, a signal, a missing exit code, and 126 and 127", () => {
    expect(crashReason({ code: null, signal: null, startError: "ENOENT" })).toBe(
      "it could not be started: ENOENT",
    );
    expect(crashReason({ code: null, signal: "SIGTERM", startError: undefined })).toBe(
      "it was stopped by signal SIGTERM",
    );
    expect(crashReason({ code: null, signal: null, startError: undefined })).toBe(
      "it stopped without an exit code",
    );
    expect(crashReason(exited(126))).toContain("exit code 126");
    expect(crashReason(exited(127))).toContain("exit code 127");
  });

  it("no longer looks at the tool's output", () => {
    const source = readFileSync(MAIN, "utf8");
    expect(source).not.toContain("internal error, shown above");
    expect(source).not.toContain("NODE_CRASH_LINE");
  });
});

describe("summaryRows", () => {
  it("marks every step PASS when all of them passed", () => {
    expect(summaryRows(LABELS, [true, true, true, true, true]).map((r) => r.status)).toEqual([
      "PASS",
      "PASS",
      "PASS",
      "PASS",
      "PASS",
    ]);
  });

  it("lists the steps after a failure as SKIPPED", () => {
    expect(summaryRows(LABELS, [true, true, false]).map((r) => r.status)).toEqual([
      "PASS",
      "PASS",
      "FAIL",
      "SKIPPED",
      "SKIPPED",
    ]);
  });

  it("keeps the labels in order", () => {
    expect(summaryRows(LABELS, [true]).map((r) => r.label)).toEqual(LABELS);
  });
});

describe("renderSummary", () => {
  it("renders one row per step with the status in the same column", () => {
    const lines = renderSummary(summaryRows(LABELS, [true, false]));
    expect(lines[0]).toBe("");
    expect(lines).toHaveLength(1 + 3 + LABELS.length + 1);
    const rows = lines.slice(4, 4 + LABELS.length);
    expect(rows.map((line) => line.split("|")[1]?.trim())).toEqual([
      "PASS",
      "FAIL",
      "SKIPPED",
      "SKIPPED",
      "SKIPPED",
    ]);
    const columns = new Set(rows.map((line) => line.indexOf("|")));
    expect(columns.size).toBe(1);
    expect(lines[2]).toMatch(/^ Step +\| Status$/);
  });

  it("widens the label column for long labels", () => {
    const long = "x".repeat(40);
    const lines = renderSummary([{ label: long, status: "PASS" }]);
    expect(lines[4]).toBe(` ${long} | PASS`);
  });
});

describe("isStackFrame", () => {
  it("recognises Node stack frames", () => {
    expect(isStackFrame("    at load (/srv/site/vite.config.ts:37:13)")).toBe(true);
    expect(isStackFrame("    at async Promise.all (index 0)")).toBe(true);
    expect(isStackFrame("    at new Promise (<anonymous>)")).toBe(true);
    expect(isStackFrame("\tat Object.transform (/x/y.js:1:2)")).toBe(true);
    expect(isStackFrame("    at /srv/site/x.js:10:5")).toBe(true);
    expect(isStackFrame("    at node:internal/modules/run_main:123:45")).toBe(true);
    expect(isStackFrame("    at process.emit (node:events:519:28)")).toBe(true);
    expect(isStackFrame("    at #build (file:///p/rolldown/dist/x.mjs:1:2)")).toBe(true);
    expect(isStackFrame("    at Object.transform [as transform] (/x/y.js:1:2)")).toBe(true);
  });

  it("recognises frames with Windows paths", () => {
    expect(isStackFrame("    at load (C:\\work\\site\\vite.config.ts:37:13)")).toBe(true);
    expect(isStackFrame("    at C:\\work\\site\\vite.config.ts:37:13")).toBe(true);
    expect(isStackFrame("    at D:/work/site/x.js:1:1")).toBe(true);
  });

  it("recognises frames with file:// URLs", () => {
    expect(isStackFrame("    at file:///srv/site/vite.config.ts:37:13")).toBe(true);
    expect(isStackFrame("    at async file:///srv/site/vite.config.ts:37:13")).toBe(true);
    expect(isStackFrame("    at load (file:///C:/work/site/vite.config.ts:37:13)")).toBe(true);
  });

  it("recognises frames wrapped in colour codes or ending in a carriage return", () => {
    expect(isStackFrame("\u001b[90m    at load (/x/y.js:1:2)\u001b[39m")).toBe(true);
    expect(isStackFrame("    at load (/x/y.js:1:2)\r")).toBe(true);
    expect(
      isStackFrame("    at async CAC.<anonymous> (file:///x/vite/dist/node/cli.js:789:3) {"),
    ).toBe(true);
  });

  // The reviewer's list: lines a test may log on purpose.
  it("drops lines that are real frames", () => {
    // A bare file name with line and column in parentheses counts as a location.
    expect(isStackFrame("    at home (index.ts:1:2)")).toBe(true);
    expect(isStackFrame("    at /etc/passwd:1:2")).toBe(true);
    expect(isStackFrame("    at new Promise (<anonymous>)")).toBe(true);
  });

  it("keeps ordinary prose that only looks a little like a frame", () => {
    expect(isStackFrame("    at least 3 items expected (got 1:2:3)")).toBe(false);
    expect(isStackFrame("Meet us at the station at 5:30 (see docs at home.md:1:2)")).toBe(false);
    expect(isStackFrame("    at the moment, retry at 10:20:30")).toBe(false);
    expect(isStackFrame("  - Arrive at 10:00 at the gate (Building 4:2:1)")).toBe(false);
    expect(isStackFrame("    at noon (got 1:2:3)")).toBe(false);
    expect(isStackFrame("    at home 10:20:30")).toBe(false);
  });

  it("keeps ordinary lines that contain the word at", () => {
    expect(isStackFrame("Look at the output above.")).toBe(false);
    expect(isStackFrame("  at least one test failed")).toBe(false);
    expect(isStackFrame("    at the top of the page (see the header)")).toBe(false);
    expect(isStackFrame("src/pages/index.html:3:5 error at line 3")).toBe(false);
    expect(isStackFrame("at load (/x/y.js:1:2)")).toBe(false);
    expect(isStackFrame("")).toBe(false);
  });

  it("keeps error message lines", () => {
    expect(isStackFrame('Error: index.html includes "nope.html", but it does not exist.')).toBe(
      false,
    );
    expect(isStackFrame("error during build:")).toBe(false);
    expect(isStackFrame("[vite:html-includes] Error: something broke")).toBe(false);
  });
});

describe("createLineFilter", () => {
  function collect(chunks: readonly string[]): string {
    let output = "";
    const filter = createLineFilter((text) => {
      output += text;
    });
    for (const chunk of chunks) {
      filter.push(chunk);
    }
    filter.end();
    return output;
  }

  it("removes frames even when they are split across chunks", () => {
    expect(collect(["Error: bad\n    at lo", "ad (/x/y.js:1", ":2)\nnext line\n"])).toBe(
      "Error: bad\nnext line\n",
    );
  });

  it("forwards a line without a final newline", () => {
    expect(collect(["first\nlast"])).toBe("first\nlast");
    expect(collect(["first\n    at load (/x/y.js:1:2)"])).toBe("first\n");
  });

  it("forwards a line that cannot be a frame before its newline arrives", () => {
    const seen: string[] = [];
    const filter = createLineFilter((text) => {
      seen.push(text);
    });
    filter.push("building");
    expect(seen).toEqual(["building"]);
    filter.push("... done\n");
    expect(seen.join("")).toBe("building... done\n");
  });

  it("keeps indented lines that are not frames", () => {
    expect(collect(["  ✓ tests/unit/year.test.ts (2 tests)\n", "   at least\n"])).toBe(
      "  ✓ tests/unit/year.test.ts (2 tests)\n   at least\n",
    );
  });

  it("drops an error dump that holds only empty properties", () => {
    expect(collect(["E\n    at f (/a.js:1:2) {\n  errors: [Getter/Setter]\n}\nafter\n"])).toBe(
      "E\nafter\n",
    );
  });

  it("keeps an error dump that holds information", () => {
    const dump = "  errno: -13,\n  code: 'EACCES',\n  path: '/x/biome'\n}\n";
    expect(collect([`E\n    at f (/a.js:1:2) {\n${dump}`])).toBe(`E\n${dump}`);
    const mixed = "  errors: [Getter/Setter],\n  code: 'X'\n}\n";
    expect(collect([`E\n    at f (/a.js:1:2) {\n${mixed}`])).toBe(`E\n${mixed}`);
  });

  it("keeps the held lines when the output ends inside a dump", () => {
    expect(collect(["E\n    at f (/a.js:1:2) {\n  errors: [Getter/Setter]\n"])).toBe(
      "E\n  errors: [Getter/Setter]\n",
    );
  });

  it("keeps a closing brace that does not follow a frame", () => {
    expect(collect(["{\n  a: [Getter]\n}\n"])).toBe("{\n  a: [Getter]\n}\n");
  });

  it("passes large output through unchanged", () => {
    const line = `${"x".repeat(99)}\n`;
    const big = line.repeat(50_000);
    const chunks: string[] = [];
    for (let i = 0; i < big.length; i += 65_536) {
      chunks.push(big.slice(i, i + 65_536));
    }
    expect(collect(chunks).length).toBe(big.length);
  });
});

describe("createAnsiStripper", () => {
  function strip(chunks: readonly string[]): string {
    let output = "";
    const stripper = createAnsiStripper((text) => {
      output += text;
    });
    for (const chunk of chunks) {
      stripper.push(chunk);
    }
    stripper.end();
    return output;
  }

  it("removes colour codes, also split across chunks", () => {
    expect(strip(["\u001b[1;31mred\u001b[0m\n"])).toBe("red\n");
    expect(strip(["a\u001b", "[3", "1mb\u001b[0", "m\n"])).toBe("ab\n");
    expect(strip(["x\u001b]8;;http://a\u0007y\u001b]8;;\u0007"])).toBe("xy");
  });

  it("does not lose an escape character left at the very end", () => {
    expect(strip(["text\u001b"])).toBe("text");
    expect(strip(["text\u001b["])).toBe("text");
  });
});

describe("unexpectedProblemMessage", () => {
  it("is one line with the first line of the message and no stack", () => {
    const error = new Error("EACCES: permission denied, open 'dist/a.html'\nmore detail");
    const message = unexpectedProblemMessage(error, "check-dist");
    expect(message).toBe(
      `xtask: unexpected problem: EACCES: permission denied, open 'dist/a.html'. Run "node tools/xtask/main.ts check-dist" again; if it repeats, reinstall with "pnpm xtask prepare-scaffold".`,
    );
    expect(message).not.toContain("\n");
    expect(message).not.toMatch(/\bat .*:\d+:\d+/);
  });

  it("handles values that are not errors and a missing command", () => {
    expect(unexpectedProblemMessage("boom.", undefined)).toBe(
      `xtask: unexpected problem: boom. Run "node tools/xtask/main.ts <command>" again; if it repeats, reinstall with "pnpm xtask prepare-scaffold".`,
    );
    expect(unexpectedProblemMessage(new Error(""), "ci")).toContain("unknown error");
  });

  it("is never used for a CheckFailure's own message", () => {
    expect(new CheckFailure("x").name).toBe("CheckFailure");
  });
});

describe("childEnvironment", () => {
  it("always sets CI=1", () => {
    expect(childEnvironment({}, false)["CI"]).toBe("1");
  });

  it("forces colours only when writing to a terminal and the user chose nothing", () => {
    expect(childEnvironment({}, true)["FORCE_COLOR"]).toBe("1");
    expect(childEnvironment({}, false)["FORCE_COLOR"]).toBeUndefined();
    expect(childEnvironment({ NO_COLOR: "1" }, true)["FORCE_COLOR"]).toBeUndefined();
    expect(childEnvironment({ FORCE_COLOR: "0" }, true)["FORCE_COLOR"]).toBe("0");
    expect(childEnvironment({ FORCE_COLOR: "1" }, false)["NO_COLOR"]).toBeUndefined();
  });

  it("turns colours off for tools that would colour a file", () => {
    expect(childEnvironment({}, false)["NO_COLOR"]).toBe("1");
    expect(childEnvironment({}, true)["NO_COLOR"]).toBeUndefined();
    expect(childEnvironment({ FORCE_COLOR: "0" }, true)["NO_COLOR"]).toBe("1");
  });
});

describe("toolEnvironment", () => {
  const folders = cacheFolders(path.join("project"));
  const inside = path.join("project", ".xtask-cache");

  it("keeps temporary files and caches in .xtask-cache, outside node_modules", () => {
    expect(CACHE_FOLDER).toBe(".xtask-cache");
    expect(folders).toEqual({
      tmp: path.join(inside, "tmp"),
      cache: path.join(inside, "cache"),
      compile: path.join(inside, "compile-cache"),
    });
    for (const folder of [folders.tmp, folders.cache, folders.compile]) {
      expect(folder.startsWith(`${inside}${path.sep}`)).toBe(true);
      // Node does not strip TypeScript types for files under node_modules.
      expect(folder.split(path.sep)).not.toContain("node_modules");
    }
    const env = toolEnvironment({ HOME: "/srv/user", TMPDIR: "/tmp", CI: "1" }, folders, {
      browser: false,
    });
    expect(env["TMPDIR"]).toBe(folders.tmp);
    expect(env["TMP"]).toBe(folders.tmp);
    expect(env["TEMP"]).toBe(folders.tmp);
    expect(env["XDG_CACHE_HOME"]).toBe(folders.cache);
    expect(env["NODE_COMPILE_CACHE"]).toBe(folders.compile);
    expect(env["HOME"]).toBe("/srv/user");
    expect(env["CI"]).toBe("1");
  });

  it("leaves the temporary and XDG cache folders alone for the browser tests", () => {
    const base = { TMPDIR: "/t", XDG_CACHE_HOME: "/c" };
    const env = toolEnvironment(base, folders, { browser: true });
    expect(env["TMPDIR"]).toBe("/t");
    expect(env["XDG_CACHE_HOME"]).toBe("/c");
    expect(env["TMP"]).toBeUndefined();
    expect(env["NODE_COMPILE_CACHE"]).toBe(folders.compile);
  });
});

describe("wantsColour", () => {
  it("follows the terminal unless the user chose", () => {
    expect(wantsColour({}, true)).toBe(true);
    expect(wantsColour({}, false)).toBe(false);
    expect(wantsColour({ NO_COLOR: "1" }, true)).toBe(false);
    expect(wantsColour({ FORCE_COLOR: "1" }, false)).toBe(true);
    expect(wantsColour({ FORCE_COLOR: "0" }, true)).toBe(false);
    expect(wantsColour({ NO_COLOR: "" }, true)).toBe(true);
  });
});

describe("HELP_TEXT", () => {
  it("explains the line pnpm adds after a failure", () => {
    expect(HELP_TEXT).toContain("[ELIFECYCLE] Command failed with exit code 1.");
    expect(HELP_TEXT).toContain("comes from pnpm, not from this project");
    expect(HELP_TEXT).toContain("  help ");
  });
});

// --- Temporary folders: one per run --------------------------------------------------------

// Everything below lives in one scratch folder in the system temporary folder (under xtask
// ci that is this run's own folder in .xtask-cache/tmp). Not in node_modules: Node does not
// run .ts files from there, and the fake projects run a copy of main.ts.
const SCRATCH = realpathSync(mkdtempSync(path.join(os.tmpdir(), "xtask-main-test-")));
afterAll(() => {
  if (!removeTree(SCRATCH, path.dirname(SCRATCH))) {
    rmSync(SCRATCH, { recursive: true, force: true });
  }
});

const SELF = { pid: process.pid, host: os.hostname() };
const HOUR = 60 * 60 * 1000;
// A process id that is not running any more: a child that has already ended.
const DEAD_PID = spawnSync(process.execPath, ["-e", ""]).pid;
// A process id that is running: the process that started this test.
const LIVE_PID = process.ppid;

let scratchCount = 0;
function scratchDir(name = "dir"): string {
  scratchCount += 1;
  const dir = path.join(SCRATCH, `${name}-${scratchCount}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

function writeFile(file: string, size = 10): void {
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, "x".repeat(size));
}

// The three kinds of leftovers that once blocked every later run.
const LEFTOVER_SCRIPT = `
import { chmodSync, mkdirSync, renameSync, writeFileSync } from "node:fs";
import path from "node:path";
export function leaveLeftovers(dir) {
  // A read-only folder with a file in it.
  mkdirSync(path.join(dir, "ro"), { recursive: true });
  writeFileSync(path.join(dir, "ro", "data.txt"), "x");
  chmodSync(path.join(dir, "ro"), 0o555);
  // A folder nobody may read or enter.
  mkdirSync(path.join(dir, "noperm", "sub"), { recursive: true });
  writeFileSync(path.join(dir, "noperm", "sub", "data.txt"), "x");
  chmodSync(path.join(dir, "noperm"), 0o000);
  // A tree whose deepest path is longer than PATH_MAX (4096), built in pieces.
  const deep = path.join(dir, "deep");
  const chain = Array.from({ length: 20 }, () => "d".repeat(100));
  mkdirSync(path.join(deep, "a", ...chain), { recursive: true });
  writeFileSync(path.join(deep, "a", ...chain, "end.txt"), "x");
  let inner = "a";
  for (const outer of ["b", "c"]) {
    mkdirSync(path.join(deep, outer, ...chain), { recursive: true });
    renameSync(path.join(deep, inner), path.join(deep, outer, ...chain, inner));
    inner = outer;
  }
}
`;
const LEFTOVER_MODULE = path.join(SCRATCH, "leftovers.mjs");
writeFileSync(LEFTOVER_MODULE, LEFTOVER_SCRIPT);
const LEFTOVER_URL = pathToFileURL(LEFTOVER_MODULE).href;
const { leaveLeftovers } = (await import(LEFTOVER_URL)) as {
  leaveLeftovers: (dir: string) => void;
};

// Root ignores file permissions (the default user in Docker and many dev containers), so a
// folder without permissions blocks nothing there and these two tests cannot fail as they should.
const AS_ROOT = process.getuid?.() === 0;

describe("removeTree", () => {
  it("refuses anything that is not inside the folder it is given, and deletes nothing", () => {
    const parent = scratchDir("guard");
    const inside = path.join(parent, "cache");
    const sibling = path.join(parent, "cache-other");
    writeFile(path.join(inside, "a.txt"));
    writeFile(path.join(sibling, "keep.txt"));
    writeFile(path.join(parent, "keep.txt"));
    for (const target of [parent, inside, sibling, path.join(sibling, "keep.txt")]) {
      expect(() => removeTree(target, inside)).toThrow(/^refusing to delete /);
    }
    expect(readdirSync(parent).sort()).toEqual(["cache", "cache-other", "keep.txt"]);
    expect(readdirSync(inside)).toEqual(["a.txt"]);
    expect(readdirSync(sibling)).toEqual(["keep.txt"]);
  });

  it("removes read-only folders, folders nobody may enter and trees deeper than PATH_MAX", () => {
    const inside = scratchDir("tree");
    const target = path.join(inside, "leftovers");
    mkdirSync(target);
    leaveLeftovers(target);
    expect(statSync(path.join(target, "ro")).mode & 0o777).toBe(0o555);
    expect(statSync(path.join(target, "noperm")).mode & 0o777).toBe(0o000);
    expect(removeTree(target, inside)).toBe(true);
    expect(existsSync(target)).toBe(false);
  });

  it("builds a deep tree that really is longer than PATH_MAX", () => {
    const dir = scratchDir("measure");
    leaveLeftovers(dir);
    const chain = Array.from({ length: 20 }, () => "d".repeat(100));
    const end = path.join(dir, "deep", "c", ...chain, "b", ...chain, "a", ...chain, "end.txt");
    expect(end.length).toBeGreaterThan(4096);
    expect(() => lstatSync(end)).toThrow(/ENAMETOOLONG/);
    // find walks the tree folder by folder, so it can still reach the file.
    const found = spawnSync("find", [path.join(dir, "deep"), "-name", "end.txt"], {
      encoding: "utf8",
    });
    expect(found.stdout.trim().endsWith("dddd/end.txt")).toBe(true);
    expect(removeTree(dir, SCRATCH)).toBe(true);
  });

  it("removes links themselves and never touches what they point to", () => {
    const inside = scratchDir("links");
    const outside = scratchDir("outside");
    writeFile(path.join(outside, "dir", "a.txt"));
    writeFile(path.join(outside, "file.txt"));
    chmodSync(path.join(outside, "dir"), 0o555);
    const target = path.join(inside, "t");
    mkdirSync(path.join(target, "sub"), { recursive: true });
    symlinkSync(path.join(outside, "dir"), path.join(target, "dir-link"), "dir");
    symlinkSync(path.join(outside, "dir"), path.join(target, "sub", "nested-link"), "dir");
    symlinkSync(path.join(outside, "file.txt"), path.join(target, "file-link"));
    linkSync(path.join(outside, "file.txt"), path.join(target, "hard-link"));
    expect(statSync(path.join(outside, "file.txt")).nlink).toBe(2);
    expect(removeTree(target, inside)).toBe(true);
    expect(existsSync(target)).toBe(false);
    expect(readdirSync(path.join(outside, "dir"))).toEqual(["a.txt"]);
    expect(statSync(path.join(outside, "dir")).mode & 0o777).toBe(0o555);
    expect(statSync(path.join(outside, "file.txt")).nlink).toBe(1);
    expect(readFileSync(path.join(outside, "file.txt"), "utf8")).toBe("x".repeat(10));
    chmodSync(path.join(outside, "dir"), 0o755);
  });

  it("is happy when the target does not exist", () => {
    const inside = scratchDir("missing");
    expect(removeTree(path.join(inside, "nothing"), inside)).toBe(true);
  });
});

describe("isRunFolderStale", () => {
  const now = Date.UTC(2030, 0, 2);
  const alive = (pid: number): boolean => pid === 7;
  const owner = (pid: number, ageMs = 0, host = SELF.host): RunOwner => ({
    pid,
    host,
    started: now - ageMs,
  });

  it("keeps a folder whose owner is still running", () => {
    expect(isRunFolderStale(owner(7), now, now, SELF, alive)).toBe(false);
    expect(isRunFolderStale(owner(7, 23 * HOUR), now, now, SELF, alive)).toBe(false);
  });

  it("removes a folder whose owner has ended", () => {
    expect(isRunFolderStale(owner(8), now, now, SELF, alive)).toBe(true);
  });

  it("removes a folder older than STALE_AGE_MS even when its process id is in use again", () => {
    expect(STALE_AGE_MS).toBe(24 * HOUR);
    expect(isRunFolderStale(owner(7, 25 * HOUR), now, now, SELF, alive)).toBe(true);
  });

  it("keeps a folder from another machine until it is old, because it cannot ask", () => {
    expect(isRunFolderStale(owner(8, HOUR, "other-host"), now, now, SELF, alive)).toBe(false);
    expect(isRunFolderStale(owner(8, 25 * HOUR, "other-host"), now, now, SELF, alive)).toBe(true);
  });

  it("keeps a folder without an owner file for a while: its run may be starting", () => {
    expect(isRunFolderStale(undefined, now - 60_000, now, SELF, alive)).toBe(false);
    expect(isRunFolderStale(undefined, now - HOUR, now, SELF, alive)).toBe(true);
  });
});

describe("isProcessAlive", () => {
  it("knows a running process from one that has ended", () => {
    expect(isProcessAlive(process.pid)).toBe(true);
    expect(isProcessAlive(LIVE_PID)).toBe(true);
    expect(DEAD_PID).toBeTypeOf("number");
    expect(isProcessAlive(DEAD_PID ?? 0)).toBe(false);
  });
});

describe("prepareRunFolders", () => {
  function fakeProject(): string {
    return scratchDir("project");
  }

  function tmpOf(root: string): string {
    return path.join(root, CACHE_FOLDER, "tmp");
  }

  /** A run folder as another run would leave it; owner undefined: no owner file. */
  function plantRun(root: string, owner: RunOwner | undefined, name: string): string {
    const run = path.join(tmpOf(root), name);
    mkdirSync(path.join(run, "tmp"), { recursive: true });
    writeFile(path.join(run, "tmp", "file.txt"));
    if (owner !== undefined) {
      writeFileSync(path.join(run, OWNER_FILE), JSON.stringify(owner));
    }
    return run;
  }

  const ownerOf = (pid: number | undefined, ageMs = 0): RunOwner => ({
    pid: pid ?? 0,
    host: SELF.host,
    started: Date.now() - ageMs,
  });

  it("gives the run its own temporary folder with an owner file", () => {
    const root = fakeProject();
    const { folders, note } = prepareRunFolders(root);
    expect(note).toBeUndefined();
    const base = path.join(root, CACHE_FOLDER);
    expect(readdirSync(base).sort()).toEqual(["cache", "compile-cache", "tmp"]);
    expect(path.dirname(folders.run)).toBe(path.join(base, "tmp"));
    expect(path.basename(folders.run).startsWith(RUN_PREFIX)).toBe(true);
    expect(folders.tmp).toBe(path.join(folders.run, "tmp"));
    expect(folders.cache).toBe(path.join(base, "cache"));
    expect(folders.compile).toBe(path.join(base, "compile-cache"));
    expect(readdirSync(folders.run).sort()).toEqual([OWNER_FILE, "tmp"]);
    const owner = JSON.parse(readFileSync(path.join(folders.run, OWNER_FILE), "utf8")) as RunOwner;
    expect(owner.pid).toBe(process.pid);
    expect(owner.host).toBe(os.hostname());
    expect(Math.abs(Date.now() - owner.started)).toBeLessThan(60_000);
  });

  it("gives every run a different folder and leaves the other runs' folders alone", () => {
    const root = fakeProject();
    const first = prepareRunFolders(root).folders;
    writeFile(path.join(first.tmp, "in-use.txt"));
    const second = prepareRunFolders(root).folders;
    expect(second.run).not.toBe(first.run);
    expect(readdirSync(first.tmp)).toEqual(["in-use.txt"]);
    expect(readdirSync(tmpOf(root)).sort()).toEqual(
      [path.basename(first.run), path.basename(second.run)].sort(),
    );
  });

  it("removes run folders whose owner has ended or that are too old, and keeps live ones", () => {
    const root = fakeProject();
    mkdirSync(tmpOf(root), { recursive: true });
    const dead = plantRun(root, ownerOf(DEAD_PID), `${RUN_PREFIX}dead`);
    const live = plantRun(root, ownerOf(LIVE_PID), `${RUN_PREFIX}live`);
    const old = plantRun(root, ownerOf(LIVE_PID, 25 * HOUR), `${RUN_PREFIX}old`);
    const starting = plantRun(root, undefined, `${RUN_PREFIX}starting`);
    const abandoned = plantRun(root, undefined, `${RUN_PREFIX}abandoned`);
    const hourAgo = (Date.now() - HOUR) / 1000;
    utimesSync(abandoned, hourAgo, hourAgo);
    const { folders, note } = prepareRunFolders(root);
    expect(note).toBeUndefined();
    for (const gone of [dead, old, abandoned]) {
      expect(existsSync(gone)).toBe(false);
    }
    for (const kept of [live, starting]) {
      expect(readdirSync(path.join(kept, "tmp"))).toEqual(["file.txt"]);
    }
    expect(readdirSync(tmpOf(root)).sort()).toEqual(
      [path.basename(folders.run), path.basename(live), path.basename(starting)].sort(),
    );
  });

  it("removes the read-only leftovers of an ended run without a note", () => {
    const root = fakeProject();
    mkdirSync(tmpOf(root), { recursive: true });
    const dead = plantRun(root, ownerOf(DEAD_PID), `${RUN_PREFIX}leftovers`);
    leaveLeftovers(path.join(dead, "tmp"));
    const { note } = prepareRunFolders(root);
    expect(note).toBeUndefined();
    expect(existsSync(dead)).toBe(false);
  });

  it("is not blocked by leftovers across two runs, and the run removes its own folder", () => {
    const root = fakeProject();
    const first = prepareRunFolders(root).folders;
    leaveLeftovers(first.tmp);
    expect(removeRunFolder(first)).toBe(true);
    expect(existsSync(first.run)).toBe(false);
    const second = prepareRunFolders(root);
    expect(second.note).toBeUndefined();
    leaveLeftovers(second.folders.tmp);
    // The second run ends without cleaning up (it was killed): the third run cleans up.
    const third = prepareRunFolders(root, { isAlive: () => false });
    expect(third.note).toBeUndefined();
    expect(readdirSync(tmpOf(root))).toEqual([path.basename(third.folders.run)]);
  });

  it("never follows a link or a hard link named like a run folder", () => {
    const root = fakeProject();
    const outside = scratchDir("outside");
    // Outside: something that looks exactly like an ended run.
    mkdirSync(path.join(outside, "run-like", "tmp"), { recursive: true });
    writeFileSync(path.join(outside, "run-like", OWNER_FILE), JSON.stringify(ownerOf(DEAD_PID)));
    writeFile(path.join(outside, "run-like", "tmp", "precious.txt"));
    writeFile(path.join(outside, "file.txt"));
    mkdirSync(tmpOf(root), { recursive: true });
    symlinkSync(path.join(outside, "run-like"), path.join(tmpOf(root), `${RUN_PREFIX}link`), "dir");
    symlinkSync(path.join(outside, "file.txt"), path.join(tmpOf(root), `${RUN_PREFIX}file-link`));
    symlinkSync(path.join(outside, "gone"), path.join(tmpOf(root), `${RUN_PREFIX}dangling`));
    linkSync(path.join(outside, "file.txt"), path.join(tmpOf(root), `${RUN_PREFIX}hard`));
    const { folders, note } = prepareRunFolders(root);
    expect(note).toBeUndefined();
    expect(readdirSync(tmpOf(root))).toEqual([path.basename(folders.run)]);
    expect(readdirSync(path.join(outside, "run-like")).sort()).toEqual([OWNER_FILE, "tmp"]);
    expect(readdirSync(path.join(outside, "run-like", "tmp"))).toEqual(["precious.txt"]);
    expect(statSync(path.join(outside, "file.txt")).nlink).toBe(1);
    expect(readFileSync(path.join(outside, "file.txt"), "utf8")).toBe("x".repeat(10));
    expect(existsSync(path.join(outside, "gone"))).toBe(false);
  });

  it("removes what the earlier layout left directly in tmp", () => {
    const root = fakeProject();
    writeFile(path.join(tmpOf(root), "old-file.txt"));
    writeFile(path.join(tmpOf(root), "vitest-xyz", "a", "b.txt"));
    const { folders } = prepareRunFolders(root);
    expect(readdirSync(tmpOf(root))).toEqual([path.basename(folders.run)]);
  });

  it("goes on with a fresh folder and returns one note when something cannot be removed", () => {
    const root = fakeProject();
    mkdirSync(tmpOf(root), { recursive: true });
    plantRun(root, ownerOf(DEAD_PID), `${RUN_PREFIX}stuck`);
    const { folders, note } = prepareRunFolders(root, { remove: () => false });
    expect(note).toBe(LEFTOVER_NOTE);
    expect(readdirSync(folders.tmp)).toEqual([]);
    expect(LEFTOVER_NOTE).toBe(
      "xtask: note: some old temporary files in .xtask-cache/tmp/ could not be removed; the checks are not affected. When no check is running, remove them with: chmod -R u+rwx .xtask-cache && rm -rf .xtask-cache",
    );
  });

  it("the command in the note removes every kind of leftover", () => {
    const root = fakeProject();
    const run = plantRun(root, ownerOf(DEAD_PID), `${RUN_PREFIX}by-hand`);
    leaveLeftovers(path.join(run, "tmp"));
    const result = spawnSync("sh", ["-c", "chmod -R u+rwx .xtask-cache && rm -rf .xtask-cache"], {
      cwd: root,
      encoding: "utf8",
    });
    expect(result.stderr).toBe("");
    expect(result.status).toBe(0);
    expect(readdirSync(root)).toEqual([]);
  });

  it("empties the compile cache only when it is larger than the budget", () => {
    expect(COMPILE_CACHE_BUDGET).toBe(20 * 1024 * 1024);
    const root = fakeProject();
    const compile = path.join(root, CACHE_FOLDER, "compile-cache");
    writeFile(path.join(compile, "v26", "one.bin"), 600);
    writeFile(path.join(compile, "v26", "two.bin"), 400);
    writeFile(path.join(root, CACHE_FOLDER, "cache", "biome", "c.bin"));
    prepareRunFolders(root, { budget: 1000 });
    expect(readdirSync(path.join(compile, "v26")).sort()).toEqual(["one.bin", "two.bin"]);
    writeFile(path.join(compile, "v26", "three.bin"), 1);
    const { folders, note } = prepareRunFolders(root, { budget: 1000 });
    expect(note).toBeUndefined();
    expect(readdirSync(compile)).toEqual([]);
    expect(readdirSync(folders.run).sort()).toEqual([OWNER_FILE, "tmp"]);
    expect(existsSync(path.join(root, CACHE_FOLDER, "cache", "biome", "c.bin"))).toBe(true);
  });

  it("refuses a cache folder that is a link to another folder and deletes nothing", () => {
    const root = fakeProject();
    const elsewhere = fakeProject();
    writeFile(path.join(elsewhere, "tmp", "precious.txt"));
    writeFile(path.join(elsewhere, "compile-cache", "big.bin"), 2000);
    symlinkSync(elsewhere, path.join(root, CACHE_FOLDER), "dir");
    expect(() => prepareRunFolders(root, { budget: 1000 })).toThrow(CheckFailure);
    expect(() => prepareRunFolders(root, { budget: 1000 })).toThrow(
      "xtask: .xtask-cache/ must be a folder inside the project, but it is a link or a file. Delete it and run the command again.",
    );
    expect(readdirSync(path.join(elsewhere, "tmp"))).toEqual(["precious.txt"]);
    expect(readdirSync(path.join(elsewhere, "compile-cache"))).toEqual(["big.bin"]);
    expect(readdirSync(elsewhere).sort()).toEqual(["compile-cache", "tmp"]);
  });

  it("refuses a temporary folder that is a link and deletes nothing", () => {
    const root = fakeProject();
    const elsewhere = fakeProject();
    writeFile(path.join(elsewhere, "precious.txt"));
    mkdirSync(path.join(root, CACHE_FOLDER), { recursive: true });
    symlinkSync(elsewhere, path.join(root, CACHE_FOLDER, "tmp"), "dir");
    expect(() => prepareRunFolders(root)).toThrow(/^xtask: \.xtask-cache\/tmp\/ must be a folder/);
    expect(readdirSync(elsewhere)).toEqual(["precious.txt"]);
  });

  it("works when the project itself is reached through a link", () => {
    const root = fakeProject();
    const link = path.join(SCRATCH, `link-${scratchCount}`);
    symlinkSync(root, link, "dir");
    const { folders } = prepareRunFolders(link);
    expect(path.dirname(folders.run)).toBe(path.join(realpathSync(root), CACHE_FOLDER, "tmp"));
  });

  it.skipIf(AS_ROOT)(
    "says plainly that the cache folder cannot be used when it has no permissions at all (skipped as root: root ignores permissions)",
    () => {
      const root = fakeProject();
      const cache = path.join(root, CACHE_FOLDER);
      mkdirSync(cache);
      chmodSync(cache, 0o000);
      try {
        expect(() => prepareRunFolders(root)).toThrow(CheckFailure);
        expect(() => prepareRunFolders(root)).toThrow(
          /^xtask: \.xtask-cache\/tmp\/ cannot be used \(EACCES\)\. Give yourself access to \.xtask-cache\/ \(chmod -R u\+rwx \.xtask-cache\) or delete it, then run the command again\.$/,
        );
      } finally {
        chmodSync(cache, 0o755);
      }
    },
  );

  it.skipIf(AS_ROOT)(
    "says plainly what to do when the project folder is read-only (skipped as root: root ignores permissions)",
    () => {
      const root = fakeProject();
      chmodSync(root, 0o555);
      try {
        expect(() => prepareRunFolders(root)).toThrow(
          /^xtask: could not create \.xtask-cache\/ for the tools' temporary files \(EACCES\)\. Make the project folder writable, then run the command again\.$/,
        );
      } finally {
        chmodSync(root, 0o755);
      }
    },
  );
});

describe("best-effort helpers", () => {
  it("sendSignal says whether the signal could be sent, and never throws", () => {
    let sent = 0;
    expect(
      sendSignal(() => {
        sent += 1;
      }),
    ).toBe(true);
    expect(sent).toBe(1);
    const gone = Object.assign(new Error("kill ESRCH"), { code: "ESRCH" });
    expect(
      sendSignal(() => {
        throw gone;
      }),
    ).toBe(false);
  });

  it("tryWriteAll writes everything, and returns false when the output is gone", () => {
    const file = path.join(scratchDir("write"), "out.txt");
    const fd = openSync(file, "w");
    try {
      expect(tryWriteAll(fd, "one line\n")).toBe(true);
    } finally {
      closeSync(fd);
    }
    expect(readFileSync(file, "utf8")).toBe("one line\n");
    expect(tryWriteAll(-1, "nobody reads this\n")).toBe(false);
  });

  it("tryMakeFolder makes the folder, and returns false when it cannot", () => {
    const dir = scratchDir("make");
    expect(tryMakeFolder(path.join(dir, "a", "b"))).toBe(true);
    expect(statSync(path.join(dir, "a", "b")).isDirectory()).toBe(true);
    expect(tryMakeFolder(path.join(dir, "a", "b"))).toBe(true);
    writeFileSync(path.join(dir, "file"), "x");
    expect(tryMakeFolder(path.join(dir, "file", "below"))).toBe(false);
  });
});

describe("removeRunFolder", () => {
  it("removes only the run's own folder, the owner file last", () => {
    const root = scratchDir("project");
    const mine = prepareRunFolders(root).folders;
    const other = prepareRunFolders(root).folders;
    leaveLeftovers(mine.tmp);
    expect(removeRunFolder(mine)).toBe(true);
    expect(existsSync(mine.run)).toBe(false);
    expect(readdirSync(other.run).sort()).toEqual([OWNER_FILE, "tmp"]);
  });

  it("keeps the owner file when something else cannot be removed", () => {
    const root = scratchDir("project");
    const mine = prepareRunFolders(root).folders;
    const stuck = (target: string, inside: string): boolean =>
      target === mine.tmp ? false : removeTree(target, inside);
    expect(removeRunFolder(mine, stuck)).toBe(false);
    expect(readdirSync(mine.run).sort()).toEqual([OWNER_FILE, "tmp"]);
  });
});

// --- The real runner on a fake project -----------------------------------------------------

// A fake project: a copy of the runner, and fake tools in node_modules whose scripts the test
// chooses. Each tool's script runs with the project as its current folder.
const TOOL_PACKAGES = {
  biome: ["@biomejs/biome", "biome"],
  tsc: ["typescript", "tsc"],
  vitest: ["vitest", "vitest"],
  vite: ["vite", "vite"],
} as const;
type FakeTool = keyof typeof TOOL_PACKAGES;

const FAKE_VITE = `import { mkdirSync, writeFileSync } from "node:fs";
if (process.argv[2] === "build") {
  mkdirSync("dist", { recursive: true });
  writeFileSync("dist/index.html", '<!doctype html><html lang="en"><head><title>t</title></head><body><main><h1>t</h1></main></body></html>');
}
`;

function fakeRunnerProject(scripts: Partial<Record<FakeTool, string>> = {}): string {
  const root = scratchDir("fake-project");
  const xtask = path.join(root, "tools", "xtask");
  mkdirSync(xtask, { recursive: true });
  for (const file of ["main.ts", "dist-check.ts", "package.json"]) {
    copyFileSync(path.join(PROJECT, "tools", "xtask", file), path.join(xtask, file));
  }
  for (const [tool, [name, bin]] of Object.entries(TOOL_PACKAGES)) {
    const dir = path.join(root, "node_modules", ...name.split("/"));
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      path.join(dir, "package.json"),
      JSON.stringify({ name, type: "module", bin: { [bin]: "bin.js" } }),
    );
    const script = scripts[tool as FakeTool] ?? (tool === "vite" ? FAKE_VITE : "");
    writeFileSync(path.join(dir, "bin.js"), script);
  }
  return root;
}

interface RunnerResult {
  readonly status: number | null;
  readonly signal: string | null;
  readonly output: string;
  readonly last: string;
}

function startRunner(
  root: string,
  args: readonly string[] = ["ci"],
): { child: ChildProcess; done: Promise<RunnerResult> } {
  const child = spawn(process.execPath, [path.join(root, "tools", "xtask", "main.ts"), ...args], {
    cwd: root,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout?.on("data", (chunk: Buffer) => {
    output += chunk.toString("utf8");
  });
  child.stderr?.on("data", (chunk: Buffer) => {
    output += chunk.toString("utf8");
  });
  const done = new Promise<RunnerResult>((resolve) => {
    child.on("close", (status, signal) => {
      resolve({ status, signal, output, last: output.trimEnd().split("\n").at(-1) ?? "" });
    });
  });
  return { child, done };
}

async function waitFor(check: () => boolean, ms = 15_000): Promise<void> {
  const deadline = Date.now() + ms;
  while (!check()) {
    if (Date.now() > deadline) {
      throw new Error("timed out waiting");
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}

function runsOf(root: string): string[] {
  try {
    return readdirSync(path.join(root, CACHE_FOLDER, "tmp"));
  } catch {
    return [];
  }
}

const SLOW = { timeout: 60_000 };

describe.concurrent("the runner on a fake project (spawned)", () => {
  it("passes, and leaves no run folder behind", SLOW, async () => {
    const root = fakeRunnerProject();
    const result = await startRunner(root).done;
    expect(result.last).toBe("xtask: all checks passed.");
    expect(result.status).toBe(0);
    expect(runsOf(root)).toEqual([]);
  });

  it(
    "is not blocked when the unit tests leave read-only folders in the temporary folder",
    SLOW,
    async () => {
      const root = fakeRunnerProject({
        vitest: `import os from "node:os";\nimport { leaveLeftovers } from ${JSON.stringify(LEFTOVER_URL)};\nleaveLeftovers(os.tmpdir());\n`,
      });
      for (const run of [1, 2]) {
        const result = await startRunner(root).done;
        expect(result.output).not.toContain("unexpected problem");
        expect(result.output).not.toContain("note:");
        expect([run, result.last]).toEqual([run, "xtask: all checks passed."]);
        expect(result.status).toBe(0);
        expect(runsOf(root)).toEqual([]);
      }
    },
  );

  it("lets two runs at once keep their own temporary files", SLOW, async () => {
    // The unit tests keep a file in the temporary folder until the other run's unit tests
    // have started too (so the other run has made its folders ready), then read it back.
    const root = fakeRunnerProject({
      vitest: `import { existsSync, readdirSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
const mine = path.join(os.tmpdir(), "held.txt");
writeFileSync(mine, "x");
writeFileSync(path.join(process.cwd(), "started-" + process.pid), "");
const started = () => readdirSync(process.cwd()).filter((n) => n.startsWith("started-")).length;
for (let waited = 0; started() < 2 && waited < 20_000; waited += 20) {
  await new Promise((resolve) => setTimeout(resolve, 20));
}
if (!existsSync(mine)) {
  console.error("my temporary file is gone");
  process.exit(1);
}
`,
    });
    const first = startRunner(root);
    const started = (): number => readdirSync(root).filter((n) => n.startsWith("started-")).length;
    await waitFor(() => started() === 1);
    const second = startRunner(root);
    const [a, b] = await Promise.all([first.done, second.done]);
    expect(started()).toBe(2);
    expect([a.last, b.last]).toEqual(["xtask: all checks passed.", "xtask: all checks passed."]);
    expect([a.status, b.status]).toEqual([0, 0]);
    expect(runsOf(root)).toEqual([]);
  });

  for (const [signal, code] of [
    ["SIGINT", 130],
    ["SIGTERM", 143],
  ] as const) {
    it(`removes its run folder when stopped by ${signal}`, SLOW, async () => {
      const root = fakeRunnerProject({
        biome: `import { writeFileSync } from "node:fs";
import os from "node:os";
writeFileSync(os.tmpdir() + "/busy.txt", "x");
writeFileSync("started", "");
setTimeout(() => {}, 30_000);
`,
      });
      const run = startRunner(root);
      await waitFor(() => existsSync(path.join(root, "started")));
      expect(runsOf(root)).toHaveLength(1);
      run.child.kill(signal);
      const result = await run.done;
      expect(result.status).toBe(code);
      expect(result.last).toBe(`xtask: stopped by ${signal}.`);
      expect(runsOf(root)).toEqual([]);
    });
  }

  it("removes the folder of a run that was killed outright at the next run", SLOW, async () => {
    const root = fakeRunnerProject({
      biome: `import { existsSync, writeFileSync } from "node:fs";
if (!existsSync("second")) {
  writeFileSync("started", String(process.pid));
  setTimeout(() => {}, 30_000);
}
`,
    });
    const run = startRunner(root);
    await waitFor(() => existsSync(path.join(root, "started")));
    run.child.kill("SIGKILL");
    await run.done;
    // The killed runner's tool is in its own process group; stop it too.
    process.kill(Number(readFileSync(path.join(root, "started"), "utf8")), "SIGKILL");
    expect(runsOf(root)).toHaveLength(1);
    writeFileSync(path.join(root, "second"), "");
    const result = await startRunner(root).done;
    expect(result.last).toBe("xtask: all checks passed.");
    expect(runsOf(root)).toEqual([]);
  });

  it("says to reinstall when a tool cannot even print its version", SLOW, async () => {
    const root = fakeRunnerProject({ biome: "process.exit(1);\n" });
    const result = await startRunner(root).done;
    expect(result.status).toBe(1);
    expect(result.last).toBe(
      `xtask: biome could not run (it fails even when asked only for its version, so its installed files are broken or missing). ${REINSTALL}`,
    );
  });

  it("says to reinstall when a tool hangs when asked only for its version", SLOW, async () => {
    expect(VERSION_PROBE_TIMEOUT_MS).toBeLessThanOrEqual(15_000);
    const root = fakeRunnerProject({
      biome:
        'if (process.argv.includes("--version")) {\n  setTimeout(() => {}, 120_000);\n} else {\n  process.exit(1);\n}\n',
    });
    const started = Date.now();
    const result = await startRunner(root).done;
    expect(Date.now() - started).toBeLessThan(VERSION_PROBE_TIMEOUT_MS + 20_000);
    expect(result.status).toBe(1);
    expect(result.last).toBe(
      `xtask: biome could not run (it fails even when asked only for its version, so its installed files are broken or missing). ${REINSTALL}`,
    );
    expect(runsOf(root)).toEqual([]);
  });

  it("blames vitest when the vite it runs on cannot even print its version", SLOW, async () => {
    const root = fakeRunnerProject({
      vitest: 'process.exit(process.argv.includes("--version") ? 0 : 1);\n',
      vite: "process.exit(1);\n",
    });
    const result = await startRunner(root).done;
    expect(result.status).toBe(1);
    expect(result.last).toBe(
      `xtask: vitest could not run (it fails even when asked only for its version, so its installed files are broken or missing). ${REINSTALL}`,
    );
  });

  it("keeps the lint sentence when the tool itself works", SLOW, async () => {
    const root = fakeRunnerProject({
      biome: 'process.exit(process.argv.includes("--version") ? 0 : 1);\n',
    });
    const result = await startRunner(root).done;
    expect(result.status).toBe(1);
    expect(result.last).toBe(CI_FAILURES[0]);
  });
});

describe("the real runner's exit", () => {
  it("exits at once with its code, even when something still holds Node's event loop", () => {
    // A timer that never ends: Node would keep running if xtask only set process.exitCode.
    const result = spawnSync(
      process.execPath,
      ["--import", "data:text/javascript,setInterval(() => {}, 1000)", MAIN, "help"],
      { cwd: PROJECT, encoding: "utf8", timeout: 20_000 },
    );
    expect(result.signal).toBeNull();
    expect(result.status).toBe(0);
    expect(result.stdout).toBe(`${HELP_TEXT}\n`);
  });

  it("exits at once with 1 after a failure too", () => {
    const result = spawnSync(
      process.execPath,
      ["--import", "data:text/javascript,setInterval(() => {}, 1000)", MAIN, "bogus"],
      { cwd: PROJECT, encoding: "utf8", timeout: 20_000 },
    );
    expect(result.signal).toBeNull();
    expect(result.status).toBe(1);
  });
});
