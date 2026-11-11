// The check runner for this site. Run it with "pnpm xtask <command>".
// Commands: prepare-scaffold, ci, e2e, check-dist, help (see HELP_TEXT below).
//
// Node runs this file directly (type stripping), so it uses only erasable TypeScript syntax.
// It imports only node: builtins statically. The build output checker next to it
// (dist-check.ts) is loaded only when a command needs it, so a missing or broken helper
// ends in the same one plain line as any other unexpected problem.
//
// Output contract:
// - The tools' own output streams live to the terminal, except lines that are pure
//   JavaScript stack frames ("    at fn (file.js:1:2)") and the property dump that Node
//   prints after such frames when it holds no information ("  errors: [Getter/Setter]").
// - When the output is not a terminal (or NO_COLOR is set), colour codes are removed.
// - On any failure the last line the runner prints is one plain sentence: what failed and
//   the command that shows more. When the runner is started through "pnpm xtask ...", pnpm
//   itself appends its own line "[ELIFECYCLE] Command failed with exit code 1." after the
//   runner's last line; that line comes from pnpm, not from this project.
// - Ctrl-C, SIGTERM or SIGHUP stop the running tool too; xtask then prints one line and exits
//   with 128 + the signal number. When the reader of the output goes away (for example
//   "pnpm xtask ci | head -1"), xtask stops its tool and exits with 1 without a message.
//
// Files: the tools started by "ci" keep their temporary files and caches inside the project,
// in .xtask-cache/ (ignored by git and Biome). Not in node_modules/: Node does not strip
// TypeScript types for files there, so a test that runs a .ts file from the temporary folder
// would fail only under xtask. Each run that starts a tool gets its own temporary folder,
// .xtask-cache/tmp/run-XXXXXX, and removes it when it ends; two runs at once never share
// one. Before its first tool starts, a run also removes the folders of runs that have ended
// and empties the compile cache when it has grown past COMPILE_CACHE_BUDGET. Removing is
// best effort: what cannot be removed never stops a run (see prepareRunFolders). Exceptions:
// - "pnpm install" in prepare-scaffold: pnpm keeps its package store outside the project by
//   design (it is the package manager).
// - The browser tests in e2e: Chromium needs the system temporary folder (its socket path
//   must be short) and Playwright finds its browser in the user's cache folder.
// - Checked on Linux. On macOS and Windows Biome may still use the system cache folder.
//
// Known limits:
// - URLs that the site's scripts build at runtime are not checked by dist-check.
// - Problems Node itself hits before this file runs (for example an unreadable
//   tools/xtask/package.json, or a syntax error in this file) cannot be caught here; Node
//   then prints its own message.

// These two lines run first, so that no unexpected error can end in a stack trace.
const startedAsEntry = isEntryPoint(process.argv[1], import.meta.url);
if (startedAsEntry) {
  process.on("uncaughtException", onFatal);
  process.on("unhandledRejection", onFatal);
}

import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import {
  chmodSync,
  closeSync,
  existsSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmdirSync,
  type Stats,
  unlinkSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { hostname, constants as osConstants } from "node:os";
import path from "node:path";
import { isatty } from "node:tty";
import { fileURLToPath } from "node:url";

export const USAGE = "pnpm xtask <prepare-scaffold|ci|e2e|check-dist|help>";
const SETUP_HINT = 'Run "pnpm xtask prepare-scaffold" first.';

export const HELP_TEXT = [
  `Usage: ${USAGE}`,
  "",
  "  prepare-scaffold  install the dependencies and normalise formatting",
  "  ci                format and lint, type check, unit tests, production build, build output check",
  "  e2e               production build, then the browser tests",
  "  check-dist        check the existing build output in dist/",
  "  help              show this text",
  "",
  "On a failure the last line printed by xtask says what failed and which command shows more.",
  'When xtask is started through "pnpm xtask ...", pnpm itself then appends its own line "[ELIFECYCLE] Command failed with exit code 1."; that line comes from pnpm, not from this project.',
].join("\n");

function projectRoot(): string {
  const currentFile = fileURLToPath(import.meta.url);
  return path.resolve(path.dirname(currentFile), "../..");
}

function realPath(file: string): string {
  try {
    return realpathSync(file);
  } catch {
    return path.resolve(file);
  }
}

/**
 * True when Node was started with this file (also through a symlinked path), false when
 * another module (a test) imports it.
 */
export function isEntryPoint(startedFile: string | undefined, moduleUrl: string): boolean {
  if (startedFile === undefined || startedFile === "") {
    return false;
  }
  let self: string;
  try {
    self = fileURLToPath(moduleUrl);
  } catch {
    return false;
  }
  return realPath(startedFile) === realPath(self);
}

/** A failure the user can act on. Its message is the one line xtask prints last. */
export class CheckFailure extends Error {
  override readonly name = "CheckFailure";
}

// --- Text filters -------------------------------------------------------------------------

// Terminal escape sequences start with ESC (character code 27); links and titles end with
// BEL (7) or ESC \. The two control characters are made from their codes, so that no regular
// expression in the source contains a control character.
const ESC = String.fromCharCode(27);
const BEL = String.fromCharCode(7);
/** A complete escape sequence: colour codes, cursor moves, links and titles. */
const ANSI_PATTERN = new RegExp(
  String.raw`${ESC}(?:\[[0-?]*[ -/]*[@-~]|\][^${BEL}${ESC}]*(?:${BEL}|${ESC}\\)|[@-Z\\-_])`,
  "g",
);
/** An escape sequence cut off at the end of a piece of output. */
const ANSI_UNFINISHED = new RegExp(
  String.raw`${ESC}(?:\[[0-?]*[ -/]*|\][^${BEL}${ESC}]*${ESC}?)?$`,
);

function plainText(line: string): string {
  return line.replace(ANSI_PATTERN, "").replace(/\r$/, "");
}

// A stack frame is "at", an optional "async " or "new ", then either a name with a location
// in parentheses, or a bare location. A location must look like a place in code: a path
// (it contains / or \), a URL or node: address, or <anonymous>, native or "index N".
// Decision: a bare file name with line and column in parentheses ("(index.ts:1:2)") counts
// as a location too, because tools print frames that way for files in the current folder.
const SCHEME = "(?:node|file|https?|data|blob|webpack(?:-internal)?|vite|chrome-extension):";
const PAREN_LOCATION = String.raw`(?:<anonymous>|native|index \d+|(?:[^()]*[\\/][^()]*|${SCHEME}[^()]*|<anonymous>|[\w.-]+\.[A-Za-z]\w*):\d+:\d+)`;
const BARE_LOCATION = String.raw`(?:(?:\/|[A-Za-z]:[\\/]|${SCHEME}).*:\d+:\d+|<anonymous>)`;
const FRAME_NAME = String.raw`[^\s()]+(?: \[as [^\]\s]+\])?`;
const STACK_FRAME = new RegExp(
  String.raw`^\s+at (?:async |new )?(?:${FRAME_NAME} \(${PAREN_LOCATION}\)|${BARE_LOCATION})$`,
);

/** True when a line of tool output is nothing but a JavaScript stack frame. */
export function isStackFrame(line: string): boolean {
  // Node prints "    at fn (file.js:1:2) {" when the error object has extra properties.
  return STACK_FRAME.test(plainText(line).replace(/ \{$/, ""));
}

// A property line Node prints after the frames that carries no information.
const EMPTY_PROPERTY = /^ {2}[\w$]+: (?:\[Getter\/Setter\]|\[Getter\]|\[Setter\]),?$/;
const DUMP_LIMIT = 20;

interface LineFilter {
  /** Takes the next piece of output, which may end in the middle of a line. */
  push(chunk: string): void;
  /** Forwards whatever is left once the output has ended. */
  end(): void;
}

/**
 * Splits streamed output into lines and forwards every line that is not a stack frame.
 * A line that does not start with white space can never be a frame, so it is forwarded
 * at once even before its newline arrives (progress output stays live).
 * After a frame that ends in " {", the lines up to the closing "}" are held back and left
 * out only when every one of them is an empty property such as "  errors: [Getter/Setter]";
 * as soon as any other line shows up, all held lines are forwarded unchanged.
 */
export function createLineFilter(forward: (text: string) => void): LineFilter {
  let pending = "";
  let passing = false; // the current line was already judged and partly forwarded
  let dump: string[] | undefined; // lines held after a frame that ended in " {"

  const flushDump = (): void => {
    if (dump !== undefined) {
      const held = dump.join("");
      dump = undefined;
      if (held !== "") {
        forward(held);
      }
    }
  };

  const judgeLine = (line: string): void => {
    const plain = plainText(line.endsWith("\n") ? line.slice(0, -1) : line);
    if (dump !== undefined) {
      if (plain === "}") {
        dump = undefined; // an empty dump: leave it out with its closing brace
        return;
      }
      if (EMPTY_PROPERTY.test(plain) && dump.length < DUMP_LIMIT) {
        dump.push(line);
        return;
      }
      flushDump();
    }
    if (isStackFrame(plain)) {
      if (plain.endsWith(" {")) {
        dump = [];
      }
      return;
    }
    forward(line);
  };

  /** Takes the end of a piece that has no newline yet. */
  const takeUnfinished = (rest: string): void => {
    if (passing) {
      forward(rest);
      return;
    }
    pending += rest;
    const plain = pending.replace(ANSI_PATTERN, "");
    if (dump !== undefined || plain === "" || /^\s/.test(plain)) {
      return; // it may still turn out to be a frame: wait for the rest of the line
    }
    forward(pending);
    pending = "";
    passing = true;
  };

  /** Takes a piece that ends with a newline: the rest of the current line. */
  const takeLineEnd = (piece: string): void => {
    if (passing) {
      forward(piece);
    } else {
      judgeLine(pending + piece);
    }
    pending = "";
    passing = false;
  };

  return {
    push(chunk: string): void {
      let rest = chunk;
      while (rest !== "") {
        const newline = rest.indexOf("\n");
        if (newline === -1) {
          takeUnfinished(rest);
          return;
        }
        takeLineEnd(rest.slice(0, newline + 1));
        rest = rest.slice(newline + 1);
      }
    },
    end(): void {
      if (pending !== "") {
        judgeLine(pending);
      }
      flushDump();
      pending = "";
      passing = false;
    },
  };
}

/** Removes terminal escape sequences from streamed text, also when one is split across pieces. */
export function createAnsiStripper(forward: (text: string) => void): LineFilter {
  let held = "";
  return {
    push(chunk: string): void {
      let text = held + chunk;
      held = "";
      const cut = ANSI_UNFINISHED.exec(text);
      if (cut !== null && cut[0] !== "" && cut[0].length < 4096) {
        held = cut[0];
        text = text.slice(0, cut.index);
      }
      const plain = text.replace(ANSI_PATTERN, "");
      if (plain !== "") {
        forward(plain);
      }
    },
    end(): void {
      // Whatever is still held is the start of an escape sequence that never ended.
      held = "";
    },
  };
}

/** The line printed for an error the runner did not expect; never a stack trace. */
export function unexpectedProblemMessage(error: unknown, command: string | undefined): string {
  const detail = error instanceof Error ? error.message : String(error);
  const firstLine = (detail.split("\n").find((line) => line.trim() !== "") ?? "unknown error")
    .trim()
    .replace(/[.\s]+$/, "");
  const cmd = command === undefined || command === "" ? "<command>" : command;
  return `xtask: unexpected problem: ${firstLine}. Run "node tools/xtask/main.ts ${cmd}" again; if it repeats, reinstall with "pnpm xtask prepare-scaffold".`;
}

function failureLine(error: unknown, command: string | undefined): string {
  return error instanceof CheckFailure ? error.message : unexpectedProblemMessage(error, command);
}

// --- Tools and their environment ----------------------------------------------------------

interface Tool {
  readonly label: string;
  readonly packageName: string;
  readonly binName: string;
  /** Other tools it runs on: when one of them is broken, this one cannot run either. */
  readonly needs?: readonly Tool[];
}

const BIOME: Tool = { label: "biome", packageName: "@biomejs/biome", binName: "biome" };
const TSC: Tool = { label: "tsc", packageName: "typescript", binName: "tsc" };
const VITE: Tool = { label: "vite", packageName: "vite", binName: "vite" };
const VITEST: Tool = { label: "vitest", packageName: "vitest", binName: "vitest", needs: [VITE] };
const PLAYWRIGHT: Tool = {
  label: "playwright",
  packageName: "@playwright/test",
  binName: "playwright",
};

/** Finds the JavaScript file behind a package's command, or undefined if it is not installed. */
function toolScript(root: string, tool: Tool): string | undefined {
  const packageDir = path.join(root, "node_modules", ...tool.packageName.split("/"));
  const manifestPath = path.join(packageDir, "package.json");
  if (!existsSync(manifestPath)) {
    return undefined;
  }
  let bin: unknown;
  try {
    bin = (JSON.parse(readFileSync(manifestPath, "utf8")) as { bin?: unknown }).bin;
  } catch {
    return undefined;
  }
  const relative =
    typeof bin === "string"
      ? bin
      : typeof bin === "object" && bin !== null
        ? (bin as Record<string, unknown>)[tool.binName]
        : undefined;
  if (typeof relative !== "string") {
    return undefined;
  }
  const script = path.join(packageDir, relative);
  return existsSync(script) ? script : undefined;
}

function requireTools(root: string, tools: readonly Tool[]): void {
  if (!existsSync(path.join(root, "node_modules"))) {
    throw new CheckFailure(`xtask: the project's tools are not installed. ${SETUP_HINT}`);
  }
  for (const tool of tools) {
    if (toolScript(root, tool) === undefined) {
      throw new CheckFailure(`xtask: ${tool.label} is not installed. ${SETUP_HINT}`);
    }
  }
}

/**
 * Whether the tools should print colours: as the user asked with NO_COLOR or FORCE_COLOR,
 * otherwise only when xtask itself writes to a terminal.
 */
export function wantsColour(env: NodeJS.ProcessEnv, stdoutIsTerminal: boolean): boolean {
  const noColor = env["NO_COLOR"];
  if (noColor !== undefined && noColor !== "") {
    return false;
  }
  const forceColor = env["FORCE_COLOR"];
  if (forceColor !== undefined) {
    return forceColor !== "0" && forceColor !== "false";
  }
  return stdoutIsTerminal;
}

/**
 * The environment for every command: CI=1, plus a colour setting that matches wantsColour.
 * The tools write into a pipe, so without help they would turn colours off on a
 * terminal, and some (picocolors, because CI is set) would turn them on in a file.
 * FORCE_COLOR and NO_COLOR set by the user are passed on unchanged.
 */
export function childEnvironment(
  base: NodeJS.ProcessEnv,
  stdoutIsTerminal: boolean,
): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...base, CI: "1" };
  const userChose = env["FORCE_COLOR"] !== undefined || env["NO_COLOR"] !== undefined;
  if (wantsColour(base, stdoutIsTerminal)) {
    if (!userChose) {
      env["FORCE_COLOR"] = "1";
    }
  } else if (env["NO_COLOR"] === undefined || env["NO_COLOR"] === "") {
    env["NO_COLOR"] = "1";
  }
  return env;
}

/** The shared layout of .xtask-cache/. */
interface CacheFolders {
  /** Holds one folder per run (see prepareRunFolders). */
  readonly tmp: string;
  /** XDG cache folder (Biome keeps its cache folder here on Linux). */
  readonly cache: string;
  /** Node's compile cache (tsc and vite turn it on), shared by all runs. */
  readonly compile: string;
}

/** The folders of one run. */
export interface RunFolders {
  /** The real path of <project>/.xtask-cache. */
  readonly base: string;
  /** This run's own folder in .xtask-cache/tmp: the owner file and tmp. */
  readonly run: string;
  /** This run's temporary folder (os.tmpdir() of the tools). */
  readonly tmp: string;
  readonly cache: string;
  readonly compile: string;
}

/** The folder, at the project root, where the tools keep temporary files and caches. */
export const CACHE_FOLDER = ".xtask-cache";

/**
 * The largest size (the sum of its file sizes) the compile cache may reach before xtask
 * empties it. Every run adds a little (vite compiles its config under a new name each time).
 */
export const COMPILE_CACHE_BUDGET = 20 * 1024 * 1024;

/** Run folders are named run-XXXXXX (made with mkdtemp, so the name is unique). */
export const RUN_PREFIX = "run-";
/** The file in a run folder that says which process made it, on which machine, and when. */
export const OWNER_FILE = "owner.json";
/** A run folder older than this is removed even if its process id is in use (again). */
export const STALE_AGE_MS = 24 * 60 * 60 * 1000;
/** A run folder without an owner file is kept this long: its run may just be starting. */
const NO_OWNER_GRACE_MS = 10 * 60 * 1000;

/** The one note xtask prints when old temporary files could not be removed. */
export const LEFTOVER_NOTE = `xtask: note: some old temporary files in ${CACHE_FOLDER}/tmp/ could not be removed; the checks are not affected. When no check is running, remove them with: chmod -R u+rwx ${CACHE_FOLDER} && rm -rf ${CACHE_FOLDER}`;

/** Where the shared folders are: inside the project, ignored by git. */
export function cacheFolders(root: string): CacheFolders {
  const base = path.join(root, CACHE_FOLDER);
  return {
    tmp: path.join(base, "tmp"),
    cache: path.join(base, "cache"),
    compile: path.join(base, "compile-cache"),
  };
}

/**
 * The environment for a project tool: keeps its temporary files and caches inside the
 * project. TMPDIR/TMP/TEMP move os.tmpdir() (vitest's temporary folder) into this run's own
 * folder, NODE_COMPILE_CACHE moves Node's compile cache (module.enableCompileCache() in tsc
 * and vite uses it), and XDG_CACHE_HOME moves Biome's cache folder.
 * Playwright keeps the user's temporary and XDG cache folders: Chromium puts a socket in
 * the temporary folder, and socket paths must be short (about 100 characters), and
 * Playwright looks for its browser under XDG_CACHE_HOME.
 */
export function toolEnvironment(
  base: NodeJS.ProcessEnv,
  folders: Pick<RunFolders, "tmp" | "cache" | "compile">,
  options: { readonly browser: boolean },
): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...base, NODE_COMPILE_CACHE: folders.compile };
  if (!options.browser) {
    env["TMPDIR"] = folders.tmp;
    env["TMP"] = folders.tmp;
    env["TEMP"] = folders.tmp;
    env["XDG_CACHE_HOME"] = folders.cache;
  }
  return env;
}

function errorCode(error: unknown): string | undefined {
  return (error as NodeJS.ErrnoException | undefined)?.code;
}

function isMissing(error: unknown): boolean {
  return errorCode(error) === "ENOENT";
}

function tryLstat(file: string): Stats | undefined {
  try {
    return lstatSync(file);
  } catch {
    return undefined;
  }
}

function tryReaddir(folder: string): string[] {
  try {
    return readdirSync(folder);
  } catch {
    return [];
  }
}

/** Makes a folder (and its parents); false when it cannot be made. */
export function tryMakeFolder(folder: string): boolean {
  try {
    mkdirSync(folder, { recursive: true });
    return true;
  } catch {
    return false;
  }
}

/** Gives a folder (known from lstat to be a real folder) u+rwx, if it lacks it. */
function makeOwnerWritable(folder: string, mode: number): void {
  if ((mode & 0o700) !== 0o700) {
    chmodSync(folder, (mode & 0o7777) | 0o700);
  }
}

/**
 * The sum of the sizes of the files below a folder. Links are not followed; what cannot be
 * read is not counted.
 */
function folderSize(folder: string): number {
  let total = 0;
  const pending = [folder];
  for (let next = pending.pop(); next !== undefined; next = pending.pop()) {
    for (const name of tryReaddir(next)) {
      const entry = path.join(next, name);
      const info = tryLstat(entry);
      if (info?.isDirectory()) {
        pending.push(entry);
      } else if (info !== undefined) {
        total += info.size;
      }
    }
  }
  return total;
}

// Paths longer than this are moved up before they are removed, so that no path xtask uses
// comes near PATH_MAX (4096 bytes on Linux), however deep a tool's leftovers are.
const LONG_PATH = 2048;

/**
 * Deletes a file or folder that lies inside the folder "inside", as far as it can, and
 * returns whether it is gone. Best effort: it never throws for a file it cannot remove.
 * - A link is removed itself; what it points to is never touched or even read.
 * - A folder without u+rwx gets it first (chmod), so read-only leftovers go too.
 * - A folder whose path grows long is first moved to the top of the target.
 * Throws only when the target is not inside "inside" (a programming error).
 */
export function removeTree(target: string, inside: string): boolean {
  if (!target.startsWith(`${inside}${path.sep}`)) {
    throw new Error(`refusing to delete ${target}: it is not inside ${inside}`);
  }
  let failed = false;
  let moved = 0;
  const shortName = (): string => {
    for (;;) {
      moved += 1;
      const candidate = path.join(target, `.xtask-moved-${moved}`);
      if (tryLstat(candidate) === undefined) {
        return candidate;
      }
    }
  };
  const folders: Array<{ readonly path: string; readonly mode: number; opened: boolean }> = [];
  const visit = (entry: string): void => {
    let info: Stats;
    try {
      info = lstatSync(entry);
    } catch (error: unknown) {
      failed ||= !isMissing(error);
      return;
    }
    if (info.isDirectory()) {
      folders.push({ path: entry, mode: info.mode, opened: false });
      return;
    }
    try {
      unlinkSync(entry);
    } catch (error: unknown) {
      failed ||= !isMissing(error);
    }
  };
  visit(target);
  for (let folder = folders.at(-1); folder !== undefined; folder = folders.at(-1)) {
    if (folder.opened) {
      folders.pop();
      try {
        rmdirSync(folder.path);
      } catch (error: unknown) {
        failed ||= !isMissing(error);
      }
      continue;
    }
    folder.opened = true;
    let names: string[];
    try {
      makeOwnerWritable(folder.path, folder.mode);
      names = readdirSync(folder.path);
    } catch (error: unknown) {
      failed ||= !isMissing(error);
      continue;
    }
    for (const name of names) {
      let entry = path.join(folder.path, name);
      if (entry.length > LONG_PATH) {
        const short = shortName();
        try {
          renameSync(entry, short);
          entry = short;
        } catch (error: unknown) {
          failed ||= !isMissing(error);
          continue;
        }
      }
      visit(entry);
    }
  }
  return !failed && tryLstat(target) === undefined;
}

/** What the owner file of a run folder says. */
export interface RunOwner {
  readonly pid: number;
  readonly host: string;
  /** When the run started (milliseconds since 1970). */
  readonly started: number;
}

/** True while a process with this id exists (also one of another user). */
export function isProcessAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) {
    return false;
  }
  try {
    process.kill(pid, 0);
    return true;
  } catch (error: unknown) {
    return errorCode(error) === "EPERM";
  }
}

/**
 * Whether a run folder may be removed: its owner has ended (same machine, process id not
 * running), or it is older than STALE_AGE_MS (a process id can be reused), or it has had
 * no owner file for longer than NO_OWNER_GRACE_MS. A folder from another machine is kept
 * until it is old, because xtask cannot ask whether its process still runs.
 */
export function isRunFolderStale(
  owner: RunOwner | undefined,
  folderTimeMs: number,
  now: number,
  self: { readonly host: string },
  isAlive: (pid: number) => boolean,
): boolean {
  if (owner === undefined) {
    return now - folderTimeMs > NO_OWNER_GRACE_MS;
  }
  if (now - owner.started > STALE_AGE_MS) {
    return true;
  }
  if (owner.host !== self.host) {
    return false;
  }
  return !isAlive(owner.pid);
}

/** Reads a run folder's owner file; undefined when it is missing, not a file, or not valid. */
function readOwner(run: string): RunOwner | undefined {
  let fd: number | undefined;
  try {
    // O_NOFOLLOW: never read through a link; O_NONBLOCK: never wait on a pipe.
    fd = openSync(
      path.join(run, OWNER_FILE),
      fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK,
    );
    const info = fstatSync(fd);
    if (!info.isFile() || info.size > 1024) {
      return undefined;
    }
    const value = JSON.parse(readFileSync(fd, "utf8")) as Partial<RunOwner>;
    if (
      typeof value.pid === "number" &&
      typeof value.host === "string" &&
      typeof value.started === "number"
    ) {
      return { pid: value.pid, host: value.host, started: value.started };
    }
    return undefined;
  } catch {
    return undefined;
  } finally {
    if (fd !== undefined) {
      closeSync(fd);
    }
  }
}

/** Fails unless the path is missing or a real folder (not a link, not a file). */
function requireFolderOrNothing(folder: string, shown: string): void {
  let info: Stats;
  try {
    info = lstatSync(folder);
  } catch (error: unknown) {
    if (isMissing(error)) {
      return;
    }
    // Usually EACCES: the cache folder lost its permissions (for example chmod 000).
    throw new CheckFailure(
      `xtask: ${shown} cannot be used (${errorCode(error) ?? "unknown error"}). Give yourself access to ${CACHE_FOLDER}/ (chmod -R u+rwx ${CACHE_FOLDER}) or delete it, then run the command again.`,
    );
  }
  if (!info.isDirectory()) {
    throw new CheckFailure(
      `xtask: ${shown} must be a folder inside the project, but it is a link or a file. Delete it and run the command again.`,
    );
  }
}

export interface PrepareOptions {
  /** See COMPILE_CACHE_BUDGET. */
  readonly budget?: number;
  /** Decides whether a process still runs (tests replace it). */
  readonly isAlive?: (pid: number) => boolean;
  /** Removes something inside .xtask-cache (tests replace it). */
  readonly remove?: (target: string, inside: string) => boolean;
}

export interface PreparedFolders {
  readonly folders: RunFolders;
  /** LEFTOVER_NOTE when old files could not be removed, otherwise undefined. */
  readonly note: string | undefined;
}

/**
 * Makes the folders ready before the first tool of a run starts:
 * 1. creates .xtask-cache/{tmp,cache,compile-cache} and this run's own folder
 *    tmp/run-XXXXXX (mkdtemp) with its owner file and its temporary folder;
 * 2. removes what no live run owns: run folders that isRunFolderStale allows, and anything
 *    else in tmp/ (links and files are removed themselves, never followed);
 * 3. empties the compile cache when it is larger than the budget.
 * Whatever is removed is first moved into this run's folder (rename is atomic), so that two
 * runs never work on the same folder. Nothing that cannot be removed stops the run: it
 * stays in this run's folder, is tried again at the end of the run and by later runs, and
 * the result carries one note.
 * Everything happens inside the real path of <root>/.xtask-cache; when that path (or one of
 * its three folders) is a link or a file, nothing is deleted or created and a CheckFailure
 * says what to do.
 */
export function prepareRunFolders(root: string, options: PrepareOptions = {}): PreparedFolders {
  const budget = options.budget ?? COMPILE_CACHE_BUDGET;
  const isAlive = options.isAlive ?? isProcessAlive;
  const remove = options.remove ?? removeTree;
  const base = path.join(realPath(root), CACHE_FOLDER);
  const shared = cacheFolders(path.dirname(base));
  requireFolderOrNothing(base, `${CACHE_FOLDER}/`);
  for (const [folder, name] of [
    [shared.tmp, "tmp"],
    [shared.cache, "cache"],
    [shared.compile, "compile-cache"],
  ] as const) {
    requireFolderOrNothing(folder, `${CACHE_FOLDER}/${name}/`);
  }
  const host = hostname();
  let run: string;
  try {
    for (const folder of [shared.tmp, shared.cache, shared.compile]) {
      mkdirSync(folder, { recursive: true });
    }
    const tmpInfo = lstatSync(shared.tmp);
    makeOwnerWritable(shared.tmp, tmpInfo.mode);
    run = mkdtempSync(path.join(shared.tmp, RUN_PREFIX));
    const owner: RunOwner = { pid: process.pid, host, started: Date.now() };
    writeFileSync(path.join(run, OWNER_FILE), `${JSON.stringify(owner)}\n`, { flag: "wx" });
    mkdirSync(path.join(run, "tmp"));
  } catch (error: unknown) {
    if (error instanceof CheckFailure) {
      throw error;
    }
    throw new CheckFailure(
      `xtask: could not create ${CACHE_FOLDER}/ for the tools' temporary files (${errorCode(error) ?? "unknown error"}). Make the project folder writable, then run the command again.`,
    );
  }
  const folders: RunFolders = {
    base,
    run,
    tmp: path.join(run, "tmp"),
    cache: shared.cache,
    compile: shared.compile,
  };

  let leftovers = false;
  let claimed = 0;
  /** Moves an entry into this run's folder, then removes it. */
  const claimAndRemove = (entry: string, info: Stats): void => {
    claimed += 1;
    const mine = path.join(run, `old-${claimed}`);
    try {
      if (info.isDirectory()) {
        makeOwnerWritable(entry, info.mode); // moving a folder needs write permission on it
      }
      renameSync(entry, mine);
    } catch (error: unknown) {
      if (!isMissing(error)) {
        leftovers = true; // another run took it if it is missing; otherwise it stays put
      }
      return;
    }
    if (!remove(mine, base)) {
      leftovers = true;
    }
  };

  const now = Date.now();
  for (const name of tryReaddir(shared.tmp)) {
    const entry = path.join(shared.tmp, name);
    if (entry === run) {
      continue;
    }
    const info = tryLstat(entry);
    if (info === undefined) {
      continue;
    }
    if (
      info.isDirectory() &&
      name.startsWith(RUN_PREFIX) &&
      !isRunFolderStale(readOwner(entry), info.mtimeMs, now, { host }, isAlive)
    ) {
      continue;
    }
    claimAndRemove(entry, info);
  }

  if (folderSize(shared.compile) > budget) {
    const info = tryLstat(shared.compile);
    if (info?.isDirectory()) {
      claimAndRemove(shared.compile, info);
    }
    // When it cannot be made again, the tools run without a compile cache; that only makes
    // them slower.
    tryMakeFolder(shared.compile);
  }
  return { folders, note: leftovers ? LEFTOVER_NOTE : undefined };
}

/**
 * Removes a run's own folder at the end of the run, as far as it can: everything in it
 * first and the owner file last, so that a folder that cannot be removed completely still
 * says whose it was (later runs remove it once that process has ended).
 */
export function removeRunFolder(
  folders: Pick<RunFolders, "base" | "run">,
  remove: (target: string, inside: string) => boolean = removeTree,
): boolean {
  let complete = true;
  for (const name of tryReaddir(folders.run)) {
    if (name !== OWNER_FILE) {
      complete = remove(path.join(folders.run, name), folders.base) && complete;
    }
  }
  return complete && remove(folders.run, folders.base);
}

// --- Commands and the step runner ---------------------------------------------------------

export type StreamId = 1 | 2;

/** A command xtask starts: a project tool, or pnpm itself. */
export type Command =
  | { readonly kind: "tool"; readonly tool: Tool; readonly args: readonly string[] }
  | { readonly kind: "pnpm"; readonly args: readonly string[] };

function commandLabel(command: Command): string {
  return command.kind === "tool" ? command.tool.label : "pnpm";
}

export function commandDisplay(command: Command): string {
  return `${commandLabel(command)} ${command.args.join(" ")}`;
}

/** How a started command ended. */
export interface ExecResult {
  /** The exit code, or null when the command was stopped by a signal. */
  readonly code: number | null;
  readonly signal: string | null;
  /** Set (for example to "EACCES") when the command could not be started at all. */
  readonly startError: string | undefined;
}

/** Everything the runner does to the outside world; the tests replace it. */
export interface RunnerIo {
  /** Whether colour codes in the tools' output are kept. */
  readonly colour: boolean;
  /** Writes text as it is to stdout (1) or stderr (2). */
  write(stream: StreamId, text: string): void;
  /** Runs a command; every piece of its output goes to sink, in the order it arrives. */
  exec(command: Command, sink: (stream: StreamId, text: string) => void): Promise<ExecResult>;
  /** The problems in a build output folder (dist-check.ts). */
  checkDist(distDir: string): Promise<string[]>;
  /**
   * Whether a tool (and the tools it needs) can start at all: "<tool> --version" ends with
   * exit code 0. Asked only after a command of that tool failed. The version commands read
   * none of the project's files, so the user's code cannot make them fail.
   */
  canStart(tool: Tool): Promise<boolean>;
}

/** xtask's own lines and the tools' output, with each line kept whole. */
interface Output {
  /** Prints one of xtask's own lines, first ending any tool output that lacks its newline. */
  line(stream: StreamId, text: string): void;
  /** A stream for a tool's output: frames left out, colours removed when wanted. */
  tool(stream: StreamId): LineFilter;
}

export function createOutput(io: Pick<RunnerIo, "colour" | "write">): Output {
  const ended: Record<StreamId, boolean> = { 1: true, 2: true };
  const write = (stream: StreamId, text: string): void => {
    if (text !== "") {
      io.write(stream, text);
      ended[stream] = text.endsWith("\n");
    }
  };
  return {
    line(stream: StreamId, text: string): void {
      for (const other of [1, 2] as const) {
        if (!ended[other]) {
          write(other, "\n");
        }
      }
      write(stream, `${text}\n`);
    },
    tool(stream: StreamId): LineFilter {
      const filter = createLineFilter((text) => write(stream, text));
      if (io.colour) {
        return filter;
      }
      const stripper = createAnsiStripper((text) => filter.push(text));
      return {
        push: (chunk) => stripper.push(chunk),
        end: () => {
          stripper.end();
          filter.end();
        },
      };
    },
  };
}

/**
 * Why a command could not do its work (it could not be started, was killed, or its shell
 * could not run it), or undefined when it ran and ended with an exit code of its own.
 * Any other exit code, also after an uncaught error in the user's own code (a plugin in
 * vite.config.ts, a test, a script), is an ordinary failure of the step.
 */
export function crashReason(result: ExecResult): string | undefined {
  if (result.startError !== undefined) {
    return `it could not be started: ${result.startError}`;
  }
  if (result.signal !== null) {
    return `it was stopped by signal ${result.signal}`;
  }
  if (result.code === null) {
    return "it stopped without an exit code";
  }
  if (result.code === 126) {
    return "exit code 126: a program it needs cannot be run";
  }
  if (result.code === 127) {
    return "exit code 127: a program it needs was not found";
  }
  return undefined;
}

/** The reason given when a tool that failed cannot even print its version. */
const BROKEN_INSTALL =
  "it fails even when asked only for its version, so its installed files are broken or missing";

function couldNotRunMessage(label: string, reason: string): string {
  // "pnpm install" does not repair files missing from an existing node_modules folder.
  return `xtask: ${label} could not run (${reason}). Reinstall: delete the node_modules folder, then run "pnpm xtask prepare-scaffold".`;
}

interface StepContext {
  readonly io: RunnerIo;
  readonly output: Output;
}

/** The outcome of a step: passed, or failed with an optional line that replaces the step's own. */
type Verdict = { readonly ok: true } | { readonly ok: false; readonly line?: string };

export interface Step {
  readonly label: string;
  /** The sentence printed when this step fails. */
  readonly failure: string;
  readonly run: (context: StepContext) => Promise<Verdict>;
}

interface CommandOutcome {
  readonly result: ExecResult;
  /** Set when the command could not do its work; see crashReason. */
  readonly crash: string | undefined;
}

/** Echoes a command, runs it and streams its output through the filters. */
async function runCommand(context: StepContext, command: Command): Promise<CommandOutcome> {
  context.output.line(1, `+ ${commandDisplay(command)}`);
  const streams = { 1: context.output.tool(1), 2: context.output.tool(2) } as const;
  let result: ExecResult;
  try {
    result = await context.io.exec(command, (stream, text) => streams[stream].push(text));
  } finally {
    streams[1].end();
    streams[2].end();
  }
  return { result, crash: crashReason(result) };
}

/** A step that runs commands one after another and stops at the first that does not pass. */
function commandStep(label: string, failure: string, commands: readonly Command[]): Step {
  return {
    label,
    failure,
    run: async (context) => {
      for (const command of commands) {
        const { result, crash } = await runCommand(context, command);
        if (crash !== undefined) {
          return { ok: false, line: couldNotRunMessage(commandLabel(command), crash) };
        }
        if (result.code !== 0) {
          if (command.kind === "tool" && !(await context.io.canStart(command.tool))) {
            return { ok: false, line: couldNotRunMessage(command.tool.label, BROKEN_INSTALL) };
          }
          return { ok: false };
        }
      }
      return { ok: true };
    },
  };
}

type StepStatus = "PASS" | "FAIL" | "SKIPPED";

interface SummaryRow {
  readonly label: string;
  readonly status: StepStatus;
}

/**
 * The summary rows for all steps, given the outcomes of the steps that ran (in order).
 * Steps after the first failure are SKIPPED; steps not reached for another reason too.
 */
export function summaryRows(labels: readonly string[], outcomes: readonly boolean[]): SummaryRow[] {
  const failedAt = outcomes.indexOf(false);
  return labels.map((label, index) => {
    const outcome = outcomes[index];
    if (outcome === undefined || (failedAt !== -1 && index > failedAt)) {
      return { label, status: "SKIPPED" };
    }
    return { label, status: outcome ? "PASS" : "FAIL" };
  });
}

/** The summary table as lines of text, starting with an empty line. */
export function renderSummary(rows: readonly SummaryRow[]): string[] {
  const width = Math.max(24, ...rows.map((row) => row.label.length));
  const divider = `${"-".repeat(width + 2)}+--------`;
  return [
    "",
    divider,
    ` ${"Step".padEnd(width)} | Status`,
    divider,
    ...rows.map((row) => ` ${row.label.padEnd(width)} | ${row.status}`),
    divider,
  ];
}

interface RunOptions {
  /** The last line when every step passed. */
  readonly success: string;
  /** The xtask command, for the message about an unexpected problem. */
  readonly command: string;
}

/**
 * Runs steps in order and stops at the first failure, then prints the summary table and
 * one last line. Never throws for a failing step. Returns the exit code (0 or 1).
 */
export async function runSteps(
  steps: readonly Step[],
  io: RunnerIo,
  options: RunOptions,
  output: Output = createOutput(io),
): Promise<number> {
  const context: StepContext = { io, output };
  const outcomes: boolean[] = [];
  let last = options.success;
  for (const step of steps) {
    let verdict: Verdict;
    try {
      verdict = await step.run(context);
    } catch (error: unknown) {
      verdict = { ok: false, line: failureLine(error, options.command) };
    }
    outcomes.push(verdict.ok);
    if (!verdict.ok) {
      last = verdict.line ?? step.failure;
      break;
    }
  }
  const passed = outcomes.length === steps.length && outcomes.every((ok) => ok);
  const rows = summaryRows(
    steps.map((step) => step.label),
    outcomes,
  );
  for (const line of renderSummary(rows)) {
    output.line(1, line);
  }
  output.line(passed ? 1 : 2, last);
  return passed ? 0 : 1;
}

async function reportDist(context: StepContext, distDir: string): Promise<boolean> {
  const problems = await context.io.checkDist(distDir);
  for (const problem of problems) {
    context.output.line(2, problem);
  }
  if (problems.length === 0) {
    context.output.line(1, "Build output check: no problems found in dist/.");
  } else {
    context.output.line(2, `Build output check: ${problems.length} problem(s) found in dist/.`);
  }
  return problems.length === 0;
}

const BUILD_STEP_LABEL = "production build (vite build)";
const BUILD_FAILURE = 'xtask: the production build failed. Run "pnpm build" to see the details.';

/** The steps of "xtask ci", in order. */
export function ciSteps(root: string): Step[] {
  return [
    commandStep(
      "format and lint (biome ci)",
      'xtask: the format and lint check failed. Run "pnpm lint" to see the details, and "pnpm format" to fix formatting.',
      [{ kind: "tool", tool: BIOME, args: ["ci", "."] }],
    ),
    commandStep(
      "type check (tsc)",
      'xtask: the type check failed. Run "pnpm typecheck" to see the details.',
      [
        { kind: "tool", tool: TSC, args: ["-p", "tsconfig.json"] },
        { kind: "tool", tool: TSC, args: ["-p", "tools/xtask/tsconfig.json"] },
      ],
    ),
    commandStep(
      "unit tests (vitest run)",
      'xtask: the unit tests failed. Run "pnpm test" to see the details.',
      [{ kind: "tool", tool: VITEST, args: ["run"] }],
    ),
    commandStep(BUILD_STEP_LABEL, BUILD_FAILURE, [{ kind: "tool", tool: VITE, args: ["build"] }]),
    {
      label: "build output check (dist/)",
      failure:
        'xtask: the build output check found problems in dist/. Run "pnpm xtask check-dist" to see the list.',
      run: async (context) => {
        context.output.line(1, "+ check dist/");
        return { ok: await reportDist(context, path.join(root, "dist")) };
      },
    },
  ];
}

/** The steps of "xtask e2e", in order. */
export function e2eSteps(): Step[] {
  return [
    commandStep(BUILD_STEP_LABEL, BUILD_FAILURE, [{ kind: "tool", tool: VITE, args: ["build"] }]),
    commandStep(
      "browser tests (playwright)",
      'xtask: the browser tests failed. Run "pnpm exec playwright test" to see the details.',
      [{ kind: "tool", tool: PLAYWRIGHT, args: ["test"] }],
    ),
  ];
}

async function cmdPrepareScaffold(root: string, context: StepContext): Promise<number> {
  const install = await runCommand(context, {
    kind: "pnpm",
    args: ["install", "--frozen-lockfile"],
  });
  if (install.result.startError !== undefined) {
    throw new CheckFailure(
      'xtask: pnpm could not be started. Install the pnpm version named in "packageManager" in package.json, then try again.',
    );
  }
  if (install.result.code !== 0) {
    throw new CheckFailure(
      'xtask: installing the dependencies failed. Run "pnpm install --frozen-lockfile" to see the details.',
    );
  }
  requireTools(root, [BIOME]);
  // Explicit normalisation step; "ci" itself never changes files.
  const format = await runCommand(context, {
    kind: "tool",
    tool: BIOME,
    args: ["check", "--write", "--linter-enabled=false", "."],
  });
  if (format.crash !== undefined) {
    throw new CheckFailure(couldNotRunMessage("biome", format.crash));
  }
  if (format.result.code !== 0) {
    if (!(await context.io.canStart(BIOME))) {
      throw new CheckFailure(couldNotRunMessage("biome", BROKEN_INSTALL));
    }
    throw new CheckFailure(
      'xtask: formatting the project failed. Run "pnpm exec biome check --write --linter-enabled=false ." to see the details.',
    );
  }
  context.output.line(1, 'xtask: the project is ready. Run "pnpm xtask ci" to check it.');
  return 0;
}

async function cmdCheckDist(root: string, context: StepContext): Promise<number> {
  const distDir = path.join(root, "dist");
  if (!existsSync(distDir)) {
    throw new CheckFailure('xtask: there is no dist/ folder yet. Run "pnpm build" first.');
  }
  if (!(await reportDist(context, distDir))) {
    throw new CheckFailure(
      "xtask: the build output check found problems in dist/; each one is listed above.",
    );
  }
  return 0;
}

/** Asks Playwright where it expects the browser, without starting or downloading anything. */
function playwrightBrowserPath(root: string): string | undefined {
  const probe =
    'import { chromium } from "@playwright/test"; process.stdout.write(chromium.executablePath());';
  const result = spawnSync(process.execPath, ["--input-type=module", "--eval", probe], {
    cwd: root,
    env: environmentFor(root, PLAYWRIGHT),
    stdio: ["ignore", "pipe", "pipe"],
    encoding: "utf8",
  });
  if (result.error !== undefined || result.status !== 0) {
    return undefined;
  }
  const found = result.stdout.trim();
  return found === "" ? undefined : found;
}

async function cmdE2e(root: string, context: StepContext): Promise<number> {
  requireTools(root, [VITE, PLAYWRIGHT]);
  const browser = playwrightBrowserPath(root);
  if (browser === undefined || !existsSync(browser)) {
    throw new CheckFailure(
      'xtask: the Playwright browser is not installed; run "pnpm exec playwright install chromium" once (it downloads the browser), then run "pnpm xtask e2e" again.',
    );
  }
  return runSteps(
    e2eSteps(),
    context.io,
    { success: "xtask: all browser tests passed.", command: "e2e" },
    context.output,
  );
}

/** Runs one xtask command. Never throws: every failure ends in one printed line and code 1. */
export async function main(argv: readonly string[], io: RunnerIo): Promise<number> {
  const output = createOutput(io);
  const context: StepContext = { io, output };
  const command = argv[0];
  try {
    if (command === "help" || command === "--help" || command === "-h") {
      output.line(1, HELP_TEXT);
      return 0;
    }
    if (argv.length > 1) {
      throw new CheckFailure(`xtask: "${command}" takes no extra arguments. Usage: ${USAGE}`);
    }
    const root = projectRoot();
    switch (command) {
      case "prepare-scaffold":
        return await cmdPrepareScaffold(root, context);
      case "ci":
        requireTools(root, [BIOME, TSC, VITEST, VITE]);
        return await runSteps(
          ciSteps(root),
          io,
          { success: "xtask: all checks passed.", command: "ci" },
          output,
        );
      case "e2e":
        return await cmdE2e(root, context);
      case "check-dist":
        return await cmdCheckDist(root, context);
      case undefined:
        throw new CheckFailure(`xtask: no command given. Usage: ${USAGE}`);
      default:
        throw new CheckFailure(`xtask: unknown command "${command}". Usage: ${USAGE}`);
    }
  } catch (error: unknown) {
    output.line(2, failureLine(error, command));
    return 1;
  }
}

// --- The real process: output, child processes, signals -----------------------------------

const running = new Set<ChildProcess>();
let stopping = false;
const pause = new Int32Array(new SharedArrayBuffer(4));

/** Writes everything to a file descriptor, waiting briefly when a non-blocking pipe is full. */
function writeAll(fd: number, text: string): void {
  const bytes = Buffer.from(text, "utf8");
  let offset = 0;
  while (offset < bytes.length) {
    try {
      offset += writeSync(fd, bytes, offset, bytes.length - offset);
    } catch (error: unknown) {
      if ((error as NodeJS.ErrnoException).code !== "EAGAIN") {
        throw error;
      }
      Atomics.wait(pause, 0, 0, 2);
    }
  }
}

/** Like writeAll, but returns false instead of throwing when nobody can read the output. */
export function tryWriteAll(fd: number, text: string): boolean {
  try {
    writeAll(fd, text);
    return true;
  } catch {
    return false;
  }
}

function isBrokenPipe(error: unknown): boolean {
  return (error as NodeJS.ErrnoException | undefined)?.code === "EPIPE";
}

/**
 * Runs `send`, which sends a signal, and says whether it could: false when the process or
 * group has ended already (or may not be signalled), which is never a reason to stop.
 */
export function sendSignal(send: () => void): boolean {
  try {
    send();
    return true;
  } catch {
    return false;
  }
}

/** Sends a signal to a command and everything it started (its own process group). */
function killTree(child: ChildProcess, signal: NodeJS.Signals): void {
  const pid = child.pid;
  if (pid === undefined) {
    return;
  }
  if (process.platform !== "win32" && sendSignal(() => process.kill(-pid, signal))) {
    return;
  }
  // The group is gone already (or this is Windows): signal the process itself, if it runs.
  sendSignal(() => child.kill(signal));
}

function killGroup(pid: number, signal: NodeJS.Signals): void {
  if (process.platform !== "win32") {
    sendSignal(() => process.kill(-pid, signal)); // false: nothing left in the group
  }
}

/** The reader of xtask's output went away: stop the tool and exit with 1, saying nothing. */
function stopQuietly(): never {
  stopping = true;
  for (const child of running) {
    killTree(child, "SIGTERM");
  }
  process.exit(1);
}

/** Writes to stdout or stderr; a closed pipe ends xtask quietly. */
function writeOutput(fd: StreamId, text: string): void {
  if (stopping) {
    return;
  }
  try {
    writeAll(fd, text);
  } catch (error: unknown) {
    if (isBrokenPipe(error)) {
      stopQuietly();
    }
    throw error;
  }
}

/** Passes a signal on to the running tool, waits briefly for it, then exits with 128 + n. */
function stopForSignal(signal: NodeJS.Signals): void {
  const code = 128 + (osConstants.signals[signal] ?? 0);
  const groups = [...running].flatMap((child) => (child.pid === undefined ? [] : [child.pid]));
  const finish = (): never => {
    for (const child of running) {
      killTree(child, "SIGKILL");
    }
    for (const pid of groups) {
      killGroup(pid, "SIGKILL");
    }
    tryWriteAll(2, `xtask: stopped by ${signal}.\n`); // false: nobody is reading any more
    process.exit(code);
  };
  if (stopping) {
    finish(); // a second signal: do not wait any longer
  }
  stopping = true;
  for (const child of running) {
    killTree(child, signal);
  }
  const deadline = Date.now() + 2000;
  const poll = (): void => {
    if (running.size === 0 || Date.now() > deadline) {
      finish();
    } else {
      setTimeout(poll, 50);
    }
  };
  poll();
}

/** An error nobody caught: one plain line, stop the tool, exit with 1. */
function onFatal(error: unknown): void {
  if (isBrokenPipe(error)) {
    stopQuietly();
  }
  let line: string;
  try {
    line = failureLine(error, process.argv[2]);
    stopping = true;
    for (const child of running) {
      killTree(child, "SIGTERM");
    }
  } catch {
    line = unexpectedProblemMessage(error, process.argv[2]);
  }
  tryWriteAll(2, `${line}\n`); // false: stderr itself is gone; nothing more can be said
  process.exit(1);
}

let readyFolders: RunFolders | undefined;

/**
 * Removes this run's folder when xtask exits, however it exits (except SIGKILL), and says
 * whether it is gone. Best effort: nothing here may throw while xtask exits, and a later
 * run removes what is left once this process has ended.
 */
function removeOwnFolderAtExit(): boolean {
  const folders = readyFolders;
  if (folders === undefined) {
    return true;
  }
  try {
    if (removeRunFolder(folders)) {
      return true;
    }
    // A tool that was just stopped may still be ending; try once more after a moment.
    Atomics.wait(pause, 0, 0, 200);
    return removeRunFolder(folders);
  } catch {
    return false;
  }
}

/**
 * The environment for a tool. The first call makes the folders ready (this run's own
 * temporary folder) and prints the note about old files, if there is one.
 */
function environmentFor(root: string, tool: Tool): NodeJS.ProcessEnv {
  if (readyFolders === undefined) {
    const prepared = prepareRunFolders(root);
    readyFolders = prepared.folders;
    process.on("exit", removeOwnFolderAtExit);
    if (prepared.note !== undefined) {
      writeOutput(2, `${prepared.note}\n`);
    }
  }
  return toolEnvironment(childEnvironment(process.env, isatty(1)), readyFolders, {
    browser: tool === PLAYWRIGHT,
  });
}

/**
 * How long a tool may take to print its version. A tool that takes longer counts as
 * broken, like one that fails: "--version" reads none of the project's files.
 */
export const VERSION_PROBE_TIMEOUT_MS = 10_000;

/**
 * Starts a command and streams its output to sink. stdin is never read. Output is consumed
 * as it arrives, so large output cannot block. Outside Windows the command gets its own
 * process group, so that a signal can reach everything it started. With timeoutMs, the
 * command and everything it started are killed (SIGKILL) once that time has passed; the
 * result then has signal SIGKILL.
 */
function execCommand(
  root: string,
  colour: boolean,
  command: Command,
  sink: (stream: StreamId, text: string) => void,
  timeoutMs?: number,
): Promise<ExecResult> {
  if (stopping) {
    return new Promise<ExecResult>(() => {}); // xtask is exiting; start nothing new
  }
  let file: string;
  let args: string[];
  let env: NodeJS.ProcessEnv;
  if (command.kind === "pnpm") {
    // pnpm installs packages into its own store outside the project; it gets no cache folders.
    file = "pnpm";
    args = [...command.args];
    env = childEnvironment(process.env, isatty(1));
  } else {
    const script = toolScript(root, command.tool);
    if (script === undefined) {
      throw new CheckFailure(`xtask: ${command.tool.label} is not installed. ${SETUP_HINT}`);
    }
    // Biome colours its output even into a pipe and ignores NO_COLOR; it has its own switch.
    // The switch only changes presentation, so the displayed command leaves it out.
    const extra = command.tool === BIOME && !colour ? ["--colors=off"] : [];
    file = process.execPath;
    args = [script, ...command.args.slice(0, 1), ...extra, ...command.args.slice(1)];
    env = environmentFor(root, command.tool);
  }
  return new Promise<ExecResult>((resolve, reject) => {
    const child = spawn(file, args, {
      cwd: root,
      env,
      stdio: ["ignore", "pipe", "pipe"],
      // On Windows pnpm is a .cmd shim, which can only be started through a shell.
      shell: command.kind === "pnpm" && process.platform === "win32",
      detached: process.platform !== "win32",
    });
    running.add(child);
    const timer =
      timeoutMs === undefined ? undefined : setTimeout(() => killTree(child, "SIGKILL"), timeoutMs);
    let settled = false;
    const settle = (done: () => void): void => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        running.delete(child);
        done();
      }
    };
    const forward = (stream: StreamId) => (chunk: string) => {
      if (settled) {
        return;
      }
      try {
        sink(stream, chunk);
      } catch (error: unknown) {
        killTree(child, "SIGTERM");
        settle(() => reject(error));
      }
    };
    child.stdout?.setEncoding("utf8");
    child.stderr?.setEncoding("utf8");
    child.stdout?.on("data", forward(1));
    child.stderr?.on("data", forward(2));
    child.on("error", (error: NodeJS.ErrnoException) => {
      if (child.pid === undefined) {
        settle(() =>
          resolve({ code: null, signal: null, startError: error.code ?? error.message }),
        );
      }
    });
    child.on("close", (code, signal) => {
      settle(() => resolve({ code, signal, startError: undefined }));
    });
  });
}

function createProcessIo(root: string): RunnerIo {
  const colour = wantsColour(process.env, isatty(1));
  return {
    colour,
    write: writeOutput,
    exec: (command, sink) => execCommand(root, colour, command, sink),
    checkDist: async (distDir) => {
      // Loaded here, not at the top, so that a broken helper ends in one plain line.
      const distCheck: typeof import("./dist-check.ts") = await import("./dist-check.ts");
      return distCheck.checkDist(distDir);
    },
    canStart: async (tool) => {
      for (const each of [tool, ...(tool.needs ?? [])]) {
        if (toolScript(root, each) === undefined) {
          return false;
        }
        const command: Command = { kind: "tool", tool: each, args: ["--version"] };
        const result = await execCommand(root, colour, command, () => {}, VERSION_PROBE_TIMEOUT_MS);
        if (result.code !== 0 || crashReason(result) !== undefined) {
          return false;
        }
      }
      return true;
    },
  };
}

if (startedAsEntry) {
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"] as const) {
    process.on(signal, () => stopForSignal(signal));
  }
  // Every line is written synchronously, so xtask can exit at once. Exiting at once, rather
  // than letting Node wind down, keeps the signal handlers above in place until the very
  // end: a Ctrl-C after the last line can no longer end the process with Node's default.
  // While a signal is being handled, stopForSignal exits with its own code instead.
  main(process.argv.slice(2), createProcessIo(projectRoot())).then((code) => {
    if (!stopping) {
      process.exit(code);
    }
  }, onFatal);
}
