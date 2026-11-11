// Build output check: reads the built site in dist/ and reports broken internal
// links, missing local files and remote resources that would load at runtime.
// Everything here is a pure function of the file list, except readSite and checkDist,
// which read a folder from disk. Only node: builtins are used.
// JavaScript is checked for string-literal URLs only: a URL assembled at runtime
// (for example "https://" + host) cannot be found by this static check.
// URL schemes are matched case-insensitively everywhere (HTTPS://, Http://, WSS://).
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

/** Site files keyed by POSIX path relative to dist/. Text for .html/.css/.js, else null. */
export type SiteFiles = ReadonlyMap<string, string | null>;

export type UrlKind = "remote" | "local" | "fragment" | "ignore" | "other";

export interface HtmlTag {
  readonly name: string;
  readonly attrs: ReadonlyMap<string, string>;
}

export interface HtmlScript {
  readonly attrs: ReadonlyMap<string, string>;
  readonly content: string;
}

export interface ParsedHtml {
  readonly tags: readonly HtmlTag[];
  readonly styles: readonly string[];
  readonly scripts: readonly HtmlScript[];
  readonly ids: ReadonlySet<string>;
}

const TEXT_EXTENSIONS = new Set([".html", ".css", ".js", ".mjs"]);
const HARMLESS_SCHEMES = new Set(["data", "blob", "mailto", "tel", "sms", "javascript", "about"]);
const REMOTE_SCHEMES = new Set(["http", "https", "ws", "wss"]);
// <link rel> values that never make the browser fetch the href.
const NON_FETCHING_RELS = new Set([
  "alternate",
  "author",
  "bookmark",
  "canonical",
  "external",
  "help",
  "license",
  "me",
  "next",
  "nofollow",
  "noopener",
  "noreferrer",
  "opener",
  "prev",
  "privacy-policy",
  "tag",
  "terms-of-service",
]);
// Elements whose content is raw text, not markup.
const RAW_TEXT_ELEMENTS = new Set(["script", "style", "textarea", "title"]);
const NON_SCRIPT_TYPES = new Set(["application/ld+json", "application/json", "importmap"]);

export function classifyUrl(raw: string): UrlKind {
  const url = raw.trim();
  if (url === "") {
    return "ignore";
  }
  if (url.startsWith("#")) {
    return "fragment";
  }
  if (url.startsWith("//")) {
    return "remote";
  }
  const scheme = /^([a-z][a-z0-9+.-]*):/i.exec(url)?.[1]?.toLowerCase();
  if (scheme === undefined) {
    return "local";
  }
  if (REMOTE_SCHEMES.has(scheme)) {
    return "remote";
  }
  if (HARMLESS_SCHEMES.has(scheme)) {
    return "ignore";
  }
  return "other";
}

function decodeEntities(value: string): string {
  return value.replace(/&(#x[0-9a-f]+|#[0-9]+|amp|quot|apos|lt|gt);/gi, (match, code: string) => {
    const lower = code.toLowerCase();
    if (lower.startsWith("#x")) {
      return String.fromCodePoint(Number.parseInt(lower.slice(2), 16));
    }
    if (lower.startsWith("#")) {
      return String.fromCodePoint(Number.parseInt(lower.slice(1), 10));
    }
    const named: Record<string, string> = { amp: "&", quot: '"', apos: "'", lt: "<", gt: ">" };
    return named[lower] ?? match;
  });
}

function isSpace(ch: string): boolean {
  return ch === " " || ch === "\t" || ch === "\n" || ch === "\r" || ch === "\f";
}

/** A small, forgiving HTML scanner: enough to find tags, attributes, ids and raw text. */
export function parseHtml(html: string): ParsedHtml {
  const tags: HtmlTag[] = [];
  const styles: string[] = [];
  const scripts: HtmlScript[] = [];
  const ids = new Set<string>();
  const lower = html.toLowerCase();
  let i = 0;

  while (i < html.length) {
    const lt = html.indexOf("<", i);
    if (lt === -1) {
      break;
    }
    if (html.startsWith("<!--", lt)) {
      const end = html.indexOf("-->", lt + 4);
      i = end === -1 ? html.length : end + 3;
      continue;
    }
    const next = html[lt + 1] ?? "";
    if (next === "!" || next === "?" || next === "/") {
      const end = html.indexOf(">", lt + 1);
      i = end === -1 ? html.length : end + 1;
      continue;
    }
    if (!/[a-z]/i.test(next)) {
      i = lt + 1;
      continue;
    }

    let j = lt + 1;
    while (j < html.length && !isSpace(html[j] ?? "") && html[j] !== ">" && html[j] !== "/") {
      j += 1;
    }
    const name = html.slice(lt + 1, j).toLowerCase();
    const attrs = new Map<string, string>();

    while (j < html.length) {
      while (j < html.length && (isSpace(html[j] ?? "") || html[j] === "/")) {
        j += 1;
      }
      if (j >= html.length || html[j] === ">") {
        break;
      }
      const nameStart = j;
      while (j < html.length && !isSpace(html[j] ?? "") && !"=>/".includes(html[j] ?? "")) {
        j += 1;
      }
      const attrName = html.slice(nameStart, j).toLowerCase();
      while (j < html.length && isSpace(html[j] ?? "")) {
        j += 1;
      }
      let value = "";
      if (html[j] === "=") {
        j += 1;
        while (j < html.length && isSpace(html[j] ?? "")) {
          j += 1;
        }
        const quote = html[j];
        if (quote === '"' || quote === "'") {
          const end = html.indexOf(quote, j + 1);
          const stop = end === -1 ? html.length : end;
          value = html.slice(j + 1, stop);
          j = stop + 1;
        } else {
          const start = j;
          while (j < html.length && !isSpace(html[j] ?? "") && html[j] !== ">") {
            j += 1;
          }
          value = html.slice(start, j);
        }
      }
      if (attrName !== "" && !attrs.has(attrName)) {
        attrs.set(attrName, decodeEntities(value));
      }
    }
    i = j + 1;

    const tag: HtmlTag = { name, attrs };
    tags.push(tag);
    const id = attrs.get("id");
    if (id !== undefined && id !== "") {
      ids.add(id);
    }
    const anchorName = attrs.get("name");
    if (name === "a" && anchorName !== undefined && anchorName !== "") {
      ids.add(anchorName);
    }

    if (RAW_TEXT_ELEMENTS.has(name)) {
      const close = lower.indexOf(`</${name}`, i);
      const end = close === -1 ? html.length : close;
      const content = html.slice(i, end);
      if (name === "style") {
        styles.push(content);
      } else if (name === "script") {
        scripts.push({ attrs, content });
      }
      const closeEnd = close === -1 ? -1 : html.indexOf(">", close);
      i = closeEnd === -1 ? html.length : closeEnd + 1;
    }
  }

  return { tags, styles, scripts, ids };
}

interface Reference {
  /** How the problem report names the reference, for example a[href]. */
  readonly where: string;
  readonly url: string;
  /** "load": fetched automatically by the browser. "navigate": only followed on click. */
  readonly mode: "load" | "navigate";
}

// Follows the HTML srcset parsing rules: a URL runs until whitespace, and a URL that
// ends in commas has no descriptors. Descriptors run until the next comma.
function srcsetUrls(srcset: string): string[] {
  const urls: string[] = [];
  let i = 0;
  while (i < srcset.length) {
    while (i < srcset.length && (isSpace(srcset[i] ?? "") || srcset[i] === ",")) {
      i += 1;
    }
    const start = i;
    while (i < srcset.length && !isSpace(srcset[i] ?? "")) {
      i += 1;
    }
    let url = srcset.slice(start, i);
    if (url.endsWith(",")) {
      url = url.replace(/,+$/, "");
    } else {
      while (i < srcset.length && srcset[i] !== ",") {
        i += 1;
      }
    }
    if (url !== "") {
      urls.push(url);
    }
  }
  return urls;
}

function tagReferences(tag: HtmlTag): Reference[] {
  const refs: Reference[] = [];
  const add = (attr: string, mode: "load" | "navigate"): void => {
    const url = tag.attrs.get(attr);
    if (url !== undefined) {
      refs.push({ where: `${tag.name}[${attr}]`, url, mode });
    }
  };

  switch (tag.name) {
    case "a":
    case "area":
      add("href", "navigate");
      break;
    case "link": {
      const rels = (tag.attrs.get("rel") ?? "").toLowerCase().split(/\s+/).filter(Boolean);
      const fetches = rels.some((rel) => !NON_FETCHING_RELS.has(rel));
      add("href", fetches ? "load" : "navigate");
      break;
    }
    case "script":
    case "iframe":
    case "frame":
    case "embed":
    case "track":
    case "input":
      add("src", "load");
      break;
    case "img":
    case "source":
      add("src", "load");
      for (const url of srcsetUrls(tag.attrs.get("srcset") ?? "")) {
        refs.push({ where: `${tag.name}[srcset]`, url, mode: "load" });
      }
      break;
    case "video":
      add("src", "load");
      add("poster", "load");
      break;
    case "audio":
      add("src", "load");
      break;
    case "object":
      add("data", "load");
      break;
    case "use":
    case "image":
    case "feimage":
      add("href", "load");
      add("xlink:href", "load");
      break;
    case "meta": {
      if ((tag.attrs.get("http-equiv") ?? "").toLowerCase() === "refresh") {
        const target = /url\s*=\s*['"]?([^'"]*)/i.exec(tag.attrs.get("content") ?? "")?.[1];
        if (target !== undefined) {
          refs.push({ where: "meta[http-equiv=refresh]", url: target.trim(), mode: "navigate" });
        }
      }
      break;
    }
    default:
      break;
  }
  return refs;
}

type Resolved =
  | { readonly ok: true; readonly target: string; readonly fragment: string }
  | { readonly ok: false; readonly reason: string };

function resolveLocal(fromFile: string, url: string, files: SiteFiles): Resolved {
  const hashAt = url.indexOf("#");
  const fragment = hashAt === -1 ? "" : url.slice(hashAt + 1);
  const withoutFragment = hashAt === -1 ? url : url.slice(0, hashAt);
  const queryAt = withoutFragment.indexOf("?");
  const rawPath = queryAt === -1 ? withoutFragment : withoutFragment.slice(0, queryAt);

  let decoded: string;
  try {
    decoded = decodeURIComponent(rawPath);
  } catch {
    return { ok: false, reason: "is not a valid URL" };
  }
  if (decoded === "") {
    return { ok: true, target: fromFile, fragment };
  }

  const joined = decoded.startsWith("/")
    ? path.posix.normalize(`.${decoded}`)
    : path.posix.join(path.posix.dirname(fromFile), decoded);
  if (joined === ".." || joined.startsWith("../")) {
    return { ok: false, reason: "points outside the site folder" };
  }
  const base = joined.replace(/\/+$/, "").replace(/^\.(\/|$)/, "");
  const isDir = decoded.endsWith("/") || base === "";
  const candidates = isDir
    ? [`${base}${base === "" ? "" : "/"}index.html`]
    : [base, `${base}/index.html`];
  for (const candidate of candidates) {
    if (files.has(candidate)) {
      return { ok: true, target: candidate, fragment };
    }
  }
  return { ok: false, reason: `points to a file that does not exist (dist/${candidates[0]})` };
}

function decodeFragment(fragment: string): string {
  try {
    return decodeURIComponent(fragment);
  } catch {
    return fragment;
  }
}

/** Quoted-string candidates of image-set() and -webkit-image-set(); url() ones are found elsewhere. */
function imageSetStrings(css: string): string[] {
  const urls: string[] = [];
  for (const match of css.matchAll(/(?:-webkit-)?image-set\(/gi)) {
    let depth = 1;
    let i = (match.index ?? 0) + match[0].length;
    while (i < css.length && depth > 0) {
      const ch = css[i] ?? "";
      if (ch === '"' || ch === "'") {
        const end = css.indexOf(ch, i + 1);
        const stop = end === -1 ? css.length : end;
        if (depth === 1) {
          urls.push(css.slice(i + 1, stop));
        }
        i = stop + 1;
        continue;
      }
      if (ch === "(") {
        depth += 1;
      } else if (ch === ")") {
        depth -= 1;
      }
      i += 1;
    }
  }
  return urls;
}

/** Checks url() and @import in one stylesheet. `file` is used for messages and for resolving. */
export function checkCss(file: string, css: string, files: SiteFiles): string[] {
  const problems: string[] = [];
  const text = css.replace(/\/\*[\s\S]*?\*\//g, "");
  const found: Array<{ readonly where: string; readonly url: string }> = [];

  for (const match of text.matchAll(/@import\s+(["'])([^"']*)\1/gi)) {
    found.push({ where: "@import", url: match[2] ?? "" });
  }
  for (const url of imageSetStrings(text)) {
    found.push({ where: "image-set()", url });
  }
  for (const match of text.matchAll(/url\(\s*(?:"([^"]*)"|'([^']*)'|([^)\s]*))\s*\)/gi)) {
    found.push({ where: "url()", url: match[1] ?? match[2] ?? match[3] ?? "" });
  }

  for (const { where, url } of found) {
    const kind = classifyUrl(url);
    if (kind === "remote" || kind === "other") {
      problems.push(
        `dist/${file}: CSS ${where} "${url}" loads a remote resource at runtime; save the file in this project instead`,
      );
    } else if (kind === "local") {
      const resolved = resolveLocal(file, url, files);
      if (!resolved.ok) {
        problems.push(`dist/${file}: CSS ${where} "${url}" ${resolved.reason}`);
      }
    }
  }
  return problems;
}

const REMOTE_LITERAL = String.raw`(["'\x60])((?:(?:[hH][tT][tT][pP][sS]?|[wW][sS][sS]?):)?\/\/[^"'\x60\s]*)`;
const JS_REMOTE_PATTERNS: readonly RegExp[] = [
  new RegExp(
    String.raw`\b(fetch|import|importScripts|sendBeacon|Worker|SharedWorker|EventSource|WebSocket)\s*\(\s*${REMOTE_LITERAL}`,
    "g",
  ),
  new RegExp(String.raw`\.(open)\s*\(\s*["'\x60][A-Za-z]+["'\x60]\s*,\s*${REMOTE_LITERAL}`, "g"),
  new RegExp(String.raw`\b(import|export)\b[^;"'\x60]*?\bfrom\s*${REMOTE_LITERAL}`, "g"),
  new RegExp(String.raw`\b(import)\s*${REMOTE_LITERAL}`, "g"),
];

/** Finds remote URLs that JavaScript loads at runtime, when they are written as string literals. */
export function checkJs(file: string, js: string): string[] {
  const hits: Array<{ readonly index: number; readonly message: string }> = [];
  const seen = new Set<number>();
  for (const pattern of JS_REMOTE_PATTERNS) {
    for (const match of js.matchAll(pattern)) {
      const index = match.index ?? 0;
      const urlIndex = index + match[0].length - (match[3]?.length ?? 0);
      if (seen.has(urlIndex)) {
        continue;
      }
      seen.add(urlIndex);
      hits.push({
        index,
        message: `dist/${file}: ${match[1] ?? "code"}(...) loads the remote URL "${match[3] ?? ""}" at runtime; serve it from this site instead`,
      });
    }
  }
  return hits.sort((a, b) => a.index - b.index).map((hit) => hit.message);
}

function checkHtml(
  file: string,
  parsed: ParsedHtml,
  files: SiteFiles,
  idsOf: (file: string) => ReadonlySet<string>,
): string[] {
  const problems: string[] = [];

  for (const tag of parsed.tags) {
    for (const ref of tagReferences(tag)) {
      const kind = classifyUrl(ref.url);
      const shown = `${ref.where} "${ref.url}"`;
      if (kind === "remote" || kind === "other") {
        if (ref.mode === "load") {
          problems.push(
            `dist/${file}: ${shown} loads a remote resource at runtime; save the file in this project instead`,
          );
        }
        continue;
      }
      if (kind === "ignore") {
        continue;
      }
      const resolved =
        kind === "fragment"
          ? ({ ok: true, target: file, fragment: ref.url.slice(1) } as const)
          : resolveLocal(file, ref.url, files);
      if (!resolved.ok) {
        problems.push(`dist/${file}: ${shown} ${resolved.reason}`);
        continue;
      }
      const fragment = decodeFragment(resolved.fragment);
      if (fragment !== "" && fragment !== "top" && resolved.target.endsWith(".html")) {
        if (!idsOf(resolved.target).has(fragment)) {
          problems.push(
            `dist/${file}: ${shown} points to id "${fragment}", which does not exist in dist/${resolved.target}`,
          );
        }
      }
    }

    const style = tag.attrs.get("style");
    if (style !== undefined) {
      problems.push(...checkCss(file, style, files));
    }
  }

  for (const css of parsed.styles) {
    problems.push(...checkCss(file, css, files));
  }
  for (const script of parsed.scripts) {
    const type = (script.attrs.get("type") ?? "").toLowerCase();
    if (!script.attrs.has("src") && !NON_SCRIPT_TYPES.has(type)) {
      problems.push(...checkJs(file, script.content));
    }
  }
  return problems;
}

/** Checks a whole site. Returns one line per problem, in a stable order. */
export function checkSite(files: SiteFiles): string[] {
  const problems: string[] = [];
  const parsedCache = new Map<string, ParsedHtml>();
  const parsedOf = (file: string): ParsedHtml => {
    let parsed = parsedCache.get(file);
    if (parsed === undefined) {
      parsed = parseHtml(files.get(file) ?? "");
      parsedCache.set(file, parsed);
    }
    return parsed;
  };

  if (!files.has("index.html")) {
    problems.push("dist/index.html: the home page is missing from the build");
  }

  for (const file of [...files.keys()].sort()) {
    const text = files.get(file);
    if (text === null || text === undefined) {
      continue;
    }
    if (file.endsWith(".html")) {
      problems.push(...checkHtml(file, parsedOf(file), files, (target) => parsedOf(target).ids));
    } else if (file.endsWith(".css")) {
      problems.push(...checkCss(file, text, files));
    } else if (file.endsWith(".js") || file.endsWith(".mjs")) {
      problems.push(...checkJs(file, text));
    }
  }
  return problems;
}

/**
 * A file that was listed in dist/ but was gone when it was read: another build is usually
 * emptying dist/ at the same moment (or the file is a link to nothing).
 */
class VanishedFile extends Error {
  constructor(entry: string) {
    super(
      `dist/${entry}: this file disappeared while dist/ was being checked; another build or check may be running in this project (or it is a link to a missing file). When nothing else is running, run the command again.`,
    );
  }
}

/** Runs read; a "no such file" (ENOENT) becomes VanishedFile, any other error stays as it is. */
function readListed<T>(entry: string, read: () => T): T {
  try {
    return read();
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException | undefined)?.code === "ENOENT") {
      throw new VanishedFile(entry);
    }
    throw error;
  }
}

/** Reads every file under a folder. Text is kept only for files the checker reads. */
export function readSite(dir: string): Map<string, string | null> {
  const files = new Map<string, string | null>();
  const listed = readListed("", () => readdirSync(dir, { recursive: true, encoding: "utf8" }));
  for (const entry of listed.sort()) {
    const full = path.join(dir, entry);
    const key = entry.split(path.sep).join("/");
    if (!readListed(key, () => statSync(full)).isFile()) {
      continue;
    }
    const text = TEXT_EXTENSIONS.has(path.extname(entry).toLowerCase())
      ? readListed(key, () => readFileSync(full, "utf8"))
      : null;
    files.set(key, text);
  }
  return files;
}

/** Checks the built site folder on disk. */
export function checkDist(dir: string): string[] {
  if (!existsSync(dir) || !statSync(dir).isDirectory()) {
    return ["dist: the build output folder was not found; build the site first"];
  }
  let files: Map<string, string | null>;
  try {
    files = readSite(dir);
  } catch (error: unknown) {
    if (error instanceof VanishedFile) {
      return [error.message];
    }
    throw error;
  }
  return checkSite(files);
}
