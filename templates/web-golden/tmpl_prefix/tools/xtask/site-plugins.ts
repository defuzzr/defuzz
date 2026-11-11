// The Vite plugins that turn src/pages into the site. vite.config.ts explains the rules
// for people editing the site; this file is the implementation. It imports only node:
// builtins and the types of Vite, and it reads nothing from disk when it is imported.
import {
  lstatSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmdirSync,
  rmSync,
  statSync,
} from "node:fs";
import path from "node:path";
import type { Plugin } from "vite";

/** Every .html file under pagesDir (each one is a page of the site), sorted. */
export function findPages(pagesDir: string): string[] {
  return readdirSync(pagesDir, { recursive: true, encoding: "utf8" })
    .filter((file) => file.endsWith(".html"))
    .sort()
    .map((file) => path.join(pagesDir, file));
}

function projectPath(projectDir: string, file: string): string {
  return path.relative(projectDir, file).split(path.sep).join("/");
}

/** True when file is inside dir (and is not dir itself). */
function isInside(dir: string, file: string): boolean {
  const rel = path.relative(dir, file);
  return rel !== "" && rel !== ".." && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel);
}

/**
 * An error meant for the person editing the site. Its stack is just the message, so the
 * dev server shows one plain line instead of a list of "at ..." lines, and Node (which
 * prints "vite build" errors with util.inspect) prints only the message.
 */
export class SiteError extends Error {
  constructor(message: string) {
    super(message);
    this.stack = message;
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return this.message;
  }
}

// ---------------------------------------------------------------------------------------
// A small reader for HTML. It finds comments and start tags with their exact positions,
// so changes can be made without touching any other byte.
// ---------------------------------------------------------------------------------------

interface Attribute {
  readonly name: string;
  /** The value as written, without quotes; "" for an attribute without a value. */
  readonly raw: string;
  /** Position of the raw value (for an attribute without a value: the end of its name). */
  readonly start: number;
  readonly end: number;
}

interface StartTag {
  readonly kind: "tag";
  readonly name: string;
  readonly attributes: readonly Attribute[];
  /** Position just after the last attribute (or after the tag name). */
  readonly afterAttributes: number;
}

interface Comment {
  readonly kind: "comment";
  /** The whole comment, from "<!--" to "-->". */
  readonly text: string;
  readonly start: number;
  readonly end: number;
}

/** Elements whose content is text, not markup: links in them are never changed. */
const RAW_TEXT_TAGS: ReadonlySet<string> = new Set(["script", "style", "textarea", "title"]);
/** Elements whose content is kept exactly as written: includes in them are not expanded. */
const VERBATIM_TAGS: ReadonlySet<string> = new Set([...RAW_TEXT_TAGS, "pre", "template"]);

function skipSpace(html: string, from: number): number {
  let p = from;
  while (p < html.length && /\s/.test(html.charAt(p))) {
    p++;
  }
  return p;
}

/** Comments and start tags in html, skipping the content of the elements in skipInside. */
function* tokens(html: string, skipInside: ReadonlySet<string>): Generator<StartTag | Comment> {
  const tagName = /<([A-Za-z][^\s/>]*)/y;
  const attrName = /[^\s"'>/=]+/y;
  const unquoted = /[^\s>]*/y;
  let i = 0;
  while (i < html.length) {
    const lt = html.indexOf("<", i);
    if (lt === -1) {
      return;
    }
    if (html.startsWith("<!--", lt)) {
      const close = html.indexOf("-->", lt + 4);
      if (close === -1) {
        return;
      }
      i = close + 3;
      yield { kind: "comment", text: html.slice(lt, i), start: lt, end: i };
      continue;
    }
    tagName.lastIndex = lt;
    const nameMatch = tagName.exec(html);
    if (nameMatch?.[1] === undefined) {
      i = lt + 1;
      continue;
    }
    const name = nameMatch[1].toLowerCase();
    const attributes: Attribute[] = [];
    let p = tagName.lastIndex;
    let afterAttributes = p;
    while (p < html.length) {
      while (p < html.length && /[\s/]/.test(html.charAt(p))) {
        p++;
      }
      if (p >= html.length || html.charAt(p) === ">") {
        break;
      }
      attrName.lastIndex = p;
      const attr = attrName.exec(html);
      if (attr === null) {
        p++;
        continue;
      }
      const attrKey = attr[0].toLowerCase();
      const nameEnd = attrName.lastIndex;
      let q = skipSpace(html, nameEnd);
      if (html.charAt(q) === "=") {
        q = skipSpace(html, q + 1);
        const quote = html.charAt(q);
        if (quote === '"' || quote === "'") {
          const close = html.indexOf(quote, q + 1);
          const end = close === -1 ? html.length : close;
          attributes.push({ name: attrKey, raw: html.slice(q + 1, end), start: q + 1, end });
          p = close === -1 ? html.length : close + 1;
        } else {
          unquoted.lastIndex = q;
          unquoted.exec(html);
          const end = unquoted.lastIndex;
          attributes.push({ name: attrKey, raw: html.slice(q, end), start: q, end });
          p = end;
        }
      } else {
        attributes.push({ name: attrKey, raw: "", start: nameEnd, end: nameEnd });
        p = nameEnd;
      }
      afterAttributes = p;
    }
    yield { kind: "tag", name, attributes, afterAttributes };
    i = p + 1;
    if (skipInside.has(name)) {
      const close = html.toLowerCase().indexOf(`</${name}`, i);
      i = close === -1 ? html.length : close;
    }
  }
}

const NAMED_ENTITIES: Readonly<Record<string, string>> = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
};

function decodeAttribute(raw: string): string {
  return raw.replace(/&(#x[0-9a-f]+|#[0-9]+|[a-z]+);/gi, (entity, code: string) => {
    if (code.startsWith("#")) {
      const hex = code[1] === "x" || code[1] === "X";
      const value = Number.parseInt(code.slice(hex ? 2 : 1), hex ? 16 : 10);
      return Number.isNaN(value) || value > 0x10ffff ? entity : String.fromCodePoint(value);
    }
    return NAMED_ENTITIES[code.toLowerCase()] ?? entity;
  });
}

interface Edit {
  readonly start: number;
  readonly end: number;
  readonly text: string;
}

function applyEdits(html: string, edits: readonly Edit[]): string {
  let result = html;
  for (const edit of [...edits].sort((a, b) => b.start - a.start)) {
    result = result.slice(0, edit.start) + edit.text + result.slice(edit.end);
  }
  return result;
}

// ---------------------------------------------------------------------------------------
// Partials: <!-- include: header.html current=/about/ -->
// ---------------------------------------------------------------------------------------

export interface IncludeComment {
  readonly name: string;
  readonly current?: string;
}

/** Reads a partial by its path inside src/components; undefined when it does not exist. */
export type ReadPartial = (name: string) => string | undefined;

const MAX_INCLUDE_DEPTH = 10;
const NOTE_HINT = "If this is only a note, start it with another word.";
const INCLUDE_EXAMPLE =
  "<!-- include: header.html --> or <!-- include: header.html current=/about/ -->";
const SHOWN_LENGTH = 80;

/** A comment as shown in a message: on one line and at most 80 characters long. */
function showComment(comment: string): string {
  const line = comment.replace(/\s+/g, " ");
  return line.length <= SHOWN_LENGTH ? line : `${line.slice(0, SHOWN_LENGTH - 3)}...`;
}

/** An error about an include comment; every such message ends with the note hint. */
function includeError(message: string): SiteError {
  return new SiteError(`${message} ${NOTE_HINT}`);
}

/**
 * Parses one HTML comment. Returns undefined when it is an ordinary comment: one that
 * does not start with "include:" (in any letter case) and does not look like an include
 * with a forgotten colon.
 */
export function parseIncludeComment(comment: string, where = "a page"): IncludeComment | undefined {
  const text = comment.replace(/^<!--/, "").replace(/-->$/, "").trim();
  const shown = showComment(comment);
  const head = /^(include)\s*:/i.exec(text);
  if (head === null) {
    if (/^include\s+[\w./-]+\.html\b/i.test(text)) {
      throw includeError(
        `${where} has the comment "${shown}", which looks like an include without the colon; write it as <!-- include: header.html -->.`,
      );
    }
    return undefined;
  }
  if (head[1] !== "include") {
    throw includeError(
      `${where} has the include "${shown}", but the word must be written in lowercase as "include:".`,
    );
  }
  const broken = () =>
    includeError(`${where} has the broken include "${shown}"; write it as ${INCLUDE_EXAMPLE}.`);
  const match = /^include:\s*(\S+)([\s\S]*)$/.exec(text);
  const name = match?.[1];
  if (match === null || name === undefined) {
    throw broken();
  }
  const setting = /^\s+([^\s=]+)=(?:"([^"]*)"|'([^']*)'|(\S*))(?=\s|$)/;
  let rest = (match[2] ?? "").trimEnd();
  let current: string | undefined;
  while (rest !== "") {
    const parts = setting.exec(rest);
    if (parts === null) {
      throw broken();
    }
    rest = rest.slice(parts[0].length);
    if (parts[1] !== "current") {
      throw includeError(
        `${where} has the include "${shown}" with the unknown setting "${parts[1]}"; the only setting is current, as in <!-- include: header.html current=/about/ -->.`,
      );
    }
    if (current !== undefined) {
      throw includeError(
        `${where} has the include "${shown}" with current given twice; give it once.`,
      );
    }
    const value = parts[2] ?? parts[3] ?? parts[4] ?? "";
    if (value === "") {
      throw includeError(
        `${where} has the include "${shown}" with an empty current=; give the address of the link to mark, as in current=/about/.`,
      );
    }
    if (/[\s"'<>]/.test(value)) {
      throw includeError(
        `${where} has the include "${shown}", but an address in current= cannot contain spaces, quotes, < or >.`,
      );
    }
    current = value;
  }
  return current === undefined ? { name } : { name, current };
}

/** Turns an include name into a clean path inside src/components, or undefined. */
function partialPath(name: string): string | undefined {
  if (name.includes("\\") || name.includes(":") || name.startsWith("/")) {
    return undefined;
  }
  const normal = path.posix.normalize(name);
  if (normal === ".." || normal.startsWith("../") || !normal.endsWith(".html")) {
    return undefined;
  }
  return normal;
}

/** The current= address of one include, and what was found for it in its partials. */
interface CurrentLink {
  readonly value: string;
  found: boolean;
  readonly hrefs: string[];
}

function markLinks(html: string, current: CurrentLink): string {
  const edits: Edit[] = [];
  for (const tag of tokens(html, RAW_TEXT_TAGS)) {
    if (tag.kind !== "tag" || tag.name !== "a") {
      continue;
    }
    const raw = tag.attributes.find((a) => a.name === "href")?.raw;
    if (raw === undefined) {
      continue;
    }
    const href = decodeAttribute(raw);
    if (!current.hrefs.includes(href)) {
      current.hrefs.push(href);
    }
    if (href !== current.value) {
      continue;
    }
    current.found = true;
    if (!tag.attributes.some((a) => a.name === "aria-current")) {
      edits.push({
        start: tag.afterAttributes,
        end: tag.afterAttributes,
        text: ' aria-current="page"',
      });
    }
  }
  return applyEdits(html, edits);
}

/** Adds aria-current="page" to every <a> tag whose href is exactly current. */
export function markCurrentLinks(html: string, current: string): string {
  return markLinks(html, { value: current, found: false, hrefs: [] });
}

/**
 * Replaces every include comment in a page with its partial. file is the page's path
 * from the project folder (used in messages); readPartial reads src/components files.
 */
export function expandIncludes(html: string, file: string, readPartial: ReadPartial): string {
  return expandIn(html, file, file, readPartial, 0, undefined);
}

function expandIn(
  html: string,
  file: string,
  page: string,
  readPartial: ReadPartial,
  depth: number,
  inherited: CurrentLink | undefined,
): string {
  const where = file === page ? file : `${file} (included by ${page})`;
  if (depth > MAX_INCLUDE_DEPTH) {
    throw includeError(
      `${where} nests partials more than ${MAX_INCLUDE_DEPTH} levels deep, probably because a partial includes itself; remove the loop.`,
    );
  }
  const edits: Edit[] = [];
  for (const token of tokens(html, VERBATIM_TAGS)) {
    if (token.kind !== "comment") {
      continue;
    }
    const include = parseIncludeComment(token.text, where);
    if (include === undefined) {
      continue;
    }
    const shown = showComment(token.text);
    checkCommentEnd(html, token, where);
    const name = partialPath(include.name);
    if (name === undefined) {
      throw includeError(
        `${where} has the include "${shown}", but an include must name an .html file inside src/components, for example <!-- include: header.html -->.`,
      );
    }
    let content: string | undefined;
    try {
      content = readPartial(name);
    } catch (error: unknown) {
      if (error instanceof SiteError) {
        throw includeError(`${where} includes "${include.name}", but ${error.message}`);
      }
      throw error;
    }
    if (content === undefined) {
      throw includeError(
        `${where} includes "${include.name}", but src/components/${name} does not exist; create that file or fix the name in "${shown}".`,
      );
    }
    const own: CurrentLink | undefined =
      include.current === undefined
        ? undefined
        : { value: include.current, found: false, hrefs: [] };
    const current = own ?? inherited;
    const marked = current === undefined ? content : markLinks(content, current);
    const text = expandIn(marked, `src/components/${name}`, page, readPartial, depth + 1, current);
    if (own !== undefined && !own.found) {
      const links =
        own.hrefs.length === 0
          ? `${include.name} has no links.`
          : `the links in ${include.name} are ${own.hrefs.map((href) => `"${href}"`).join(", ")}.`;
      throw includeError(
        `${where} has the include "${shown}", but no link in ${include.name} goes to "${own.value}"; ${links}`,
      );
    }
    edits.push({ start: token.start, end: token.end, text });
  }
  return applyEdits(html, edits);
}

/**
 * A comment ends at the first "-->", so <!-- include: x.html current=/a-->b/ --> would
 * end early and leave "b/ -->" in the page. Such a stray "-->" on the rest of the line
 * is reported instead.
 */
function checkCommentEnd(html: string, comment: Comment, where: string): void {
  const lineEnd = html.indexOf("\n", comment.end);
  const rest = html.slice(comment.end, lineEnd === -1 ? html.length : lineEnd);
  const close = rest.indexOf("-->");
  const open = rest.indexOf("<!--");
  if (close !== -1 && (open === -1 || close < open)) {
    const shown = showComment(comment.text + rest.slice(0, close + 3));
    throw includeError(
      `${where} has the include "${shown}", which ends early at the first "-->"; an address in current= cannot contain "-->".`,
    );
  }
}

/**
 * Reads partials from componentsDir. A partial must be a file whose real location (after
 * following links) is inside componentsDir, so nothing from elsewhere is published.
 */
export function partialReader(componentsDir: string): ReadPartial {
  return (name) => {
    let real: string;
    try {
      real = realpathSync(path.join(componentsDir, name));
    } catch {
      return undefined;
    }
    if (!isInside(realpathSync(componentsDir), real)) {
      throw new SiteError(
        `src/components/${name} is a link to a file outside src/components; put the file itself in src/components.`,
      );
    }
    if (!statSync(real).isFile()) {
      throw new SiteError(`src/components/${name} is a folder, not a file.`);
    }
    return readFileSync(real, "utf8");
  };
}

// ---------------------------------------------------------------------------------------
// Images and other files from src: <img src="/src/assets/photo.jpg" alt="">
// ---------------------------------------------------------------------------------------

const ASSET_ATTRIBUTES: Readonly<Record<string, readonly string[]>> = {
  img: ["src", "srcset"],
  source: ["src", "srcset"],
  video: ["src", "poster"],
  audio: ["src"],
  track: ["src"],
  use: ["href", "xlink:href"],
  image: ["href", "xlink:href"],
  link: ["href"],
};
const SRC_PREFIX = "/src/";

/** Rewrites /src/... asset addresses in a page; toUrl gets the part after "/src/". */
export function rewriteSrcUrls(html: string, toUrl: (rest: string) => string): string {
  const edits: Edit[] = [];
  for (const tag of tokens(html, RAW_TEXT_TAGS)) {
    const names = tag.kind === "tag" ? ASSET_ATTRIBUTES[tag.name] : undefined;
    if (tag.kind !== "tag" || names === undefined) {
      continue;
    }
    const rel = tag.attributes.find((a) => a.name === "rel")?.raw.toLowerCase() ?? "";
    if (tag.name === "link" && /\b(stylesheet|modulepreload)\b/.test(rel)) {
      continue;
    }
    for (const attr of tag.attributes) {
      if (!names.includes(attr.name)) {
        continue;
      }
      const rewritten =
        attr.name === "srcset"
          ? attr.raw.replace(
              /(^|,)(\s*)\/src\/([^\s,]*)/g,
              (_match, comma: string, space: string, rest: string) =>
                `${comma}${space}${toUrl(rest)}`,
            )
          : attr.raw.startsWith(SRC_PREFIX)
            ? toUrl(attr.raw.slice(SRC_PREFIX.length))
            : attr.raw;
      if (rewritten !== attr.raw) {
        edits.push({ start: attr.start, end: attr.end, text: rewritten });
      }
    }
  }
  return applyEdits(html, edits);
}

/** The address of src/<rest> relative to a page (pageFile is relative to the project). */
export function relativeSrcUrl(pageFile: string, rest: string): string {
  return `${path.posix.relative(path.posix.dirname(pageFile), "src")}/${rest}`;
}

/** Decodes %-escapes; an address with a broken one (URIError) is kept as written. */
function decodedOrAsWritten(text: string): string {
  try {
    return decodeURIComponent(text);
  } catch (error: unknown) {
    if (error instanceof URIError) {
      return text; // kept as written: no file has that name, so it is reported as missing
    }
    throw error;
  }
}

/**
 * Checks that the address "/src/<rest>" in page names a file that exists inside srcDir
 * (after following links). A ?query or #fragment is ignored.
 */
export function checkSrcUrl(srcDir: string, page: string, rest: string): void {
  const written = `${SRC_PREFIX}${rest}`;
  const decoded = decodedOrAsWritten(rest.split(/[?#]/)[0] ?? "");
  const outside = new SiteError(
    `${page} refers to "${written}", which is outside the src folder; only files inside src/ can be used with a /src/ address.`,
  );
  const missing = new SiteError(
    `${page} refers to "${written}", but that file does not exist in src/.`,
  );
  const file = path.resolve(srcDir, decoded);
  if (decoded.includes("\\") || !isInside(srcDir, file)) {
    throw outside;
  }
  let real: string;
  try {
    real = realpathSync(file);
  } catch {
    throw missing;
  }
  if (!isInside(realpathSync(srcDir), real)) {
    throw outside;
  }
  if (!statSync(real).isFile()) {
    throw missing;
  }
}

// ---------------------------------------------------------------------------------------
// The page plugin
// ---------------------------------------------------------------------------------------

interface SiteFolders {
  readonly projectDir: string;
  readonly srcDir: string;
  readonly pagesDir: string;
  readonly componentsDir: string;
}

function siteFolders(projectDir: string): SiteFolders {
  const srcDir = path.join(projectDir, "src");
  return {
    projectDir,
    srcDir,
    pagesDir: path.join(srcDir, "pages"),
    componentsDir: path.join(srcDir, "components"),
  };
}

/** The dev server address of src/<rest>: Vite serves allowed files under /@fs/. */
function devSrcUrl(srcDir: string, rest: string): string {
  return `/@fs/${srcDir.split(path.sep).join("/").replace(/^\//, "")}/${rest}`;
}

function transformPage(html: string, file: string, folders: SiteFolders, dev: boolean): string {
  const page = projectPath(folders.projectDir, file);
  const expanded = expandIncludes(html, page, partialReader(folders.componentsDir));
  return rewriteSrcUrls(expanded, (rest) => {
    checkSrcUrl(folders.srcDir, page, rest);
    return dev ? devSrcUrl(folders.srcDir, rest) : relativeSrcUrl(page, rest);
  });
}

function htmlIncludes(folders: SiteFolders): Plugin {
  return {
    name: "html-includes",
    // Check every page before the bundler starts: an error thrown here reaches the
    // terminal as one plain line, while inside the bundler it gets the bundler's trace.
    // (Vite runs this hook for "vite build"; its JavaScript build() function skips it.)
    buildApp: {
      order: "pre",
      handler: async () => {
        for (const file of findPages(folders.pagesDir)) {
          transformPage(readFileSync(file, "utf8"), file, folders, false);
        }
      },
    },
    transformIndexHtml: {
      order: "pre",
      handler: (html, ctx) => transformPage(html, ctx.filename, folders, ctx.server !== undefined),
    },
    configureServer(server) {
      // Partials are not modules, so reload the page when one of them changes.
      server.watcher.add(folders.componentsDir);
      server.watcher.on("change", (file) => {
        if (file.startsWith(folders.componentsDir) && file.endsWith(".html")) {
          server.ws.send({ type: "full-reload" });
        }
      });
    },
  };
}

// ---------------------------------------------------------------------------------------
// Folder notes: README.md (any letter case) and .gitkeep
// ---------------------------------------------------------------------------------------

/** True for README.md (any letter case) and .gitkeep, in any folder. */
export function isFolderNote(file: string): boolean {
  const base = file.split(/[\\/]/).pop() ?? "";
  return base.toLowerCase() === "readme.md" || base === ".gitkeep";
}

function urlIsFolderNote(url: string | undefined): boolean {
  const pathname = (url ?? "").split(/[?#]/)[0] ?? "";
  try {
    return isFolderNote(decodeURIComponent(pathname));
  } catch {
    return isFolderNote(pathname);
  }
}

function isDirectory(file: string): boolean {
  try {
    return lstatSync(file).isDirectory();
  } catch {
    return false;
  }
}

function isFile(file: string): boolean {
  try {
    return lstatSync(file).isFile();
  } catch {
    return false;
  }
}

/**
 * Vite copies all of publicDir into outDir. This deletes the copies of the folder notes
 * in publicDir from outDir, and then the folders that this made empty. Nothing else in
 * outDir is touched, so files that were there before the build stay.
 */
export function removeFolderNotes(publicDir: string, outDir: string): void {
  if (!isDirectory(publicDir)) {
    return;
  }
  const notes: string[] = [];
  const folders: string[] = [];
  for (const entry of readdirSync(publicDir, { recursive: true, withFileTypes: true })) {
    const rel = path.relative(publicDir, path.join(entry.parentPath, entry.name));
    if (entry.isDirectory()) {
      folders.push(rel);
    } else if (isFolderNote(entry.name)) {
      notes.push(rel);
    }
  }
  const emptied = new Set<string>();
  for (const rel of notes) {
    const target = path.join(outDir, rel);
    if (isFile(target)) {
      rmSync(target);
      emptied.add(path.dirname(rel));
    }
  }
  // Deepest folders first, so a parent can become empty in turn.
  folders.sort((a, b) => b.split(path.sep).length - a.split(path.sep).length);
  for (const rel of folders) {
    const target = path.join(outDir, rel);
    if (emptied.has(rel) && isDirectory(target) && readdirSync(target).length === 0) {
      rmdirSync(target);
      emptied.add(path.dirname(rel));
    }
  }
}

interface NoteRequest {
  readonly url?: string | undefined;
}

interface NoteResponse {
  statusCode: number;
  end(): unknown;
}

/** Dev and preview server middleware: answers 404 for folder notes. */
export function folderNoteGuard(req: NoteRequest, res: NoteResponse, next: () => void): void {
  if (urlIsFolderNote(req.url)) {
    res.statusCode = 404;
    res.end();
    return;
  }
  next();
}

function hideFolderNotes(): Plugin {
  let publicDir = "";
  return {
    name: "hide-folder-notes",
    configResolved(config) {
      publicDir = config.publicDir;
    },
    writeBundle(options) {
      // options.dir is the resolved output folder (dist/).
      if (options.dir !== undefined && publicDir !== "") {
        removeFolderNotes(publicDir, options.dir);
      }
    },
    configureServer(server) {
      server.middlewares.use(folderNoteGuard);
    },
    configurePreviewServer(server) {
      server.middlewares.use(folderNoteGuard);
    },
  };
}

// ---------------------------------------------------------------------------------------
// Used by vite.config.ts
// ---------------------------------------------------------------------------------------

/** The plugins of the site, for the project in projectDir. */
export function sitePlugins(projectDir: string): Plugin[] {
  return [htmlIncludes(siteFolders(projectDir)), hideFolderNotes()];
}

/** Output names: all CSS as assets/site-<hash>.css, other files keep their name. */
export function assetFileNames(asset: { readonly names: readonly string[] }): string {
  return asset.names.some((name) => name.endsWith(".css"))
    ? "assets/site-[hash][extname]"
    : "assets/[name]-[hash][extname]";
}
