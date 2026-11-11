import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createBuilder, createServer, type Plugin, resolveConfig } from "vite";
import { afterAll, describe, expect, it } from "vitest";
import {
  checkSrcUrl,
  expandIncludes,
  folderNoteGuard,
  partialReader,
  removeFolderNotes,
  SiteError,
} from "../../tools/xtask/site-plugins.ts";

// Everything these tests write goes into node_modules/.cache inside the project and is
// removed again at the end.
const projectDir = fileURLToPath(new URL("../../", import.meta.url));
const cacheDir = path.join(projectDir, "node_modules", ".cache");
mkdirSync(cacheDir, { recursive: true });
const tempDir = mkdtempSync(path.join(cacheDir, "site-plugins-test-"));
afterAll(() => rmSync(tempDir, { recursive: true, force: true }));

function write(file: string, text: string): void {
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, text);
}

/** Runs fn and returns the SiteError message it throws. */
function siteErrorOf(fn: () => unknown): string {
  try {
    fn();
  } catch (error: unknown) {
    expect(error).toBeInstanceOf(SiteError);
    expect((error as Error).stack ?? "").not.toMatch(/^\s*at /m);
    return (error as Error).message;
  }
  throw new Error("expected an error");
}

/** Makes a symbolic link, or returns false when this system does not allow it. */
function trySymlink(target: string, link: string): boolean {
  try {
    symlinkSync(target, link);
    return true;
  } catch {
    return false;
  }
}

const NO_SYMLINKS =
  "symbolic links cannot be created on this system (for example Windows without developer mode)";

describe("partialReader", () => {
  const base = path.join(tempDir, "reader");
  const components = path.join(base, "src", "components");
  write(path.join(components, "ok.html"), "<p>ok</p>");
  write(path.join(base, "outside.html"), "SECRET-OUTSIDE");
  mkdirSync(path.join(components, "folder.html"), { recursive: true });
  const read = partialReader(components);

  it("reads partials and answers undefined for missing ones", () => {
    expect(read("ok.html")).toBe("<p>ok</p>");
    expect(read("missing.html")).toBeUndefined();
  });

  it("refuses a folder", () => {
    expect(siteErrorOf(() => read("folder.html"))).toBe(
      "src/components/folder.html is a folder, not a file.",
    );
  });

  it("refuses a link to a file outside src/components but allows one inside", (ctx) => {
    const madeOutside = trySymlink(
      path.join(base, "outside.html"),
      path.join(components, "evil.html"),
    );
    const madeInside = trySymlink("ok.html", path.join(components, "inner.html"));
    ctx.skip(!(madeOutside && madeInside), NO_SYMLINKS);
    expect(read("inner.html")).toBe("<p>ok</p>");
    expect(siteErrorOf(() => read("evil.html"))).toBe(
      "src/components/evil.html is a link to a file outside src/components; put the file itself in src/components.",
    );
    const message = siteErrorOf(() =>
      expandIncludes("<!-- include: evil.html -->", "src/pages/index.html", read),
    );
    expect(message).toBe(
      'src/pages/index.html includes "evil.html", but src/components/evil.html is a link to a file outside src/components; put the file itself in src/components. If this is only a note, start it with another word.',
    );
    expect(message).not.toContain("SECRET");
  });
});

describe("checkSrcUrl", () => {
  const src = path.join(tempDir, "check", "src");
  write(path.join(src, "assets", "a b.png"), "png");
  write(path.join(src, "assets", "icons.svg"), "<svg></svg>");
  write(path.join(tempDir, "check", "package.json"), "{}");
  const page = "src/pages/index.html";

  it("accepts files that exist in src, with a query, a fragment or %-escapes", () => {
    expect(() => checkSrcUrl(src, page, "assets/icons.svg#home")).not.toThrow();
    expect(() => checkSrcUrl(src, page, "assets/icons.svg?v=1")).not.toThrow();
    expect(() => checkSrcUrl(src, page, "assets/a%20b.png")).not.toThrow();
  });

  it("names the address as written when the file does not exist", () => {
    expect(siteErrorOf(() => checkSrcUrl(src, page, "assets/nope.png"))).toBe(
      'src/pages/index.html refers to "/src/assets/nope.png", but that file does not exist in src/.',
    );
    expect(siteErrorOf(() => checkSrcUrl(src, page, "assets"))).toBe(
      'src/pages/index.html refers to "/src/assets", but that file does not exist in src/.',
    );
  });

  it("keeps an address with a broken %-escape as written, so it is simply not found", () => {
    for (const rest of ["assets/a%E0b.png", "assets/%", "assets/a%2"]) {
      expect(siteErrorOf(() => checkSrcUrl(src, page, rest))).toBe(
        `src/pages/index.html refers to "/src/${rest}", but that file does not exist in src/.`,
      );
    }
  });

  it("refuses addresses that leave the src folder", () => {
    for (const rest of ["../package.json", "assets/../../package.json", "%2e%2e/package.json"]) {
      expect(siteErrorOf(() => checkSrcUrl(src, page, rest))).toBe(
        `src/pages/index.html refers to "/src/${rest}", which is outside the src folder; only files inside src/ can be used with a /src/ address.`,
      );
    }
  });

  it("refuses a link inside src that points outside it", (ctx) => {
    const made = trySymlink(
      path.join(tempDir, "check", "package.json"),
      path.join(src, "assets", "link.json"),
    );
    ctx.skip(!made, NO_SYMLINKS);
    expect(siteErrorOf(() => checkSrcUrl(src, page, "assets/link.json"))).toContain(
      "outside the src folder",
    );
  });
});

describe("removeFolderNotes", () => {
  it("deletes only the folder notes that public/ has, and folders it emptied", () => {
    const publicDir = path.join(tempDir, "notes", "public");
    const outDir = path.join(tempDir, "notes", "out");
    for (const file of [
      "README.md",
      "robots.txt",
      "fonts/.gitkeep",
      "fonts/README.md",
      "fonts/font.woff2",
      "onlynotes/sub/.gitkeep",
      "onlynotes/README.md",
    ]) {
      write(path.join(publicDir, file), "x");
      write(path.join(outDir, file), "x");
    }
    mkdirSync(path.join(publicDir, "emptyinpublic"));
    mkdirSync(path.join(outDir, "emptyinpublic"));
    // Things the build did not make: they must survive.
    mkdirSync(path.join(outDir, "pre-empty"));
    write(path.join(outDir, "prenote", "README.md"), "user");
    write(path.join(outDir, "fonts", "readme.MD"), "user");

    removeFolderNotes(publicDir, outDir);

    const left = readdirSync(outDir, { recursive: true, encoding: "utf8" })
      .map((file) => file.split(path.sep).join("/"))
      .sort();
    expect(left).toEqual([
      "emptyinpublic",
      "fonts",
      "fonts/font.woff2",
      "fonts/readme.MD",
      "pre-empty",
      "prenote",
      "prenote/README.md",
      "robots.txt",
    ]);
    // public/ itself is never changed.
    expect(existsSync(path.join(publicDir, "README.md"))).toBe(true);
  });

  it("does nothing when public/ does not exist", () => {
    const outDir = path.join(tempDir, "notes-none", "out");
    write(path.join(outDir, "README.md"), "x");
    removeFolderNotes(path.join(tempDir, "notes-none", "public"), outDir);
    expect(existsSync(path.join(outDir, "README.md"))).toBe(true);
  });
});

interface FakeResponse {
  statusCode: number;
  ended: boolean;
  end(): void;
}

function fakeResponse(): FakeResponse {
  return {
    statusCode: 200,
    ended: false,
    end() {
      this.ended = true;
    },
  };
}

type Middleware = (req: { url?: string }, res: FakeResponse, next: () => void) => void;

/** Sends url through a middleware; returns 404 when it answered, "next" when it passed. */
function answer(middleware: Middleware, url: string): number | "next" {
  const res = fakeResponse();
  let passed = false;
  middleware({ url }, res, () => {
    passed = true;
  });
  return passed ? "next" : res.statusCode;
}

describe("folderNoteGuard", () => {
  it("answers 404 for folder notes in any spelling and passes everything else on", () => {
    for (const url of [
      "/README.md",
      "/fonts/readme.MD",
      "/fonts/.gitkeep",
      "/README.md?x=1",
      "/README.md#a",
      "/README%2Emd",
      "/%52EADME.md",
      "/fonts/%2egitkeep",
    ]) {
      expect(answer(folderNoteGuard, url)).toBe(404);
    }
    for (const url of ["/", "/about/", "/robots.txt", "/favicon.svg", "/README.md.txt", "/%E0"]) {
      expect(answer(folderNoteGuard, url)).toBe("next");
    }
  });
});

// ---------------------------------------------------------------------------------------
// The real configuration, run through Vite's JavaScript API on a small copy of the
// project in node_modules/.cache.
// ---------------------------------------------------------------------------------------

const fixture = path.join(tempDir, "site");
const fixtureSrc = path.join(fixture, "src");

function makeFixture(): void {
  mkdirSync(path.join(fixture, "tools", "xtask"), { recursive: true });
  copyFileSync(path.join(projectDir, "vite.config.ts"), path.join(fixture, "vite.config.ts"));
  copyFileSync(
    path.join(projectDir, "tools", "xtask", "site-plugins.ts"),
    path.join(fixture, "tools", "xtask", "site-plugins.ts"),
  );
  const page = (title: string) =>
    [
      "<!doctype html>",
      `<html lang="en"><head><title>${title}</title>`,
      '<link rel="stylesheet" href="/src/styles/main.css" />',
      "</head><body>",
      `<!-- include: header.html current=${title === "home" ? "/" : "/about/"} -->`,
      '<img src="/src/assets/pic.svg" alt="" />',
      '<script type="module" src="/src/components/hello.ts"></script>',
      "</body></html>",
      "",
    ].join("\n");
  write(path.join(fixtureSrc, "pages", "index.html"), page("home"));
  write(path.join(fixtureSrc, "pages", "about", "index.html"), page("about"));
  write(
    path.join(fixtureSrc, "components", "header.html"),
    '<header><a href="/">Home</a> <a href="/about/">About</a></header>',
  );
  write(path.join(fixtureSrc, "components", "hello.ts"), 'document.title += "!";\n');
  write(path.join(fixtureSrc, "styles", "main.css"), "body { color: #222; }\n");
  // Larger than Vite's inline limit, so it is emitted as a file.
  write(
    path.join(fixtureSrc, "assets", "pic.svg"),
    `<svg xmlns="http://www.w3.org/2000/svg"><!-- ${"x".repeat(5000)} --></svg>\n`,
  );
  for (const file of ["README.md", "fonts/README.md", "fonts/.gitkeep"]) {
    write(path.join(fixture, "public", file), "note");
  }
  write(path.join(fixture, "public", "robots.txt"), "User-agent: *\n");
  write(path.join(fixture, "public", "fonts", "font.woff2"), "font");
}

makeFixture();

const configFile = path.join(fixture, "vite.config.ts");
const quiet = { configFile, logLevel: "silent", cacheDir: path.join(fixture, ".vite") } as const;

/** Builds the fixture the way "vite build" does and returns the output folder. */
async function buildFixture(name: string): Promise<string> {
  const outDir = path.join(tempDir, name);
  const builder = await createBuilder({ ...quiet, build: { outDir, emptyOutDir: true } });
  await builder.buildApp();
  return outDir;
}

async function buildError(name: string): Promise<Error> {
  try {
    await buildFixture(name);
  } catch (error: unknown) {
    return error as Error;
  }
  throw new Error("expected the build to fail");
}

function filesIn(dir: string): string[] {
  return readdirSync(dir, { recursive: true, encoding: "utf8" })
    .map((file) => file.split(path.sep).join("/"))
    .sort();
}

describe("vite build with the site configuration", () => {
  it("builds pages, a site-<hash>.css file and hashed images, without folder notes", async () => {
    const outDir = await buildFixture("dist-ok");
    const files = filesIn(outDir);
    expect(files.filter((file) => /^assets\/site-[\w-]+\.css$/.test(file))).toHaveLength(1);
    const image = files.find((file) => /^assets\/pic-[\w-]+\.svg$/.test(file));
    expect(image).toBeDefined();
    expect(files).toContain("robots.txt");
    expect(files).toContain("fonts/font.woff2");
    expect(files.filter((file) => /readme\.md$|\.gitkeep$/i.test(file))).toEqual([]);
    const home = readFileSync(path.join(outDir, "index.html"), "utf8");
    const about = readFileSync(path.join(outDir, "about", "index.html"), "utf8");
    for (const html of [home, about]) {
      expect(html).toContain(`/${image}`);
      expect(html).not.toContain("/src/assets/");
      expect(html).not.toContain("@fs");
      expect(html).not.toContain(projectDir);
    }
    expect(home).toContain('<a href="/" aria-current="page">Home</a>');
    expect(about).toContain('<a href="/about/" aria-current="page">About</a>');
  });

  it("stops before bundling with only the plain sentence for an include error", async () => {
    const pageFile = path.join(fixtureSrc, "pages", "about", "index.html");
    const original = readFileSync(pageFile, "utf8");
    write(pageFile, original.replace("header.html current=/about/", "header.html current=/abuot/"));
    try {
      const error = await buildError("dist-include-error");
      // The configuration is bundled by Vite, so its SiteError is not the one imported here.
      expect(error.message).toBe(
        'src/pages/about/index.html has the include "<!-- include: header.html current=/abuot/ -->", but no link in header.html goes to "/abuot/"; the links in header.html are "/", "/about/". If this is only a note, start it with another word.',
      );
      expect(error.stack).toBe(error.message);
    } finally {
      write(pageFile, original);
    }
  });

  it("stops for a /src/ file that does not exist", async () => {
    const pageFile = path.join(fixtureSrc, "pages", "index.html");
    const original = readFileSync(pageFile, "utf8");
    write(pageFile, original.replace("/src/assets/pic.svg", "/src/assets/nope.png"));
    try {
      const error = await buildError("dist-missing");
      expect(error.message).toBe(
        'src/pages/index.html refers to "/src/assets/nope.png", but that file does not exist in src/.',
      );
      expect(error.stack).toBe(error.message);
    } finally {
      write(pageFile, original);
    }
  });
});

/** Finds a plugin of the site configuration by name. */
async function sitePlugin(name: string, command: "build" | "serve"): Promise<Plugin> {
  const config = await resolveConfig(quiet, command);
  const plugin = config.plugins.find((p) => p.name === name);
  if (plugin === undefined) {
    throw new Error(`the plugin ${name} is missing`);
  }
  return plugin as Plugin;
}

/** Calls a server hook of a plugin with a fake server and returns the middlewares it adds. */
async function middlewaresOf(hook: unknown): Promise<Middleware[]> {
  const added: Middleware[] = [];
  const server = {
    middlewares: { use: (middleware: Middleware) => added.push(middleware) },
    watcher: { add: () => undefined, on: () => undefined },
    ws: { send: () => undefined },
  };
  const handler = typeof hook === "function" ? hook : (hook as { handler: unknown }).handler;
  await (handler as (server: unknown) => unknown)(server);
  return added;
}

describe("dev and preview servers", () => {
  it("answer 404 for folder notes", async () => {
    const plugin = await sitePlugin("hide-folder-notes", "serve");
    for (const hook of [plugin.configureServer, plugin.configurePreviewServer]) {
      const middlewares = await middlewaresOf(hook);
      expect(middlewares.map((m) => answer(m, "/fonts/README.md"))).toContain(404);
      expect(middlewares.map((m) => answer(m, "/robots.txt"))).not.toContain(404);
    }
  });

  it("serve pages with includes and /src/ files under /@fs/, and report mistakes", async () => {
    const server = await createServer({
      ...quiet,
      server: { middlewareMode: true, ws: false, watch: null },
      optimizeDeps: { noDiscovery: true, include: [] },
    });
    try {
      const html = await server.transformIndexHtml(
        "/about/index.html",
        readFileSync(path.join(fixtureSrc, "pages", "about", "index.html"), "utf8"),
      );
      // Vite loads the configuration from its real path (node_modules may be a link).
      const srcUrl = realpathSync(fixtureSrc).split(path.sep).join("/").replace(/^\/?/, "/@fs/");
      expect(html).toContain(`src="${srcUrl}/assets/pic.svg"`);
      expect(html).toContain('<a href="/about/" aria-current="page">About</a>');
      await expect(
        server.transformIndexHtml("/index.html", '<img src="/src/assets/nope.png" alt="">'),
      ).rejects.toThrow(
        'src/pages/index.html refers to "/src/assets/nope.png", but that file does not exist in src/.',
      );
    } finally {
      await server.close();
    }
  });
});
