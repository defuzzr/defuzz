import { readdirSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { expandIncludes, parseIncludeComment } from "../../vite.config.ts";

// Source-level checks of the pages and partials, expanded with the same include code
// the build uses. The built output is checked again by "pnpm xtask ci" (links, local
// files, remote URLs).
const pagesDir = new URL("../../src/pages/", import.meta.url);
const componentsDir = new URL("../../src/components/", import.meta.url);

function read(dir: URL, file: string): string {
  return readFileSync(new URL(file, dir), "utf8");
}

function readPartial(name: string): string | undefined {
  try {
    return read(componentsDir, name);
  } catch {
    return undefined;
  }
}

const pageFiles = readdirSync(pagesDir, { recursive: true, encoding: "utf8" })
  .filter((file) => file.endsWith(".html"))
  .map((file) => file.replace(/\\/g, "/"))
  .sort();
const partialFiles = readdirSync(componentsDir).filter((file) => file.endsWith(".html"));

const pages = pageFiles.map((file) => {
  const source = read(pagesDir, file);
  return { file, source, html: expandIncludes(source, `src/pages/${file}`, readPartial) };
});

const urlOf = (file: string): string => `/${file.replace(/index\.html$/, "")}`;

function count(html: string, pattern: RegExp): number {
  return html.match(pattern)?.length ?? 0;
}

function includesOf(source: string): { name: string; current?: string }[] {
  return [...source.matchAll(/<!--[\s\S]*?-->/g)].flatMap(([comment]) => {
    const include = parseIncludeComment(comment);
    return include === undefined ? [] : [include];
  });
}

/** Start tags in document order, skipping comments and the contents of script/style. */
function startTags(html: string): string[] {
  const clean = html
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1>/gi, "");
  return [...clean.matchAll(/<[a-z][^>]*>/gi)].map((match) => match[0]);
}

function isFocusable(tag: string): boolean {
  const name = /^<([a-z0-9]+)/i.exec(tag)?.[1]?.toLowerCase() ?? "";
  const tabindex = /\stabindex="(-?\d+)"/.exec(tag)?.[1];
  if (tabindex !== undefined) {
    return Number(tabindex) >= 0;
  }
  if (/\s(disabled|hidden)[\s>=/]/.test(tag)) {
    return false;
  }
  if (name === "a" || name === "area") {
    return /\shref=/.test(tag);
  }
  return ["button", "input", "select", "textarea", "summary", "iframe"].includes(name);
}

// The page that each file is; 404.html is shown at any missing address, so it marks nothing.
const expectedCurrent: Readonly<Record<string, string | undefined>> = {
  "404.html": undefined,
  "about/index.html": "/about/",
  "index.html": "/",
};

describe("page sources", () => {
  it.each(pageFiles)("%s includes header.html exactly once with the right current", (file) => {
    const source = pages.find((page) => page.file === file)?.source ?? "";
    const headers = includesOf(source).filter((include) => include.name.startsWith("header"));
    expect(headers).toHaveLength(1);
    expect(headers[0]?.name).toBe("header.html");
    const expected = file in expectedCurrent ? expectedCurrent[file] : urlOf(file);
    expect(headers[0]?.current).toBe(expected);
  });

  it.each(pageFiles)("%s includes head.html once", (file) => {
    const source = pages.find((page) => page.file === file)?.source ?? "";
    expect(includesOf(source).filter((include) => include.name === "head.html")).toHaveLength(1);
  });

  it("have one header partial, and no partial marks a current link itself", () => {
    expect(partialFiles.filter((file) => file.startsWith("header"))).toEqual(["header.html"]);
    for (const file of partialFiles) {
      expect(read(componentsDir, file), file).not.toContain('aria-current="page"');
    }
  });

  it("reach files in src only with addresses that start with /src/", () => {
    const sources = [
      ...pageFiles.map((file) => ({ file: `src/pages/${file}`, text: read(pagesDir, file) })),
      ...partialFiles.map((file) => ({
        file: `src/components/${file}`,
        text: read(componentsDir, file),
      })),
    ];
    for (const { file, text } of sources) {
      for (const [, , value = ""] of text.matchAll(/\s(src|href|srcset|poster)="([^"]*)"/g)) {
        expect(value, `${file}: ${value}`).not.toMatch(/(^|[\s,])\.\.?\//);
        if (/(^|\/)(src|assets|styles|components|lib|pages)\//.test(value)) {
          expect(value, `${file}: ${value}`).toMatch(/^\/src\//);
        }
      }
    }
  });
});

describe("partials", () => {
  const partial = (name: string): string => read(componentsDir, name);

  it("site-name.html links to / and is never marked as the current page", () => {
    // aria-current="false" keeps the header include from marking it: on the home page
    // only the nav link says "current page".
    expect(partial("site-name.html")).toMatch(
      /^<a class="site-name" href="\/" aria-current="false">/,
    );
  });

  it("header.html names its nav", () => {
    expect(partial("header.html")).toMatch(/<nav aria-label="[^"]+">/);
  });

  it("theme-switch.html starts hidden with exactly one pressed button", () => {
    const html = partial("theme-switch.html");
    expect(html).toMatch(/^<fieldset class="theme-switch" data-theme-switch hidden>/);
    expect(count(html, /aria-pressed="true"/g)).toBe(1);
  });
});

describe("head.html", () => {
  const head = read(componentsDir, "head.html");

  it("runs theme-init.html before the stylesheet is loaded", () => {
    const init = head.indexOf("<!-- include: theme-init.html -->");
    const stylesheet = head.indexOf('<link rel="stylesheet"');
    expect(init).toBeGreaterThanOrEqual(0);
    expect(stylesheet).toBeGreaterThan(init);
  });

  it("loads one script module, src/components/site.ts, which loads the others", () => {
    const scripts = [...head.matchAll(/<script\b[^>]*\bsrc="([^"]+)"/g)].map((match) => match[1]);
    expect(scripts).toEqual(["/src/components/site.ts"]);
    const site = read(componentsDir, "site.ts");
    expect(site).toContain('import "./theme-switch.ts";');
    expect(site).toContain('import "./footer-year.ts";');
  });
});

describe.each(pages)("$file", ({ file, html }) => {
  it("has the required document parts", () => {
    expect(html).toMatch(/^<!doctype html>/);
    expect(html).toContain('<html lang="en">');
    expect(html).toContain('<meta charset="utf-8" />');
    expect(html).toContain('name="viewport"');
    expect(html).toMatch(/<title>[^<]+<\/title>/);
    expect(html).toMatch(/<meta name="description" content="[^"]+" \/>/);
  });

  it("has exactly one h1 and every landmark", () => {
    expect(count(html, /<h1[\s>]/g)).toBe(1);
    for (const tag of ["header", "nav", "main", "footer"]) {
      expect(count(html, new RegExp(`<${tag}[\\s>]`, "g"))).toBe(1);
    }
  });

  it("starts the body with a skip link to an element that exists once", () => {
    const body = html.slice(html.indexOf("<body"));
    const first = startTags(body).slice(1).find(isFocusable) ?? "(nothing focusable)";
    expect(first).toMatch(/^<a class="skip-link" href="#[^"]+"/);
    const target = /href="#([^"]+)"/.exec(first)?.[1] ?? "";
    expect(count(html, new RegExp(`\\sid="${target}"`, "g"))).toBe(1);
  });

  it("makes main focusable for the skip link", () => {
    expect(html).toContain('<main id="main" tabindex="-1">');
  });

  it("marks exactly one link as the current page, and none on 404.html", () => {
    expect(count(html, /aria-current="page"/g)).toBe(file === "404.html" ? 0 : 1);
  });

  it("does not link to itself from the content", () => {
    const main = html.slice(html.indexOf("<main"), html.indexOf("</main>"));
    const own = file in expectedCurrent ? expectedCurrent[file] : urlOf(file);
    expect(main).not.toContain(`href="${own}"`);
  });

  it("has no duplicated ids", () => {
    const ids = [...html.matchAll(/\sid="([^"]+)"/g)].map((match) => match[1]);
    expect(ids.length).toBe(new Set(ids).size);
  });

  it("marks only its own nav link as the current page", () => {
    const current = [...html.matchAll(/<a href="([^"]+)" aria-current="page">/g)].map(
      (match) => match[1],
    );
    const navLinks = [...html.matchAll(/<li><a href="([^"]+)"/g)].map((match) => match[1]);
    const own = file in expectedCurrent ? expectedCurrent[file] : urlOf(file);
    expect(current).toEqual(navLinks.filter((href) => href === own));
  });

  it("gives every image a size and an alt attribute", () => {
    for (const [img] of html.matchAll(/<img\s[^>]*>/g)) {
      expect(img).toMatch(/\swidth="\d+"/);
      expect(img).toMatch(/\sheight="\d+"/);
      expect(img).toMatch(/\salt="/);
    }
  });
});
