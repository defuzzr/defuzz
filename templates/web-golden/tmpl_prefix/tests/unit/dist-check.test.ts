import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  checkCss,
  checkDist,
  checkJs,
  checkSite,
  classifyUrl,
  parseHtml,
  readSite,
  type SiteFiles,
} from "../../tools/xtask/dist-check.ts";

function page(body: string, head = ""): string {
  return `<!doctype html><html lang="en"><head><title>t</title>${head}</head><body>${body}</body></html>`;
}

function site(entries: Record<string, string | null>): SiteFiles {
  return new Map(Object.entries(entries));
}

describe("classifyUrl", () => {
  it("treats http, https, protocol-relative and websocket URLs as remote", () => {
    expect(classifyUrl("https://example.com/a.js")).toBe("remote");
    expect(classifyUrl("http://example.com/a.js")).toBe("remote");
    expect(classifyUrl("//cdn.example.com/a.js")).toBe("remote");
    expect(classifyUrl("wss://example.com/socket")).toBe("remote");
    expect(classifyUrl("  HTTPS://EXAMPLE.COM/  ")).toBe("remote");
  });

  it("treats data, blob, mailto, tel and javascript URLs as harmless", () => {
    for (const url of ["data:image/png;base64,AAAA", "blob:x", "mailto:a@b.c", "tel:+1", ""]) {
      expect(classifyUrl(url)).toBe("ignore");
    }
  });

  it("separates same-page fragments from local paths", () => {
    expect(classifyUrl("#main")).toBe("fragment");
    expect(classifyUrl("/about/")).toBe("local");
    expect(classifyUrl("../x.png")).toBe("local");
    expect(classifyUrl("about/index.html?x=1#y")).toBe("local");
  });

  it("treats unknown schemes as other", () => {
    expect(classifyUrl("ftp://example.com/x")).toBe("other");
    expect(classifyUrl("file:///etc/passwd")).toBe("other");
  });
});

describe("parseHtml", () => {
  it("reads attributes in every quoting style and decodes entities", () => {
    const parsed = parseHtml(`<a href="/a?x=1&amp;y=2" data-x='q>r' id=top class=x>t</a>`);
    const tag = parsed.tags[0];
    expect(tag?.name).toBe("a");
    expect(tag?.attrs.get("href")).toBe("/a?x=1&y=2");
    expect(tag?.attrs.get("data-x")).toBe("q>r");
    expect(tag?.attrs.get("id")).toBe("top");
    expect(parsed.ids.has("top")).toBe(true);
  });

  it("skips comments and does not read tags inside them", () => {
    const parsed = parseHtml(`<!-- <img src="https://example.com/x.png"> --><p id="a"></p>`);
    expect(parsed.tags.map((t) => t.name)).toEqual(["p"]);
  });

  it("collects style and script bodies without parsing them as HTML", () => {
    const parsed = parseHtml(
      `<style>a{background:url(/x.png)}</style><script>const s = "<img src=x>";</script>`,
    );
    expect(parsed.styles).toEqual(["a{background:url(/x.png)}"]);
    expect(parsed.scripts.map((s) => s.content)).toEqual([`const s = "<img src=x>";`]);
    expect(parsed.tags.some((t) => t.name === "img")).toBe(false);
  });

  it("collects ids and a[name] anchors", () => {
    const parsed = parseHtml(`<section id="one"></section><a name="two"></a>`);
    expect([...parsed.ids].sort()).toEqual(["one", "two"]);
  });
});

describe("checkSite: internal links", () => {
  it("passes a small valid site", () => {
    const files = site({
      "index.html": page(
        `<a href="/about/">About</a><a href="about/index.html#team">Team</a><a href="#main">Skip</a><main id="main"></main>`,
        `<link rel="stylesheet" href="/assets/main.css"><link rel="icon" href="/favicon.svg"><script type="module" src="/assets/main.js"></script>`,
      ),
      "about/index.html": page(`<h2 id="team">Team</h2><a href="../">Home</a><a href="/">Home</a>`),
      "404.html": page(`<a href="/">Home</a>`),
      "assets/main.css": "body{background:url(./bg.png)}",
      "assets/bg.png": null,
      "assets/main.js": `document.title = "x";`,
      "favicon.svg": null,
    });
    expect(checkSite(files)).toEqual([]);
  });

  it("reports a link to a missing page with file and link", () => {
    const files = site({ "index.html": page(`<a href="/abut/">About</a>`) });
    const problems = checkSite(files);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain("dist/index.html:");
    expect(problems[0]).toContain(`"/abut/"`);
  });

  it("resolves a directory without a trailing slash to its index.html", () => {
    const files = site({
      "index.html": page(`<a href="/about">About</a>`),
      "about/index.html": page(""),
    });
    expect(checkSite(files)).toEqual([]);
  });

  it("ignores the query string when resolving", () => {
    const files = site({
      "index.html": page(`<img src="/a.png?v=2" alt="">`),
      "a.png": null,
    });
    expect(checkSite(files)).toEqual([]);
  });

  it("reports a missing fragment on the same page and on another page", () => {
    const files = site({
      "index.html": page(`<a href="#nope">x</a><a href="/about/#gone">y</a>`),
      "about/index.html": page(`<h2 id="here">x</h2>`),
    });
    const problems = checkSite(files);
    expect(problems).toHaveLength(2);
    expect(problems[0]).toContain(`"#nope"`);
    expect(problems[1]).toContain(`"/about/#gone"`);
  });

  it("accepts #top and a bare # without a matching id", () => {
    const files = site({ "index.html": page(`<a href="#top">Top</a><a href="#">x</a>`) });
    expect(checkSite(files)).toEqual([]);
  });

  it("reports a missing local image, srcset candidate, poster and video source", () => {
    const files = site({
      "index.html": page(
        `<img src="/missing.png" alt=""><img srcset="/a.png 1x, /b.png 2x" src="/a.png" alt=""><video poster="/p.jpg"><source src="/v.webm"></video>`,
      ),
      "a.png": null,
    });
    const problems = checkSite(files);
    expect(problems.join("\n")).toContain(`"/missing.png"`);
    expect(problems.join("\n")).toContain(`"/b.png"`);
    expect(problems.join("\n")).toContain(`"/p.jpg"`);
    expect(problems.join("\n")).toContain(`"/v.webm"`);
    expect(problems).toHaveLength(4);
  });

  it("reports a link that leaves the site folder", () => {
    const files = site({ "index.html": page(`<a href="../../etc/passwd">x</a>`) });
    expect(checkSite(files)[0]).toContain("outside");
  });

  it("allows external page links, mailto and tel", () => {
    const files = site({
      "index.html": page(
        `<a href="https://example.com/">x</a><a href="mailto:a@example.com">m</a><a href="tel:+100">t</a>`,
        `<link rel="canonical" href="https://example.com/">`,
      ),
    });
    expect(checkSite(files)).toEqual([]);
  });

  it("allows the SVG namespace in inline SVG and checks use[href]", () => {
    const files = site({
      "index.html": page(
        `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><use href="/icons.svg#a"></use></svg>`,
      ),
    });
    const problems = checkSite(files);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain(`"/icons.svg#a"`);
  });

  it("decodes percent-encoded paths and checks meta refresh targets", () => {
    const files = site({
      "index.html": page(
        `<img src="/my%20photo.png" alt="">`,
        `<meta http-equiv="refresh" content="5; url=/moved/">`,
      ),
      "my photo.png": null,
    });
    const problems = checkSite(files);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain(`"/moved/"`);
  });

  it("checks local links in partial-style relative paths from nested pages", () => {
    const files = site({
      "index.html": page(""),
      "blog/post/index.html": page(`<a href="../../">Home</a><a href="../">Blog</a>`),
    });
    const problems = checkSite(files);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain(`"../"`);
  });

  it("reports a missing home page", () => {
    const files = site({ "about/index.html": page("") });
    expect(checkSite(files).join("\n")).toContain("index.html");
  });
});

describe("checkSite: remote resources", () => {
  it("reports a remote script", () => {
    const files = site({
      "index.html": page("", `<script src="https://example.com/x.js"></script>`),
    });
    const problems = checkSite(files);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain("dist/index.html:");
    expect(problems[0]).toContain("remote");
    expect(problems[0]).toContain("https://example.com/x.js");
  });

  it("reports remote stylesheets, icons, preloads and preconnects", () => {
    const files = site({
      "index.html": page(
        "",
        `<link rel="stylesheet" href="//cdn.example.com/a.css"><link rel="icon" href="https://example.com/i.png"><link rel="preload" as="font" href="https://example.com/f.woff2"><link rel="preconnect" href="https://fonts.example.com">`,
      ),
    });
    expect(checkSite(files)).toHaveLength(4);
  });

  it("treats an alternate stylesheet as fetched but an alternate language page as a link", () => {
    const files = site({
      "index.html": page(
        "",
        `<link rel="alternate stylesheet" href="https://example.com/a.css"><link rel="alternate" hreflang="de" href="https://example.com/de/">`,
      ),
    });
    const problems = checkSite(files);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain("a.css");
  });

  it("reports remote images, iframes, embeds, objects and media", () => {
    const files = site({
      "index.html": page(
        `<img src="https://example.com/a.png" alt=""><img srcset="https://example.com/b.png 2x" alt=""><iframe src="https://example.com/"></iframe><embed src="https://example.com/e"><object data="https://example.com/o"></object><audio src="https://example.com/a.mp3"></audio>`,
      ),
    });
    expect(checkSite(files)).toHaveLength(6);
  });

  it("reports remote URLs in inline style attributes and style elements", () => {
    const files = site({
      "index.html": page(
        `<div style="background: url('https://example.com/bg.png')"></div>`,
        `<style>@import url("https://example.com/x.css");</style>`,
      ),
    });
    expect(checkSite(files)).toHaveLength(2);
  });

  it("reports remote loads in inline scripts but not in JSON-LD", () => {
    const files = site({
      "index.html": page(
        `<script>fetch("https://api.example.com/data")</script><script type="application/ld+json">{"url":"https://example.com/"}</script>`,
      ),
    });
    const problems = checkSite(files);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain("fetch");
  });

  it("checks built CSS and JS files", () => {
    const files = site({
      "index.html": page(""),
      "assets/a.css": `@font-face{font-family:x;src:url(https://fonts.example.com/x.woff2)}`,
      "assets/a.js": `import("https://example.com/m.js");`,
    });
    const problems = checkSite(files);
    expect(problems).toHaveLength(2);
    expect(problems[0]).toContain("dist/assets/a.css:");
    expect(problems[1]).toContain("dist/assets/a.js:");
  });
});

describe("checkCss", () => {
  const files = site({ "assets/a.css": "", "assets/x.png": null, "fonts/f.woff2": null });

  it("resolves url() relative to the stylesheet and accepts data URLs and fragments", () => {
    const css = `a{background:url(x.png)} b{background:url("data:image/png;base64,AA")} c{filter:url(#f)} @font-face{src:url('/fonts/f.woff2') format("woff2")}`;
    expect(checkCss("assets/a.css", css, files)).toEqual([]);
  });

  it("reports missing url() and @import targets", () => {
    const css = `@import "missing.css"; a{background:url(nope.png)}`;
    const problems = checkCss("assets/a.css", css, files);
    expect(problems).toHaveLength(2);
    expect(problems[0]).toContain(`"missing.css"`);
    expect(problems[1]).toContain(`"nope.png"`);
  });

  it("reports remote @import in both forms and remote url()", () => {
    const css = `@import url("https://example.com/a.css"); @import 'https://example.com/b.css'; a{background:url(//cdn.example.com/x.png)}`;
    expect(checkCss("assets/a.css", css, files)).toHaveLength(3);
  });

  it("ignores URLs inside comments", () => {
    const css = `/* url(https://example.com/x.png) */ a{color:red}`;
    expect(checkCss("assets/a.css", css, files)).toEqual([]);
  });
});

describe("checkJs", () => {
  it("reports remote fetch, import, workers, sockets, XHR and beacons", () => {
    const js = [
      `fetch("https://api.example.com/a")`,
      `import('https://example.com/m.js')`,
      "new Worker(`https://example.com/w.js`)",
      `new EventSource("https://example.com/s")`,
      `new WebSocket("wss://example.com/ws")`,
      `x.open("GET","https://example.com/x")`,
      `navigator.sendBeacon("https://example.com/b", d)`,
      `import x from "https://example.com/esm.js"`,
    ].join(";\n");
    expect(checkJs("assets/a.js", js)).toHaveLength(8);
  });

  it("ignores local requests and plain strings that hold remote URLs", () => {
    const js = `fetch("/api/data.json"); import("./chunk.js"); const ns = "http://www.w3.org/2000/svg"; window.open("https://example.com/")`;
    expect(checkJs("assets/a.js", js)).toEqual([]);
  });
});

describe("readSite and checkDist", () => {
  // Scratch folders live inside the project (node_modules is ignored by git and Biome),
  // so the tests never write outside the project folder.
  const scratchRoot = path.join(import.meta.dirname, "../../node_modules/.cache");
  let dir = "";

  afterEach(() => {
    if (dir !== "") {
      rmSync(dir, { recursive: true, force: true });
      dir = "";
    }
  });

  it("reads a folder from disk and checks it", () => {
    mkdirSync(scratchRoot, { recursive: true });
    dir = mkdtempSync(path.join(scratchRoot, "dist-check-"));
    mkdirSync(path.join(dir, "about"));
    writeFileSync(path.join(dir, "index.html"), page(`<a href="/about/">a</a>`));
    writeFileSync(path.join(dir, "about", "index.html"), page(`<img src="/gone.png" alt="">`));
    writeFileSync(path.join(dir, "logo.png"), "binary");
    const files = readSite(dir);
    expect([...files.keys()].sort()).toEqual(["about/index.html", "index.html", "logo.png"]);
    expect(files.get("logo.png")).toBeNull();
    const problems = checkDist(dir);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain("dist/about/index.html:");
  });

  it("reports a missing folder", () => {
    expect(checkDist(path.join(scratchRoot, "dist-check-does-not-exist"))[0]).toContain(
      "not found",
    );
  });

  it("says plainly that a file vanished while it was checked (another build may be running)", () => {
    mkdirSync(scratchRoot, { recursive: true });
    dir = mkdtempSync(path.join(scratchRoot, "dist-check-"));
    writeFileSync(path.join(dir, "index.html"), page(""));
    // A link to nothing looks exactly like a file that is gone between listing and reading.
    symlinkSync(path.join(dir, "gone.js"), path.join(dir, "assets.js"));
    expect(checkDist(dir)).toEqual([
      "dist/assets.js: this file disappeared while dist/ was being checked; another build or check may be running in this project (or it is a link to a missing file). When nothing else is running, run the command again.",
    ]);
  });

  it("still stops with the error itself for anything other than a vanished file", () => {
    if (process.getuid?.() === 0) {
      return; // root can read everything
    }
    mkdirSync(scratchRoot, { recursive: true });
    dir = mkdtempSync(path.join(scratchRoot, "dist-check-"));
    writeFileSync(path.join(dir, "index.html"), page(""));
    chmodSync(path.join(dir, "index.html"), 0o000);
    expect(() => checkDist(dir)).toThrow(/EACCES/);
  });
});

describe("case-insensitive schemes and image-set()", () => {
  it("reports upper- and mixed-case schemes in every JavaScript call site", () => {
    const js = [
      'fetch("HTTPS://example.com/U");',
      'import("Http://example.com/m.js");',
      'new WebSocket("WSS://example.com/s");',
      'new Worker("//CDN.example.com/w.js");',
      'xhr.open("GET", "HTTP://example.com/x");',
      'import x from "HTTPS://example.com/y.js";',
      'import "Https://example.com/z.js";',
    ].join("\n");
    expect(checkJs("assets/index-a1b2c3d4.js", js)).toHaveLength(7);
  });

  it("reports upper-case schemes in CSS and HTML", () => {
    expect(
      checkCss("a.css", "a{background:url(HTTPS://example.com/a.png)}", site({})),
    ).toHaveLength(1);
    expect(checkCss("a.css", '@import "Http://example.com/a.css";', site({}))).toHaveLength(1);
    const problems = checkSite(
      site({ "index.html": page('<img src="HTTPS://example.com/a.png" alt="">') }),
    );
    expect(problems).toHaveLength(1);
  });

  it("reports remote string candidates in image-set() and -webkit-image-set()", () => {
    const css =
      'h1{background-image:image-set("https://example.com/i2.png" 2x)}' +
      "h2{background-image:-webkit-image-set('HTTPS://example.com/i3.png' 1x, url(\"//x.example.com/i.png\") 2x)}";
    const problems = checkCss("a.css", css, site({}));
    expect(problems).toHaveLength(3);
    expect(problems.join("\n")).toContain("https://example.com/i2.png");
    expect(problems.join("\n")).toContain("HTTPS://example.com/i3.png");
  });

  it("requires every local image-set() candidate to exist", () => {
    const css = 'h1{background-image:image-set("./a.png" 1x, "./a@2x.png" 2x)}';
    expect(checkCss("a.css", css, site({ "a.png": null, "a@2x.png": null }))).toEqual([]);
    const problems = checkCss("a.css", css, site({ "a.png": null }));
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain("a@2x.png");
  });

  it("does not flag XML namespaces or URLs in comments and visible text", () => {
    const js =
      'document.createElementNS("http://www.w3.org/2000/svg","svg");const n="HTTP://www.w3.org/1999/xhtml";';
    expect(checkJs("a.js", js)).toEqual([]);
    const html = page(
      '<!-- <script src="HTTPS://example.com/a.js"></script> --><p>See HTTPS://example.com/ and //example.com</p>' +
        '<svg xmlns="http://www.w3.org/2000/svg"></svg><a href="HTTPS://example.com/">x</a>',
    );
    expect(checkSite(site({ "index.html": html }))).toEqual([]);
  });
});
