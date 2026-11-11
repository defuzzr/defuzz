import { inspect } from "node:util";
import { describe, expect, it } from "vitest";
import {
  expandIncludes,
  isFolderNote,
  markCurrentLinks,
  parseIncludeComment,
  type ReadPartial,
  relativeSrcUrl,
  rewriteSrcUrls,
} from "../../vite.config.ts";

function partials(files: Record<string, string>): ReadPartial {
  return (name) => files[name];
}

/** Runs fn, expects it to throw, and returns the error message. */
function errorOf(fn: () => unknown): string {
  try {
    fn();
  } catch (error: unknown) {
    expect(error).toBeInstanceOf(Error);
    const message = (error as Error).message;
    // Plain one-line messages without stack frames.
    expect(message).not.toContain("\n");
    expect((error as Error).stack ?? "").not.toMatch(/^\s*at /m);
    // "vite build" prints errors with util.inspect: only the sentence must appear.
    expect(inspect(error)).toBe(message);
    return message;
  }
  throw new Error("expected an error");
}

const PAGE = "src/pages/index.html";
const HINT = "If this is only a note, start it with another word.";

describe("parseIncludeComment", () => {
  it("returns undefined for comments that are not includes", () => {
    expect(parseIncludeComment("<!-- just a note -->")).toBeUndefined();
    expect(parseIncludeComment("<!-- includes are explained in the README -->")).toBeUndefined();
  });

  it("reads the partial name with and without current", () => {
    expect(parseIncludeComment("<!-- include: header.html -->")).toEqual({ name: "header.html" });
    expect(parseIncludeComment("<!--include:header.html-->")).toEqual({ name: "header.html" });
    expect(parseIncludeComment("<!-- include: header.html current=/about/ -->")).toEqual({
      name: "header.html",
      current: "/about/",
    });
    expect(parseIncludeComment('<!-- include: header.html current="/about/" -->')).toEqual({
      name: "header.html",
      current: "/about/",
    });
  });

  it("rejects an unknown parameter", () => {
    const message = errorOf(() =>
      parseIncludeComment("<!-- include: header.html curent=/x/ -->", PAGE),
    );
    expect(message).toContain(PAGE);
    expect(message).toContain("<!-- include: header.html curent=/x/ -->");
    expect(message).toContain('"curent"');
  });

  it("rejects malformed include comments", () => {
    for (const comment of [
      "<!-- include header.html -->",
      "<!-- include: -->",
      "<!-- include: header.html current= -->",
      '<!-- include: header.html current="/a b/" -->',
      "<!-- include: header.html current=/a/ current=/b/ -->",
    ]) {
      const message = errorOf(() => parseIncludeComment(comment, PAGE));
      expect(message).toContain(PAGE);
      expect(message).toContain(comment);
    }
  });
});

describe("ordinary comments and include mistakes", () => {
  it("leaves ordinary comments that start with the word include alone", () => {
    const notes = [
      "<!-- Include the logo here later -->",
      "<!-- include-me -->",
      "<!-- includes a note for editors -->",
      "<!-- include the new logo here -->",
      "<!--\n  include the new logo here\n  when it is ready\n-->",
      "<!-- include header later, see header.html -->",
    ];
    for (const comment of notes) {
      expect(parseIncludeComment(comment, PAGE)).toBeUndefined();
      const page = `<p>a</p>${comment}<p>b</p>`;
      expect(expandIncludes(page, PAGE, partials({}))).toBe(page);
    }
  });

  it("explains a forgotten colon", () => {
    const message = errorOf(() => parseIncludeComment("<!-- include header.html -->", PAGE));
    expect(message).toBe(
      `${PAGE} has the comment "<!-- include header.html -->", which looks like an include without the colon; write it as <!-- include: header.html -->. ${HINT}`,
    );
    expect(
      errorOf(() => parseIncludeComment("<!-- Include nav/main.html current=/ -->")),
    ).toContain("without the colon");
  });

  it("explains that the word include must be lowercase", () => {
    for (const comment of ["<!-- INCLUDE: header.html -->", "<!-- Include: header.html -->"]) {
      const message = errorOf(() => parseIncludeComment(comment, PAGE));
      expect(message).toBe(
        `${PAGE} has the include "${comment}", but the word must be written in lowercase as "include:". ${HINT}`,
      );
    }
  });

  it("ends every include error with the hint about notes", () => {
    const read = partials({ "h.html": `<a href="/">x</a>` });
    for (const page of [
      "<!-- include header.html -->",
      "<!-- INCLUDE: h.html -->",
      "<!-- include: -->",
      "<!-- include : h.html -->",
      "<!-- include: h.html curent=/x/ -->",
      "<!-- include: h.html current=/a/ current=/b/ -->",
      "<!-- include: h.html current= -->",
      "<!-- include: h.html current=/nope/ -->",
      "<!-- include: ../h.html -->",
      "<!-- include: missing.html -->",
    ]) {
      expect(errorOf(() => expandIncludes(page, PAGE, read)).endsWith(` ${HINT}`)).toBe(true);
    }
  });

  it("shows a long or multi-line comment on one line, cut to 80 characters", () => {
    const comment = `<!--\n  include: header.html\n  ${"x".repeat(100)}\n-->`;
    const message = errorOf(() => parseIncludeComment(comment, PAGE));
    const shown = /"(<!--[^"]*)"/.exec(message)?.[1] ?? "";
    expect(shown.length).toBe(80);
    expect(shown.startsWith("<!-- include: header.html xxx")).toBe(true);
    expect(shown.endsWith("...")).toBe(true);
  });
});

describe("current=", () => {
  const header = `<header><a href="/">Home</a><a href="/about/">About</a></header>`;
  const read = partials({ "header.html": header });

  it("accepts single quotes like double quotes", () => {
    expect(parseIncludeComment("<!-- include: header.html current='/about/' -->")).toEqual({
      name: "header.html",
      current: "/about/",
    });
    expect(expandIncludes("<!-- include: header.html current='/about/' -->", PAGE, read)).toBe(
      `<header><a href="/">Home</a><a href="/about/" aria-current="page">About</a></header>`,
    );
  });

  it("fails when no link in the included partials has the address", () => {
    const message = errorOf(() =>
      expandIncludes("<!-- include: header.html current=/abuot/ -->", PAGE, read),
    );
    expect(message).toBe(
      `${PAGE} has the include "<!-- include: header.html current=/abuot/ -->", but no link in header.html goes to "/abuot/"; the links in header.html are "/", "/about/". ${HINT}`,
    );
    const empty = errorOf(() =>
      expandIncludes("<!-- include: x.html current=/ -->", PAGE, partials({ "x.html": "<p></p>" })),
    );
    expect(empty).toContain("x.html has no links.");
  });

  it("counts a matching link in a nested partial or one that already has aria-current", () => {
    const nested = partials({
      "header.html": "<header><!-- include: nav.html --></header>",
      "nav.html": `<a href="/">Home</a><a aria-current="page" href="/about/">About</a>`,
    });
    expect(expandIncludes("<!-- include: header.html current=/about/ -->", PAGE, nested)).toBe(
      `<header><a href="/">Home</a><a aria-current="page" href="/about/">About</a></header>`,
    );
  });

  it("refuses addresses that cannot be written in a comment", () => {
    for (const [page, part] of [
      ["<!-- include: header.html current=/a-->b/ -->", '"-->"'],
      ["<!-- include: header.html current=/a>b/ -->", "cannot contain"],
      ['<!-- include: header.html current="/a b/" -->', "cannot contain"],
      ['<!-- include: header.html current=/a"b/ -->', "cannot contain"],
      ["<!-- include: header.html current='/a\"b/' -->", "cannot contain"],
      ["<!-- include: header.html current= -->", "empty current="],
      ['<!-- include: header.html current="" -->', "empty current="],
    ] as const) {
      const message = errorOf(() => expandIncludes(page, PAGE, read));
      expect(message).toContain(PAGE);
      expect(message).toContain(part);
    }
  });
});

describe("includes inside raw text elements", () => {
  it("are left as they are inside script, style, pre, textarea and template", () => {
    const read = partials({ "h.html": "<header></header>" });
    const raw = [
      `<script>const s = "<!-- include: h.html -->";</script>`,
      `<style>/* <!-- include: missing.html --> */</style>`,
      `<pre><!-- include: h.html --></pre>`,
      `<PRE class="x"><!-- INCLUDE: h.html --></PRE>`,
      `<textarea><!-- include: h.html --></textarea>`,
      `<template><!-- include header.html --></template>`,
    ].join("\n");
    expect(expandIncludes(`${raw}\n<!-- include: h.html -->`, PAGE, read)).toBe(
      `${raw}\n<header></header>`,
    );
  });
});

describe("markCurrentLinks", () => {
  it("marks exactly the link whose href equals current, in every quoting style and case", () => {
    const html = [
      `<a href="/">Home</a>`,
      `<a href="/about/">A1</a>`,
      `<a class=x href='/about/'>A2</a>`,
      `<A HREF=/about/>A3</A>`,
      `<a\n  class="nav"\n  href="/about/"\n>A4</a>`,
      `<a href="/about">no slash</a>`,
      `<a href="/about/#team">fragment</a>`,
    ].join("\n");
    const result = markCurrentLinks(html, "/about/");
    expect(result).toBe(
      [
        `<a href="/">Home</a>`,
        `<a href="/about/" aria-current="page">A1</a>`,
        `<a class=x href='/about/' aria-current="page">A2</a>`,
        `<A HREF=/about/ aria-current="page">A3</A>`,
        `<a\n  class="nav"\n  href="/about/" aria-current="page"\n>A4</a>`,
        `<a href="/about">no slash</a>`,
        `<a href="/about/#team">fragment</a>`,
      ].join("\n"),
    );
  });

  it("compares the decoded attribute value", () => {
    expect(markCurrentLinks(`<a href="/a?x=1&amp;y=2">x</a>`, "/a?x=1&y=2")).toBe(
      `<a href="/a?x=1&amp;y=2" aria-current="page">x</a>`,
    );
  });

  it("leaves a tag that already has aria-current unchanged", () => {
    const html = `<a aria-current="step" href="/about/">x</a><a ARIA-CURRENT href="/about/">y</a>`;
    expect(markCurrentLinks(html, "/about/")).toBe(html);
  });

  it("does not touch link, area, abbr, comments or scripts", () => {
    const html = [
      `<link rel="alternate" href="/about/">`,
      `<area href="/about/" alt="x">`,
      `<abbr href="/about/">x</abbr>`,
      `<!-- <a href="/about/">old</a> -->`,
      `<script>const s = '<a href="/about/">';</script>`,
    ].join("\n");
    expect(markCurrentLinks(html, "/about/")).toBe(html);
  });

  it("keeps a self-closing slash after the new attribute", () => {
    expect(markCurrentLinks(`<a href="/" />`, "/")).toBe(`<a href="/" aria-current="page" />`);
  });
});

describe("expandIncludes", () => {
  const header = `<header>\n  <a href="/">Home</a>\n  <a href='/about/'>About</a>\n</header>\n`;

  it("replaces a plain include with the partial", () => {
    const read = partials({ "header.html": header });
    expect(expandIncludes("<body>\n<!-- include: header.html -->\n</body>", PAGE, read)).toBe(
      `<body>\n${header}\n</body>`,
    );
  });

  it("expands nested partials and passes current down to them", () => {
    const read = partials({
      "header.html": `<header><!-- include: nav.html --></header>`,
      "nav.html": `<nav><a href="/">Home</a><a href="/about/">About</a></nav>`,
    });
    expect(expandIncludes("<!-- include: header.html current=/about/ -->", PAGE, read)).toBe(
      `<header><nav><a href="/">Home</a><a href="/about/" aria-current="page">About</a></nav></header>`,
    );
  });

  it("marks only links inside the partial, not the page's own links", () => {
    const read = partials({ "header.html": header });
    const page = `<a href="/">page link</a><!-- include: header.html current=/ -->`;
    expect(expandIncludes(page, PAGE, read)).toBe(
      `<a href="/">page link</a><header>\n  <a href="/" aria-current="page">Home</a>\n  <a href='/about/'>About</a>\n</header>\n`,
    );
  });

  it("leaves the partial byte-for-byte unchanged without current", () => {
    const tricky = `<a HREF="/" >x</a>\r\n<a\thref='/about/'>y</a><link href="/">`;
    const read = partials({ "x.html": tricky });
    expect(expandIncludes("<!-- include: x.html -->", PAGE, read)).toBe(tricky);
  });

  it("does not mark link tags inside the partial", () => {
    const head = `<link rel="canonical" href="/about/"><area href="/about/" alt="">`;
    const read = partials({ "head.html": `${head}<a href="/about/">x</a>` });
    expect(expandIncludes("<!-- include: head.html current=/about/ -->", PAGE, read)).toBe(
      `${head}<a href="/about/" aria-current="page">x</a>`,
    );
  });

  it("fails on an unknown parameter or a malformed include, naming the page", () => {
    const read = partials({ "header.html": header });
    const unknown = errorOf(() =>
      expandIncludes("<!-- include: header.html curent=/x/ -->", PAGE, read),
    );
    expect(unknown).toContain(PAGE);
    expect(unknown).toContain("curent=/x/");
    const malformed = errorOf(() => expandIncludes("<!-- include header.html -->", PAGE, read));
    expect(malformed).toContain(PAGE);
    expect(malformed).toContain("<!-- include header.html -->");
  });

  it("reports a missing partial with the file to create", () => {
    const message = errorOf(() => expandIncludes("<!-- include: hdr.html -->", PAGE, partials({})));
    expect(message).toContain(PAGE);
    expect(message).toContain("src/components/hdr.html does not exist");
  });

  it("names the partial and the page when a nested include is broken", () => {
    const read = partials({ "header.html": "<!-- include: nav.html -->" });
    const message = errorOf(() => expandIncludes("<!-- include: header.html -->", PAGE, read));
    expect(message).toContain("src/components/header.html");
    expect(message).toContain(PAGE);
    expect(message).toContain("src/components/nav.html does not exist");
  });

  it("refuses paths outside src/components and non-.html files without reading them", () => {
    const read: ReadPartial = (name) => {
      throw new Error(`must not read ${name}`);
    };
    for (const name of ["../x.html", "a/../../x.html", "/etc/x.html", "..\\x.html", "notes.txt"]) {
      const message = errorOf(() => expandIncludes(`<!-- include: ${name} -->`, PAGE, read));
      expect(message).toContain(PAGE);
      expect(message).toContain("inside src/components");
    }
  });

  it("allows partials in sub-folders of src/components", () => {
    const read = partials({ "nav/main.html": "<nav></nav>" });
    expect(expandIncludes("<!-- include: nav/./main.html -->", PAGE, read)).toBe("<nav></nav>");
  });

  it("stops partials that include themselves", () => {
    const read = partials({ "loop.html": "x<!-- include: loop.html -->" });
    const message = errorOf(() => expandIncludes("<!-- include: loop.html -->", PAGE, read));
    expect(message).toContain("more than 10 levels");
    expect(message).toContain("src/components/loop.html");
  });

  it("allows ten levels of nesting", () => {
    const files: Record<string, string> = { "p10.html": "end" };
    for (let i = 1; i < 10; i++) {
      files[`p${i}.html`] = `<!-- include: p${i + 1}.html -->`;
    }
    expect(expandIncludes("<!-- include: p1.html -->", PAGE, partials(files))).toBe("end");
  });
});

describe("rewriteSrcUrls", () => {
  const toRoot = (rest: string) => relativeSrcUrl("src/pages/index.html", rest);
  const toNested = (rest: string) => relativeSrcUrl("src/pages/about/index.html", rest);

  it("turns /src/ asset URLs into paths relative to the page", () => {
    expect(rewriteSrcUrls(`<img src="/src/assets/a.svg" alt="">`, toRoot)).toBe(
      `<img src="../assets/a.svg" alt="">`,
    );
    expect(rewriteSrcUrls(`<img src="/src/assets/a.svg" alt="">`, toNested)).toBe(
      `<img src="../../assets/a.svg" alt="">`,
    );
    expect(rewriteSrcUrls(`<svg><use href="/src/assets/icons.svg#home"></use></svg>`, toRoot)).toBe(
      `<svg><use href="../assets/icons.svg#home"></use></svg>`,
    );
  });

  it("rewrites every srcset candidate and keeps the descriptors", () => {
    const html = `<img srcset="/src/assets/a.png 1x,\n  /src/assets/b.png 2x, /photo.png 3x" alt="">`;
    expect(rewriteSrcUrls(html, toNested)).toBe(
      `<img srcset="../../assets/a.png 1x,\n  ../../assets/b.png 2x, /photo.png 3x" alt="">`,
    );
  });

  it("handles source, video poster and icon links", () => {
    const html = `<picture><source srcset="/src/assets/a.webp"></picture><video poster='/src/assets/p.jpg' src=/src/assets/v.webm></video><link rel="icon" href="/src/assets/i.svg">`;
    expect(rewriteSrcUrls(html, toRoot)).toBe(
      `<picture><source srcset="../assets/a.webp"></picture><video poster='../assets/p.jpg' src=../assets/v.webm></video><link rel="icon" href="../assets/i.svg">`,
    );
  });

  it("leaves relative, public, remote and data URLs, scripts and stylesheets alone", () => {
    const html = [
      `<img src="../assets/a.svg" alt="">`,
      `<link rel="icon" href="/favicon.svg">`,
      `<img src="https://example.com/src/a.png" alt="">`,
      `<img src="data:image/png;base64,AA" alt="">`,
      `<img src="/srcset.png" alt="">`,
      `<link rel="stylesheet" href="/src/styles/main.css">`,
      `<script type="module" src="/src/components/footer-year.ts"></script>`,
      `<a href="/src/assets/a.svg">link text</a>`,
      `<!-- <img src="/src/assets/a.svg"> -->`,
    ].join("\n");
    expect(rewriteSrcUrls(html, toRoot)).toBe(html);
  });
});

describe("isFolderNote", () => {
  it("excludes README.md in any letter case and .gitkeep, in any folder", () => {
    for (const file of ["README.md", "readme.md", "ReadMe.MD", "fonts/README.md", ".gitkeep"]) {
      expect(isFolderNote(file)).toBe(true);
    }
    expect(isFolderNote("fonts/.gitkeep")).toBe(true);
    expect(isFolderNote("fonts\\.gitkeep")).toBe(true);
  });

  it("keeps every other file", () => {
    for (const file of ["README.md.txt", "readme.html", "robots.txt", "favicon.svg", "x.gitkeep"]) {
      expect(isFolderNote(file)).toBe(false);
    }
  });
});
