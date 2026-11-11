import { readdirSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { contrastRatio } from "../../src/lib/contrast.ts";
import { checkPairs } from "../../src/lib/contrast-pairs.ts";
import { parseRules } from "../../src/lib/css-rules.ts";
import { readColourTokens, readDeclarations } from "../../src/lib/tokens.ts";

const css = readFileSync(new URL("../../design/tokens/tokens.css", import.meta.url), "utf8");

// The stylesheet itself (pairs it draws, hard-coded colours, focus spacing) is checked in
// tests/unit/stylesheet.test.ts.

describe("readDeclarations", () => {
  it("reads custom properties from one rule", () => {
    const sample = ":root {\n  --a: #fff;\n  --b: 1rem;\n}\n.x { --a: #000; }";
    expect(readDeclarations(sample, ":root")).toEqual({ "--a": "#fff", "--b": "1rem" });
  });

  it("fails clearly when the rule is missing", () => {
    expect(() => readDeclarations("", ":root")).toThrow(/no rule/);
  });
});

describe("design tokens", () => {
  const themes = readColourTokens(css);

  it("define the same colour names in light and dark", () => {
    const light = Object.keys(themes.light);
    const dark = [...new Set([...Object.keys(themes.dark), ...Object.keys(themes.systemDark)])];
    const problems = [
      ...light
        .filter((name) => !(name in themes.dark && name in themes.systemDark))
        .map(
          (name) =>
            `${name} is defined for light but not for dark; add it to both dark blocks in design/tokens/tokens.css`,
        ),
      ...dark
        .filter((name) => !(name in themes.light))
        .map(
          (name) =>
            `${name} is defined for dark but not for light; add it to :root in design/tokens/tokens.css, or remove it from both dark blocks`,
        ),
    ];
    expect(problems).toEqual([]);
  });

  it("use the same dark values for the system setting and the explicit choice", () => {
    expect(themes.systemDark).toEqual(themes.dark);
  });

  it("use only hex colours, so the contrast check can read them", () => {
    for (const value of [...Object.values(themes.light), ...Object.values(themes.dark)]) {
      expect(value).toMatch(/^#[0-9a-f]{6}$/);
    }
  });

  it("pass every listed contrast pair in both themes", () => {
    const failures = checkPairs(themes).filter((result) => !result.pass);
    expect(failures).toEqual([]);
  });

  it("would catch a failing pair", () => {
    expect(contrastRatio("#777777", "#ffffff")).toBeLessThan(4.5);
    const broken = { ...themes, light: { ...themes.light, "--color-text-muted": "#bbbbbb" } };
    expect(checkPairs(broken).some((result) => !result.pass)).toBe(true);
  });
});

describe("every token", () => {
  it("is used by the site or by another token", () => {
    const src = new URL("../../src/", import.meta.url);
    const files = readdirSync(src, { recursive: true, encoding: "utf8" }).filter((file) =>
      /\.(css|html|ts)$/.test(file),
    );
    const declarations = parseRules(css).flatMap((rule) => rule.declarations);
    const used = [
      ...files.map((file) => readFileSync(new URL(file, src), "utf8")),
      ...declarations.map((d) => d.value),
    ].join("\n");
    const unused = [...new Set(declarations.map((d) => d.property))]
      .filter(
        (name) => name.startsWith("--") && !new RegExp(`var\\(\\s*${name}\\s*[,)]`).test(used),
      )
      .map(
        (name) =>
          `${name} is defined in design/tokens/tokens.css but used nowhere; use it or remove it`,
      );
    expect(unused).toEqual([]);
  });
});
