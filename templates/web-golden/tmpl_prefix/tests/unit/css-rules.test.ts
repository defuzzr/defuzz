import { describe, expect, it } from "vitest";
import { parseRules, UnsupportedCssError } from "../../src/lib/css-rules.ts";

const constructOf = (css: string): string => {
  try {
    parseRules(css);
  } catch (error) {
    if (error instanceof UnsupportedCssError) {
      return error.construct;
    }
    throw error;
  }
  return "(none)";
};

describe("parseRules", () => {
  it("reads rules, @media inside @media, and skips comments and @import", () => {
    const rules = parseRules(
      '@import "x.css";\n/* a { b } */ a, b { color: red; content: "}{" }\n' +
        "@media (min-width: 1px) { @media (hover: hover) { c { color: blue } } }",
    );
    expect(rules).toEqual([
      {
        selectors: ["a", "b"],
        declarations: [
          { property: "color", value: "red" },
          { property: "content", value: '"}{"' },
        ],
        atRules: [],
      },
      {
        selectors: ["c"],
        declarations: [{ property: "color", value: "blue" }],
        atRules: ["@media (min-width: 1px)", "@media (hover: hover)"],
      },
    ]);
  });

  it("reads rules inside @supports, @layer and @container, and skips @font-face", () => {
    const css =
      "@layer base, page;\n@supports (display: grid) { a { color: red } }\n" +
      "@layer base { b { color: red } }\n@container (min-width: 1px) { c { color: red } }\n" +
      '@font-face { font-family: "X"; src: local("X"); }';
    expect(parseRules(css).map((rule) => rule.selectors[0])).toEqual(["a", "b", "c"]);
  });

  it("rejects what it cannot represent, naming the construct", () => {
    expect(constructOf("a { color: red; & b { color: blue } }")).toBe(
      "CSS nesting (a rule inside a rule)",
    );
    expect(constructOf("@keyframes spin { from { color: red } }")).toBe("@keyframes");
    expect(constructOf("@scope (.x) { a { color: red } }")).toBe("@scope");
    expect(constructOf('a { content: "{"; }')).toBe("(none)");
  });
});
