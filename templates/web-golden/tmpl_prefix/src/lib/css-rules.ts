/** One declaration such as { property: "color", value: "var(--color-text)" }. */
export interface CssDeclaration {
  readonly property: string;
  readonly value: string;
}

/** One style rule, with the at-rules (for example "@media (forced-colors: active)") around it. */
export interface CssRule {
  readonly selectors: readonly string[];
  readonly declarations: readonly CssDeclaration[];
  readonly atRules: readonly string[];
}

/**
 * Thrown for CSS this reader cannot represent as plain style rules, so a check built on
 * it fails instead of silently missing a rule. `construct` names what was found.
 */
export class UnsupportedCssError extends Error {
  readonly construct: string;

  constructor(construct: string, near: string) {
    super(`${construct} is not supported, near: ${near.replace(/\s+/g, " ").slice(0, 60)}`);
    this.construct = construct;
  }
}

/** At-rules whose body is a list of rules, read like the rest of the stylesheet. */
const GROUPING_AT_RULES = new Set(["@media", "@supports", "@layer", "@container"]);

/** Removes comments, keeping strings intact. */
export function stripComments(css: string): string {
  return css.replace(
    /("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')|\/\*[\s\S]*?\*\//g,
    (_m, text?: string) => (text === undefined ? " " : text),
  );
}

/** Splits text at `separator` where it is not inside (), [] or a string. */
export function splitTopLevel(text: string, separator: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let quote = "";
  let start = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charAt(i);
    if (quote !== "") {
      if (c === "\\") {
        i++;
      } else if (c === quote) {
        quote = "";
      }
    } else if (c === '"' || c === "'") {
      quote = c;
    } else if (c === "(" || c === "[") {
      depth++;
    } else if (c === ")" || c === "]") {
      depth--;
    } else if (c === separator && depth === 0) {
      parts.push(text.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(text.slice(start));
  return parts.map((part) => part.trim()).filter((part) => part !== "");
}

/** Index of the "}" that closes the "{" at `open`, ignoring braces in strings. */
function closingBrace(css: string, open: number): number {
  let depth = 0;
  let quote = "";
  for (let i = open; i < css.length; i++) {
    const c = css.charAt(i);
    if (quote !== "") {
      if (c === "\\") {
        i++;
      } else if (c === quote) {
        quote = "";
      }
    } else if (c === '"' || c === "'") {
      quote = c;
    } else if (c === "{") {
      depth++;
    } else if (c === "}") {
      depth--;
      if (depth === 0) {
        return i;
      }
    }
  }
  throw new Error(
    `The stylesheet has a "{" without a matching "}" near: ${css.slice(open, open + 40)}`,
  );
}

/** True when `text` has a "{" outside strings. */
function hasBrace(text: string): boolean {
  return text.replace(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/g, "").includes("{");
}

function parseBlock(css: string, atRules: readonly string[], rules: CssRule[]): void {
  let i = 0;
  while (i < css.length) {
    const brace = css.indexOf("{", i);
    const semicolon = css.indexOf(";", i);
    if (brace === -1) {
      return;
    }
    if (semicolon !== -1 && semicolon < brace && css.slice(i, semicolon).trim().startsWith("@")) {
      i = semicolon + 1; // a statement such as @import
      continue;
    }
    const prelude = css.slice(i, brace).trim();
    const end = closingBrace(css, brace);
    const body = css.slice(brace + 1, end);
    if (prelude.startsWith("@")) {
      const name = (/^@[\w-]+/.exec(prelude)?.[0] ?? prelude).toLowerCase();
      if (GROUPING_AT_RULES.has(name)) {
        parseBlock(body, [...atRules, prelude.replace(/\s+/g, " ")], rules);
      } else if (name !== "@font-face") {
        // @font-face only names a font; anything else (@keyframes, @page, @scope ...)
        // holds something other than style rules.
        throw new UnsupportedCssError(name, prelude);
      }
    } else {
      if (hasBrace(body)) {
        throw new UnsupportedCssError("CSS nesting (a rule inside a rule)", prelude);
      }
      const declarations = splitTopLevel(body, ";").flatMap((text) => {
        const colon = text.indexOf(":");
        return colon === -1
          ? []
          : [
              {
                property: text.slice(0, colon).trim().toLowerCase(),
                value: text.slice(colon + 1).trim(),
              },
            ];
      });
      rules.push({
        selectors: splitTopLevel(prelude, ",").map((s) => s.replace(/\s+/g, " ")),
        declarations,
        atRules,
      });
    }
    i = end + 1;
  }
}

/** Reads a stylesheet into its style rules, including those nested in @media and similar. */
export function parseRules(css: string): CssRule[] {
  const rules: CssRule[] = [];
  parseBlock(stripComments(css), [], rules);
  return rules;
}
