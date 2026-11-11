/*
 * Checks of src/styles/main.css against the design tokens and the contrast pair list.
 *
 * What is checked, and what to do when a check fails:
 *
 * 1. Colour pairs. Every colour pair the stylesheet declares must be listed in
 *    src/lib/contrast-pairs.ts (which "pnpm contrast" measures), and every listed pair
 *    must still be declared. To find the pairs, this test reads each rule and needs:
 *    - the selector in PLACES below, which says what background the element is drawn
 *      on. A new selector that uses colour fails until you add it there.
 *    - "color" in every rule that sets a background, so the text on it is known.
 *    - colour properties that use only var(--color-*) tokens: no gradients, images or
 *      other names (aliases) for colour tokens, in main.css or in tokens.css; and
 *      currentColor only in a rule that also sets color.
 *    - only system colours (such as Highlight) inside @media (forced-colors: active).
 *    - plain rules, optionally inside @media, @supports, @layer or @container. CSS
 *      nesting and other at-rules make the test fail, because it cannot read them.
 *    When it fails, the message says what to change.
 * 2. No hard-coded colours, and fonts, sizes and spacing come from tokens.
 * 3. Focus ring geometry: neighbouring controls and the shown skip link are far enough
 *    apart that a focus ring never touches another control.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { CONTRAST_PAIRS, NON_TEXT, TEXT } from "../../src/lib/contrast-pairs.ts";
import {
  type CssRule,
  parseRules,
  splitTopLevel,
  UnsupportedCssError,
} from "../../src/lib/css-rules.ts";
import { readDeclarations } from "../../src/lib/tokens.ts";

const tokensCss = readFileSync(new URL("../../design/tokens/tokens.css", import.meta.url), "utf8");
const stylesheet = readFileSync(new URL("../../src/styles/main.css", import.meta.url), "utf8");
const tokens = readDeclarations(tokensCss, ":root");

const BG = "--color-bg";
const SURFACE = "--color-surface";
const ACCENT = "--color-accent";
const ACCENT_HOVER = "--color-accent-hover";

const isForcedColors = (rule: CssRule): boolean =>
  rule.atRules.some((at) => at.replace(/\s+/g, "") === "@media(forced-colors:active)");

// ---------------------------------------------------------------------------------------
// Where each selector is drawn, reviewed by hand against the pages.
// inside:  the background behind the element's text when the rule sets none itself.
// outside: the background around the element, behind its border and focus ring
//          (the same as inside when not given).
// fill:    the element's own background marks a control or a state, so the fill must
//          stand out from the outside background (3:1).
// ---------------------------------------------------------------------------------------
interface Place {
  readonly inside: readonly string[];
  readonly outside?: readonly string[];
  readonly fill?: true;
}
const PLACES = new Map<string, Place>([
  ["body", { inside: [BG] }],
  ["code", { inside: [SURFACE], outside: [BG] }],
  ["a", { inside: [BG] }], // links in main; header links have their own rules below
  ["a:visited", { inside: [BG] }],
  ["a:hover", { inside: [BG] }],
  // Rings in main and of the shown skip link sit on the page; header rings on the header.
  [":focus-visible", { inside: [BG, SURFACE] }],
  [".skip-link", { inside: [ACCENT], outside: [BG], fill: true }],
  [".skip-link:visited", { inside: [ACCENT] }],
  [".skip-link:hover", { inside: [ACCENT] }],
  [".site-header", { inside: [SURFACE], outside: [BG] }],
  [".site-footer", { inside: [SURFACE], outside: [BG] }],
  [".site-name", { inside: [SURFACE] }],
  [".site-name:visited", { inside: [SURFACE] }],
  [".site-name:hover", { inside: [SURFACE] }],
  [".nav-list a", { inside: [SURFACE] }],
  [".nav-list a:visited", { inside: [SURFACE] }],
  [".nav-list a:hover", { inside: [SURFACE] }],
  [".theme-switch-label", { inside: [SURFACE] }],
  [".theme-switch button", { inside: [SURFACE] }],
  [".theme-switch button:hover", { inside: [SURFACE] }],
  [
    '.theme-switch button[aria-pressed="true"]',
    { inside: [ACCENT], outside: [SURFACE], fill: true },
  ],
  [
    '.theme-switch button[aria-pressed="true"]:hover',
    { inside: [ACCENT_HOVER], outside: [SURFACE], fill: true },
  ],
  [".lead", { inside: [BG] }],
  [".note", { inside: [BG] }],
  [".figure", { inside: [BG] }],
  [".figure figcaption", { inside: [SURFACE], outside: [BG] }],
  [".footer-note", { inside: [SURFACE] }],
]);

const COLOUR_PROPERTY =
  /^(color|background(-color|-image)?|(border|outline|text-decoration|column-rule)(-[a-z-]+)?|fill|stroke|caret-color|accent-color|box-shadow|text-shadow)$/;
const TEXT_PROPERTY = /^(color|fill|stroke|caret-color|text-shadow|text-decoration(-[a-z-]+)?)$/;
const BACKGROUND_PROPERTY = /^background(-color)?$/;
const colourTokensIn = (value: string): string[] =>
  [...value.matchAll(/var\(\s*(--color-[\w-]+)/g)].map((match) => match[1] ?? "");

interface Usage {
  readonly foreground: string;
  readonly background: string;
  readonly minimum: number;
  readonly where: string;
}

/** Problems with how a rule uses colour, before any pair is worked out. */
function ruleProblems(rule: CssRule, selector: string): string[] {
  const problems: string[] = [];
  for (const { property, value } of rule.declarations) {
    const where = `${selector} { ${property}: ${value} }`;
    if (property.startsWith("--")) {
      problems.push(
        `${where}: main.css must not define custom properties; define tokens in design/tokens/tokens.css and use --color-* tokens directly.`,
      );
    } else if (isForcedColors(rule)) {
      if (colourTokensIn(value).length > 0) {
        problems.push(
          `${where} is inside @media (forced-colors: active); use only system colours such as Highlight there.`,
        );
      }
    } else if (!COLOUR_PROPERTY.test(property)) {
      if (colourTokensIn(value).length > 0) {
        problems.push(
          `${where}: a colour token in "${property}" cannot be checked; use colour tokens only in colour properties.`,
        );
      }
    } else if (/-gradient\(|image-set\(|url\(/i.test(value) || property === "background-image") {
      problems.push(
        `${where}: gradients and images are not checked for contrast; use a plain colour token.`,
      );
    } else {
      for (const [, name = ""] of value.matchAll(/var\(\s*(--[\w-]+)/g)) {
        const token = tokens[name];
        if (!name.startsWith("--color-") && (token === undefined || /#|var\(/.test(token))) {
          problems.push(
            `${where}: colour properties may use only var(--color-*) tokens, not var(${name}).`,
          );
        }
      }
    }
  }
  const setsBackground = rule.declarations.some(
    (d) => BACKGROUND_PROPERTY.test(d.property) && !/^(transparent|none)$/i.test(d.value),
  );
  if (
    !isForcedColors(rule) &&
    setsBackground &&
    !rule.declarations.some((d) => d.property === "color")
  ) {
    problems.push(
      `${selector} sets a background without setting color in the same rule; add color so the pair can be checked.`,
    );
  }
  return problems;
}

/** Every colour pair the stylesheet declares, and every reason it cannot tell. */
function pairsDrawn(css: string): { usages: Usage[]; problems: string[] } {
  const usages: Usage[] = [];
  const problems: string[] = [];
  let rules: CssRule[];
  try {
    rules = parseRules(css);
  } catch (error) {
    if (error instanceof UnsupportedCssError) {
      return {
        usages,
        problems: [
          `main.css uses ${error.construct}, which the contrast check cannot read; write plain rules (they may sit inside @media, @supports, @layer or @container).`,
        ],
      };
    }
    throw error;
  }
  for (const rule of rules) {
    for (const selector of rule.selectors) {
      problems.push(...ruleProblems(rule, selector));
      const usesColour = rule.declarations.some(
        (d) => colourTokensIn(d.value).length > 0 || /currentcolor/i.test(d.value),
      );
      if (isForcedColors(rule) || !usesColour) {
        continue;
      }
      const place = PLACES.get(selector);
      if (place === undefined) {
        problems.push(
          `add ${selector} to the map \`PLACES\` in tests/unit/stylesheet.test.ts and its colour pairs to src/lib/contrast-pairs.ts`,
        );
        continue;
      }
      const outside = place.outside ?? place.inside;
      const ownBackground = rule.declarations
        .filter((d) => BACKGROUND_PROPERTY.test(d.property))
        .flatMap((d) => colourTokensIn(d.value));
      const add = (
        foregrounds: string[],
        backgrounds: readonly string[],
        minimum: number,
        what: string,
      ): void => {
        for (const foreground of foregrounds) {
          for (const background of backgrounds) {
            usages.push({ foreground, background, minimum, where: `${selector} { ${what} }` });
          }
        }
      };
      const ownColour = rule.declarations
        .filter((d) => d.property === "color")
        .flatMap((d) => colourTokensIn(d.value));
      for (const { property, value } of rule.declarations) {
        if (/currentcolor/i.test(value) && property !== "color") {
          // currentColor is the text colour, which is known only when the rule sets it.
          if (ownColour.length === 0) {
            problems.push(
              `${selector} { ${property}: ${value} } uses currentColor; set color in the same rule so the pair can be checked.`,
            );
          }
          add(ownColour, TEXT_PROPERTY.test(property) ? place.inside : outside, NON_TEXT, property);
        }
        if (BACKGROUND_PROPERTY.test(property)) {
          if (place.fill) {
            add(colourTokensIn(value), outside, NON_TEXT, `${property} as a fill`);
          }
        } else if (TEXT_PROPERTY.test(property)) {
          const behind = ownBackground.length > 0 ? ownBackground : place.inside;
          add(colourTokensIn(value), behind, property === "color" ? TEXT : NON_TEXT, property);
        } else {
          add(colourTokensIn(value), outside, NON_TEXT, property);
        }
      }
    }
  }
  return { usages, problems };
}

const listed = new Map(CONTRAST_PAIRS.map((p) => [`${p.foreground} on ${p.background}`, p]));
function unlisted(css: string): string[] {
  const { usages, problems } = pairsDrawn(css);
  const missing = usages.flatMap((u) => {
    const pair = listed.get(`${u.foreground} on ${u.background}`);
    if (pair === undefined) {
      return [
        `${u.foreground} on ${u.background} (${u.where}) is not in src/lib/contrast-pairs.ts`,
      ];
    }
    return pair.minimum < u.minimum
      ? [`${u.foreground} on ${u.background} (${u.where}) needs a minimum of ${u.minimum}`]
      : [];
  });
  return [...new Set([...problems, ...missing])];
}

/** Colour tokens in tokens.css must be named --color-*; other names for them are aliases. */
function tokenAliases(css: string): string[] {
  return parseRules(css).flatMap((rule) =>
    rule.declarations
      .filter((d) => d.property.startsWith("--") && !d.property.startsWith("--color-"))
      .filter((d) => /#|var\(\s*--color-/.test(d.value))
      .map(
        (d) =>
          `design/tokens/tokens.css: ${d.property} is a colour; name colour tokens --color-* and use them directly.`,
      ),
  );
}

// Fixed input for the checks below that test the guard itself, so that a change to
// main.css can only make the tests about main.css fail.
const SAMPLE = "body { color: var(--color-text); background: var(--color-bg); }\n";

describe("contrast pairs", () => {
  it("list every colour pair the stylesheet declares", () => {
    expect(unlisted(stylesheet)).toEqual([]);
  });

  it("list only pairs the stylesheet declares", () => {
    const drawn = new Set(
      pairsDrawn(stylesheet).usages.map((u) => `${u.foreground} on ${u.background}`),
    );
    expect([...listed.keys()].filter((pair) => !drawn.has(pair))).toEqual([]);
  });

  it("have no other names for colour tokens in tokens.css", () => {
    expect(tokenAliases(tokensCss)).toEqual([]);
    expect(tokenAliases(":root { --a: 1px; --my: var(--color-link-visited); }")).toHaveLength(1);
  });

  it("would catch an unlisted pair made of listed tokens", () => {
    const mutated = `${SAMPLE}.lead { color: var(--color-link-visited); background: var(--color-accent); }\n`;
    expect(unlisted(mutated)).toEqual([
      "--color-link-visited on --color-accent (.lead { color }) is not in src/lib/contrast-pairs.ts",
    ]);
  });

  it("accept a rule that uses a listed pair", () => {
    expect(unlisted(`${SAMPLE}.lead { color: var(--color-text); }\n`)).toEqual([]);
  });

  it.each([
    [".note { background: var(--color-accent); }", /\.note sets a background without/],
    ["main { background: var(--color-accent-hover); }", /main sets a background without/],
    [".brand { color: var(--color-link-visited); }", /add \.brand to the map `PLACES`/],
    [".site-footer p { color: var(--color-link-visited); }", /add \.site-footer p to the/],
    [".lead { --my: var(--color-link-visited); color: var(--my); }", /must not define custom/],
    [".lead { color: var(--my); }", /may use only var\(--color-\*\) tokens, not var\(--my\)/],
    [
      ".lead { color: var(--color-text); background: linear-gradient(var(--color-bg), red); }",
      /gradients/,
    ],
    [".lead { color: var(--color-text); background-image: url(/x.png); }", /gradients and images/],
    [".lead { filter: drop-shadow(0 0 1px var(--color-text)); }", /cannot be checked/],
    ["@media (forced-colors: active) { .x { color: var(--color-text); } }", /forced-colors/],
    [".lead { background: var(--color-surface); color: var(--color-link-visited); }", /not in src/],
    [".x { color: var(--color-text); & .y { color: var(--color-text); } }", /uses CSS nesting/],
    ["@keyframes spin { from { color: var(--color-text); } }", /main\.css uses @keyframes/],
    [
      "@media (min-width: 1px) { @media (hover: hover) { .x { color: var(--color-text); } } }",
      /add \.x to/,
    ],
    [".footer-note { outline-color: var(--color-link-visited); }", /visited on --color-surface/],
    [".lead { color: var(--color-border); }", /needs a minimum of 4\.5/],
    [".lead { box-shadow: 0 0 0 2px currentColor; }", /uses currentColor; set color/],
    [".x { box-shadow: 0 0 0 2px currentColor; }", /add \.x to the map `PLACES`/],
  ])("refuse %s", (rule, message) => {
    expect(unlisted(`${SAMPLE}${rule}\n`).join("\n")).toMatch(message);
  });

  it("read a fill that marks a control even when its border changes", () => {
    const pressed = '.theme-switch button[aria-pressed="true"] {';
    const mutated = stylesheet.replace(pressed, `${pressed} border-color: var(--color-border);`);
    const drawn = pairsDrawn(mutated).usages.map((u) => `${u.foreground} on ${u.background}`);
    expect(drawn).toContain(`${ACCENT} on ${SURFACE}`);
  });
});

// ---------------------------------------------------------------------------------------
// Hard-coded colours
// ---------------------------------------------------------------------------------------

const NAMED_COLOURS = new Set(
  `aliceblue antiquewhite aqua aquamarine azure beige bisque black blanchedalmond blue blueviolet brown
  burlywood cadetblue chartreuse chocolate coral cornflowerblue cornsilk crimson cyan darkblue darkcyan
  darkgoldenrod darkgray darkgreen darkgrey darkkhaki darkmagenta darkolivegreen darkorange darkorchid
  darkred darksalmon darkseagreen darkslateblue darkslategray darkslategrey darkturquoise darkviolet
  deeppink deepskyblue dimgray dimgrey dodgerblue firebrick floralwhite forestgreen fuchsia gainsboro
  ghostwhite gold goldenrod gray green greenyellow grey honeydew hotpink indianred indigo ivory khaki
  lavender lavenderblush lawngreen lemonchiffon lightblue lightcoral lightcyan lightgoldenrodyellow
  lightgray lightgreen lightgrey lightpink lightsalmon lightseagreen lightskyblue lightslategray
  lightslategrey lightsteelblue lightyellow lime limegreen linen magenta maroon mediumaquamarine
  mediumblue mediumorchid mediumpurple mediumseagreen mediumslateblue mediumspringgreen mediumturquoise
  mediumvioletred midnightblue mintcream mistyrose moccasin navajowhite navy oldlace olive olivedrab
  orange orangered orchid palegoldenrod palegreen paleturquoise palevioletred papayawhip peachpuff peru
  pink plum powderblue purple rebeccapurple red rosybrown royalblue saddlebrown salmon sandybrown
  seagreen seashell sienna silver skyblue slateblue slategray slategrey snow springgreen steelblue tan
  teal thistle tomato turquoise violet wheat white whitesmoke yellow yellowgreen`.split(/\s+/),
);
const SYSTEM_COLOURS = new Set(
  `accentcolor accentcolortext activetext buttonborder buttonface buttontext canvas canvastext field
  fieldtext graytext highlight highlighttext linktext mark marktext selecteditem selecteditemtext
  visitedtext`.split(/\s+/),
);
const COLOUR_FUNCTION = /(^|[^\w-])(rgba?|hsla?|hwb|lab|lch|oklab|oklch|color|color-mix)\(/i;
const HEX = /#[0-9a-f]{3,8}\b/i;

function hardCodedColours(css: string): string[] {
  const found: string[] = [];
  for (const rule of parseRules(css)) {
    for (const { property, value } of rule.declarations) {
      const where = `${rule.selectors.join(", ")} { ${property}: ${value} }`;
      if (HEX.test(value) || COLOUR_FUNCTION.test(value)) {
        found.push(where);
        continue;
      }
      const words = value.replace(/var\([^)]*\)/g, " ").match(/[a-z][a-z-]*/gi) ?? [];
      for (const word of words.map((w) => w.toLowerCase())) {
        if (NAMED_COLOURS.has(word) || (SYSTEM_COLOURS.has(word) && !isForcedColors(rule))) {
          found.push(where);
        }
      }
    }
  }
  return found;
}

const rulesFor = (selector: string): CssRule[] =>
  parseRules(stylesheet).filter(
    (rule) => rule.selectors.includes(selector) && !isForcedColors(rule),
  );
/** The last value the stylesheet gives `property` in rules that list `selector`. */
const declared = (selector: string, property: string): string | undefined =>
  rulesFor(selector)
    .flatMap((rule) => rule.declarations.filter((d) => d.property === property))
    .at(-1)?.value;

describe("the stylesheet", () => {
  it("uses no colour except through tokens (system colours only for forced colours)", () => {
    expect(hardCodedColours(stylesheet)).toEqual([]);
  });

  it.each([
    "a { color: red; }",
    "a { color: gray; background: oklch(0.9 0 0); }",
    "a { color: rgba(0, 0, 0, 0.5); }",
    "a { border-color: color-mix(in srgb, var(--color-text), white); }",
    "a { color: #123; }",
    "a { color: Highlight; }",
  ])("would catch %s", (rule) => {
    expect(hardCodedColours(`${SAMPLE}${rule}\n`)).not.toEqual([]);
  });

  it("takes fonts, type sizes and spacing from tokens", () => {
    const property =
      /^(font-family|font-size|font-weight|line-height|(margin|padding)(-[a-z-]+)?|gap|row-gap|column-gap)$/;
    const allowed = /^(var\(--[\w-]+\)|0|auto|inherit)$/;
    const literal = parseRules(stylesheet).flatMap((rule) =>
      rule.declarations
        .filter((d) => property.test(d.property))
        .filter((d) => splitTopLevel(d.value, " ").some((part) => !allowed.test(part)))
        .map((d) => `${rule.selectors.join(", ")} { ${d.property}: ${d.value} }`),
    );
    expect(literal).toEqual([]);
  });

  it("marks the pressed theme button with system colours in forced-colours mode", () => {
    const forced = parseRules(stylesheet).filter(isForcedColors);
    const pressed = forced.find((rule) =>
      rule.selectors.includes('.theme-switch button[aria-pressed="true"]'),
    );
    const background = pressed?.declarations.find((d) => d.property === "background")?.value ?? "";
    expect(SYSTEM_COLOURS.has(background.toLowerCase())).toBe(true);
  });

  it("lets a long name without spaces wrap in the heading and the site name", () => {
    expect(declared("h1", "overflow-wrap")).toBe("anywhere");
    expect(declared(".site-name", "overflow-wrap")).toBe("anywhere");
  });
});

// ---------------------------------------------------------------------------------------
// Focus ring and neighbours
// ---------------------------------------------------------------------------------------

/**
 * Smallest value in px a length can take, for the length tokens in tokens.css:
 * it replaces var() by the token, takes the lower bound of clamp(), and adds and
 * multiplies px and rem values (1rem = 16px).
 */
function minimumPx(value: string): number {
  let text = value.trim();
  for (let i = 0; i < 20 && text.includes("var("); i++) {
    text = text.replace(/var\(\s*(--[\w-]+)\s*\)/g, (_m, name: string) => {
      const token = tokens[name];
      if (token === undefined) {
        throw new Error(`${name} is not defined in design/tokens/tokens.css`);
      }
      return `(${token})`;
    });
  }
  text = text
    .replace(/clamp\(([^,()]+|\([^()]*\)),[^()]*(\([^()]*\)[^()]*)*\)/g, "($1)")
    .replace(/calc\(/g, "(");
  let p = 0;
  const peek = (): string => text.slice(p).trimStart().charAt(0);
  const skip = (): void => {
    while (/\s/.test(text.charAt(p))) {
      p++;
    }
  };
  function factor(): number {
    skip();
    if (text.charAt(p) === "(") {
      p++;
      const v = sum();
      skip();
      p++; // ")"
      return v;
    }
    const m = /^(-?\d*\.?\d+)(px|rem)?/.exec(text.slice(p));
    if (m === null) {
      throw new Error(`cannot read the length "${value}" at "${text.slice(p)}"`);
    }
    p += m[0].length;
    return Number(m[1]) * (m[2] === "rem" ? 16 : 1);
  }
  function product(): number {
    let v = factor();
    while (peek() === "*") {
      skip();
      p++;
      v *= factor();
    }
    return v;
  }
  function sum(): number {
    let v = product();
    while (peek() === "+" || peek() === "-") {
      skip();
      const op = text.charAt(p);
      p++;
      const w = product();
      v = op === "+" ? v + w : v - w;
    }
    return v;
  }
  return sum();
}

describe("focus ring", () => {
  // The ring reaches this far outside a focused element.
  const ringExtent = minimumPx("var(--focus-offset)") + minimumPx("var(--focus-width)");

  it("is at least 2px clear of the neighbouring control (gap > ring extent)", () => {
    for (const selector of [".theme-switch", ".nav-list", ".site-header-inner"]) {
      const gap = declared(selector, "gap");
      expect(gap, `${selector} has no gap`).toBeDefined();
      for (const part of splitTopLevel(gap ?? "", " ")) {
        expect(minimumPx(part), `${selector} gap ${part}`).toBeGreaterThanOrEqual(ringExtent + 2);
      }
    }
  });

  it("uses --control-gap, which is derived from the ring tokens", () => {
    expect(tokens["--control-gap"]).toMatch(/var\(--focus-offset\)/);
    expect(tokens["--control-gap"]).toMatch(/var\(--focus-width\)/);
    expect(minimumPx("var(--control-gap)")).toBeGreaterThanOrEqual(ringExtent + 2);
  });

  it("hides the skip link but keeps it focusable, and shows it in the page flow", () => {
    const hidden = rulesFor(".skip-link").flatMap((rule) =>
      rule.declarations.map((d) => `${d.property}: ${d.value}`),
    );
    expect(hidden).toContain("position: absolute");
    expect(hidden).toContain("clip-path: inset(50%)");
    expect(hidden).not.toContain("display: none");
    expect(hidden).not.toContain("visibility: hidden");
    // When focused it is an ordinary block at the top that pushes the header down, with
    // room for its ring on every side, so it never floats over another control.
    expect(declared(".skip-link:focus", "position")).toBe("static");
    expect(declared(".skip-link:focus", "clip-path")).toBe("none");
    for (const part of splitTopLevel(declared(".skip-link:focus", "margin") ?? "0", " ")) {
      expect(minimumPx(part), `.skip-link:focus margin ${part}`).toBeGreaterThanOrEqual(
        ringExtent + 2,
      );
    }
  });

  it("reads lengths", () => {
    expect(minimumPx("calc(2px + 0.25rem * 2)")).toBe(10);
    expect(minimumPx("clamp(1rem, 0.92rem + 0.35vw, 1.25rem)")).toBe(16);
  });
});
