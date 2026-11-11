import { contrastRatio } from "./contrast.ts";
import type { ColourThemes } from "./tokens.ts";

/** WCAG AA: 4.5 for normal text, 3 for large text and for UI parts and focus rings. */
export const TEXT = 4.5;
export const NON_TEXT = 3;

export interface ContrastPair {
  readonly foreground: string;
  readonly background: string;
  readonly minimum: number;
  readonly usedFor: string;
}

/**
 * Every colour pair that src/styles/main.css declares, and nothing else. usedFor names
 * the rules that use it.
 *
 * tests/unit/stylesheet.test.ts lists every colour pair the stylesheet declares and
 * fails when one is missing here, when one here is no longer used, or when a rule uses
 * colour in a way it cannot read. Its message says what to change.
 *
 * The focus ring is drawn outside the element (--focus-offset), so it sits on the
 * background around the element: the page for links in main and for the skip link
 * (which is shown at the top of the page, above the header), the header for the site
 * name, nav links and theme buttons. Controls next to each other are --control-gap
 * apart, which is wider than the ring reaches, so a ring never touches another control.
 */
export const CONTRAST_PAIRS: readonly ContrastPair[] = [
  { foreground: "--color-text", background: "--color-bg", minimum: TEXT, usedFor: "body" },
  {
    foreground: "--color-text",
    background: "--color-surface",
    minimum: TEXT,
    usedFor:
      "code; .site-header, .site-footer; .figure figcaption; .theme-switch button; border of .theme-switch button:hover",
  },
  {
    foreground: "--color-text-muted",
    background: "--color-bg",
    minimum: TEXT,
    usedFor: ".lead, .note",
  },
  {
    foreground: "--color-text-muted",
    background: "--color-surface",
    minimum: TEXT,
    usedFor: ".theme-switch-label, .footer-note",
  },
  { foreground: "--color-link", background: "--color-bg", minimum: TEXT, usedFor: "a in main" },
  {
    foreground: "--color-link",
    background: "--color-surface",
    minimum: TEXT,
    usedFor: ".site-name, .nav-list a (also when visited)",
  },
  {
    foreground: "--color-link-hover",
    background: "--color-bg",
    minimum: TEXT,
    usedFor: "a:hover in main",
  },
  {
    foreground: "--color-link-hover",
    background: "--color-surface",
    minimum: TEXT,
    usedFor: ".site-name:hover, .nav-list a:hover",
  },
  {
    foreground: "--color-link-visited",
    background: "--color-bg",
    minimum: TEXT,
    usedFor: "a:visited in main",
  },
  {
    foreground: "--color-accent-text",
    background: "--color-accent",
    minimum: TEXT,
    usedFor: '.skip-link; .theme-switch button[aria-pressed="true"]',
  },
  {
    foreground: "--color-accent-text",
    background: "--color-accent-hover",
    minimum: TEXT,
    usedFor: '.theme-switch button[aria-pressed="true"]:hover',
  },
  {
    foreground: "--color-accent",
    background: "--color-surface",
    minimum: NON_TEXT,
    usedFor: 'fill and border of .theme-switch button[aria-pressed="true"] against the header',
  },
  {
    foreground: "--color-accent",
    background: "--color-bg",
    minimum: NON_TEXT,
    usedFor: "fill of the shown .skip-link against the page",
  },
  {
    foreground: "--color-accent-hover",
    background: "--color-surface",
    minimum: NON_TEXT,
    usedFor:
      'fill and border of .theme-switch button[aria-pressed="true"]:hover against the header',
  },
  {
    foreground: "--color-border",
    background: "--color-surface",
    minimum: NON_TEXT,
    usedFor: "border of .theme-switch button",
  },
  {
    foreground: "--color-border",
    background: "--color-bg",
    minimum: NON_TEXT,
    usedFor: "border of .figure",
  },
  {
    foreground: "--color-focus",
    background: "--color-bg",
    minimum: NON_TEXT,
    usedFor: ":focus-visible ring of links in main and of the skip link",
  },
  {
    foreground: "--color-focus",
    background: "--color-surface",
    minimum: NON_TEXT,
    usedFor: ":focus-visible ring in the header (site name, nav links, theme buttons)",
  },
];

export interface PairResult {
  readonly theme: "light" | "dark";
  readonly pair: ContrastPair;
  readonly ratio: number;
  readonly pass: boolean;
}

/** Ratios of every pair in both themes. A missing token fails loudly. */
export function checkPairs(themes: ColourThemes): PairResult[] {
  const results: PairResult[] = [];
  for (const theme of ["light", "dark"] as const) {
    const tokens = themes[theme];
    for (const pair of CONTRAST_PAIRS) {
      const foreground = tokens[pair.foreground];
      const background = tokens[pair.background];
      if (foreground === undefined || background === undefined) {
        const missing = foreground === undefined ? pair.foreground : pair.background;
        throw new Error(`the ${theme} theme does not define ${missing}.`);
      }
      const ratio = contrastRatio(foreground, background);
      results.push({ theme, pair, ratio, pass: ratio >= pair.minimum });
    }
  }
  return results;
}
