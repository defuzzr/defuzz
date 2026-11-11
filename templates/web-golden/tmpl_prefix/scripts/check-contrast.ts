// Checks the colour contrast of every pair listed in src/lib/contrast-pairs.ts,
// using the colours in design/tokens/tokens.css, in the light and the dark theme.
// Run: node scripts/check-contrast.ts   (exits with 1 if any pair fails)
// It finds the tokens file from its own location, so it works from any folder.
// Every problem is reported as one line that starts with "check-contrast: ".
import { readFileSync } from "node:fs";
import { parseHex } from "../src/lib/contrast.ts";
import { checkPairs, type PairResult } from "../src/lib/contrast-pairs.ts";
import { readColourTokens } from "../src/lib/tokens.ts";

const TOKENS_FILE = "design/tokens/tokens.css";

/** Reads the tokens and measures every pair; throws an Error with a plain message. */
function measure(): PairResult[] {
  const css = readFileSync(new URL(`../${TOKENS_FILE}`, import.meta.url), "utf8");
  const themes = readColourTokens(css);
  for (const tokens of [themes.light, themes.dark, themes.systemDark]) {
    for (const [name, value] of Object.entries(tokens)) {
      const shown = value.replace(/\s+/g, " ").slice(0, 60);
      if (/[:;\n]/.test(value)) {
        throw new Error(
          `the value of ${name} in ${TOKENS_FILE} could not be read (is a ";" missing?): "${shown}".`,
        );
      }
      try {
        parseHex(value);
      } catch {
        throw new Error(
          `${name} in ${TOKENS_FILE} is "${shown}", which is not a hex colour such as #1a2b3c.`,
        );
      }
    }
  }
  return checkPairs(themes);
}

let results: PairResult[];
try {
  results = measure();
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`check-contrast: ${message.replace(/\s+/g, " ")}`);
  process.exit(1);
}

const rows = results.map((result) => [
  result.theme,
  result.pair.foreground,
  result.pair.background,
  result.ratio.toFixed(2),
  result.pair.minimum.toFixed(1),
  result.pass ? "pass" : "FAIL",
  result.pair.usedFor,
]);
const header = ["theme", "foreground", "background", "ratio", "needs", "result", "used for"];
const widths = header.map((title, column) =>
  Math.max(title.length, ...rows.map((row) => (row[column] ?? "").length)),
);
const line = (cells: readonly string[]): string =>
  cells
    .map((cell, column) => cell.padEnd(widths[column] ?? 0))
    .join("  ")
    .trimEnd();

console.log(line(header));
for (const row of rows) {
  console.log(line(row));
}

const failed = results.filter((result) => !result.pass).length;
if (failed > 0) {
  console.log(`check-contrast: ${failed} colour pair(s) are below WCAG AA; see the table above.`);
  process.exitCode = 1;
} else {
  console.log(`check-contrast: all ${results.length} colour pairs pass WCAG AA.`);
}
