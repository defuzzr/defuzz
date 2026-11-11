/** A colour as 0-255 red, green and blue channels. */
export interface Rgb {
  readonly r: number;
  readonly g: number;
  readonly b: number;
}

const HEX_PATTERN = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i;

/** Reads "#rgb" or "#rrggbb". Throws for anything else. */
export function parseHex(text: string): Rgb {
  const match = HEX_PATTERN.exec(text.trim());
  const digits = match?.[1];
  if (digits === undefined) {
    throw new Error(`"${text}" is not a hex colour such as #1a2b3c.`);
  }
  const full = digits.length === 3 ? [...digits].map((digit) => digit + digit).join("") : digits;
  return {
    r: Number.parseInt(full.slice(0, 2), 16),
    g: Number.parseInt(full.slice(2, 4), 16),
    b: Number.parseInt(full.slice(4, 6), 16),
  };
}

function channel(value: number): number {
  const c = value / 255;
  return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
}

/** Relative luminance as defined by WCAG 2.2. */
export function relativeLuminance(colour: Rgb): number {
  return 0.2126 * channel(colour.r) + 0.7152 * channel(colour.g) + 0.0722 * channel(colour.b);
}

/** WCAG contrast ratio of two hex colours, from 1 to 21. Order does not matter. */
export function contrastRatio(first: string, second: string): number {
  const a = relativeLuminance(parseHex(first));
  const b = relativeLuminance(parseHex(second));
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}
