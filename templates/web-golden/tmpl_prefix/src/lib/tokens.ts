/** Custom properties of one theme, for example { "--color-text": "#1b1f24" }. */
export type TokenMap = Readonly<Record<string, string>>;

export interface ColourThemes {
  readonly light: TokenMap;
  readonly dark: TokenMap;
  readonly systemDark: TokenMap;
}

/** Selectors used in design/tokens/tokens.css. */
export const LIGHT_SELECTOR = ":root";
export const DARK_SELECTOR = ':root[data-theme="dark"]';
export const SYSTEM_DARK_SELECTOR = ':root:not([data-theme="light"])';

/**
 * Reads the custom properties of the first rule whose selector is exactly
 * `selector`. The rule body must not contain nested rules.
 */
export function readDeclarations(css: string, selector: string): Record<string, string> {
  const withoutComments = css.replace(/\/\*[\s\S]*?\*\//g, "");
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const rule = new RegExp(`(?:^|[\\s}])${escaped}\\s*\\{([^{}]*)\\}`).exec(withoutComments);
  const body = rule?.[1];
  if (body === undefined) {
    throw new Error(`There is no rule for ${selector} in the tokens file.`);
  }
  const result: Record<string, string> = {};
  for (const match of body.matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)) {
    const [, name, value] = match;
    if (name !== undefined && value !== undefined) {
      result[name] = value.trim();
    }
  }
  return result;
}

function colourTokens(tokens: Record<string, string>): TokenMap {
  return Object.fromEntries(Object.entries(tokens).filter(([name]) => name.startsWith("--color-")));
}

/** The colour tokens of each theme in design/tokens/tokens.css. */
export function readColourTokens(css: string): ColourThemes {
  return {
    light: colourTokens(readDeclarations(css, LIGHT_SELECTOR)),
    dark: colourTokens(readDeclarations(css, DARK_SELECTOR)),
    systemDark: colourTokens(readDeclarations(css, SYSTEM_DARK_SELECTOR)),
  };
}
