/** The choices offered by the theme switch. "auto" follows the system setting. */
export const THEME_CHOICES = ["auto", "light", "dark"] as const;
export type ThemeChoice = (typeof THEME_CHOICES)[number];

/** localStorage key. src/components/theme-init.html reads the same key. */
export const THEME_STORAGE_KEY = "theme";

/** Reads a stored value; anything unknown or missing means "auto". */
export function parseChoice(stored: string | null): ThemeChoice {
  return THEME_CHOICES.find((choice) => choice === stored) ?? "auto";
}

/** The data-theme value for <html>, or null to remove the attribute. */
export function dataThemeFor(choice: ThemeChoice): "light" | "dark" | null {
  return choice === "auto" ? null : choice;
}

export interface ThemeState {
  readonly dataTheme: "light" | "dark" | null;
  /** The value to store, or null to remove the stored value. */
  readonly stored: ThemeChoice | null;
  readonly pressed: Readonly<Record<ThemeChoice, boolean>>;
}

/** The part of localStorage the theme switch uses. */
export type ChoiceStorage = Pick<Storage, "getItem" | "setItem" | "removeItem">;

/**
 * The stored choice, or null when there is none. `storage` is a function because in some
 * browsers even reading `localStorage` throws when storage is blocked; that counts as
 * nothing stored.
 */
export function readStoredChoice(storage: () => ChoiceStorage): string | null {
  try {
    return storage().getItem(THEME_STORAGE_KEY);
  } catch {
    return null;
  }
}

/**
 * Stores the choice (null removes it). Returns false when storage is blocked or full:
 * the choice then lasts only until the page is left, which is all a visitor can expect.
 */
export function writeStoredChoice(storage: () => ChoiceStorage, value: string | null): boolean {
  try {
    if (value === null) {
      storage().removeItem(THEME_STORAGE_KEY);
    } else {
      storage().setItem(THEME_STORAGE_KEY, value);
    }
    return true;
  } catch {
    return false;
  }
}

/** Everything the page should show after the visitor picks `choice`. */
export function nextState(choice: ThemeChoice): ThemeState {
  return {
    dataTheme: dataThemeFor(choice),
    stored: choice === "auto" ? null : choice,
    pressed: { auto: choice === "auto", light: choice === "light", dark: choice === "dark" },
  };
}
