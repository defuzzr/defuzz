import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { describe, expect, it } from "vitest";
import {
  type ChoiceStorage,
  dataThemeFor,
  nextState,
  parseChoice,
  readStoredChoice,
  THEME_CHOICES,
  THEME_STORAGE_KEY,
  writeStoredChoice,
} from "../../src/lib/theme.ts";

/** A storage like localStorage, kept in a Map. */
function memoryStorage(): ChoiceStorage & { readonly items: Map<string, string> } {
  const items = new Map<string, string>();
  return {
    items,
    getItem: (key) => items.get(key) ?? null,
    setItem: (key, value) => {
      items.set(key, value);
    },
    removeItem: (key) => {
      items.delete(key);
    },
  };
}

/** Storage that the browser blocks: every use throws, as localStorage does then. */
const blocked = (): ChoiceStorage => {
  throw new DOMException("The operation is insecure.", "SecurityError");
};

describe("the stored choice", () => {
  it("is written, read back and removed", () => {
    const storage = memoryStorage();
    expect(writeStoredChoice(() => storage, "dark")).toBe(true);
    expect(storage.items.get(THEME_STORAGE_KEY)).toBe("dark");
    expect(readStoredChoice(() => storage)).toBe("dark");
    expect(writeStoredChoice(() => storage, null)).toBe(true);
    expect(storage.items.has(THEME_STORAGE_KEY)).toBe(false);
    expect(readStoredChoice(() => storage)).toBeNull();
  });

  it("is simply not kept when storage is blocked or full, and nothing throws", () => {
    expect(readStoredChoice(blocked)).toBeNull();
    expect(writeStoredChoice(blocked, "light")).toBe(false);
    expect(writeStoredChoice(blocked, null)).toBe(false);
    const full: ChoiceStorage = {
      ...memoryStorage(),
      setItem: () => {
        throw new DOMException("The quota has been exceeded.", "QuotaExceededError");
      },
    };
    expect(writeStoredChoice(() => full, "dark")).toBe(false);
  });
});

describe("parseChoice", () => {
  it("accepts the three known choices", () => {
    for (const choice of THEME_CHOICES) {
      expect(parseChoice(choice)).toBe(choice);
    }
  });

  it("falls back to auto for missing or unknown values", () => {
    expect(parseChoice(null)).toBe("auto");
    expect(parseChoice("")).toBe("auto");
    expect(parseChoice("Dark")).toBe("auto");
    expect(parseChoice("purple")).toBe("auto");
  });
});

describe("dataThemeFor", () => {
  it("sets an explicit theme only for light and dark", () => {
    expect(dataThemeFor("light")).toBe("light");
    expect(dataThemeFor("dark")).toBe("dark");
    expect(dataThemeFor("auto")).toBeNull();
  });
});

describe("nextState", () => {
  it("presses only the chosen button and stores the choice", () => {
    expect(nextState("dark")).toEqual({
      dataTheme: "dark",
      stored: "dark",
      pressed: { auto: false, light: false, dark: true },
    });
  });

  it("removes the stored value for auto", () => {
    expect(nextState("auto")).toEqual({
      dataTheme: null,
      stored: null,
      pressed: { auto: true, light: false, dark: false },
    });
  });
});

// The inline script in theme-init.html runs before the stylesheet, so the page never
// flashes the wrong theme. It cannot import theme.ts, so check that it agrees with it.
describe("theme-init.html", () => {
  const html = readFileSync(
    new URL("../../src/components/theme-init.html", import.meta.url),
    "utf8",
  );
  const script = /<script>([\s\S]*?)<\/script>/.exec(html)?.[1] ?? "";

  function runInit(stored: string | null, storageThrows = false): string | undefined {
    const dataset: Record<string, string> = {};
    const localStorage = {
      getItem(key: string): string | null {
        if (storageThrows) {
          throw new Error("storage is blocked");
        }
        return key === THEME_STORAGE_KEY ? stored : null;
      },
    };
    runInNewContext(script, { localStorage, document: { documentElement: { dataset } } });
    return dataset["theme"];
  }

  it("contains a script", () => {
    expect(script.trim()).not.toBe("");
  });

  // Every valid choice plus values that look close to one.
  const invalid = [null, "", "sepia", "purple", "Dark", "LIGHT", " dark", "dark ", "auto ", "true"];
  const samples = [...THEME_CHOICES, ...invalid, ...THEME_CHOICES.map((c) => c.toUpperCase())];

  it("agrees with parseChoice and dataThemeFor", () => {
    for (const stored of samples) {
      expect(runInit(stored), String(stored)).toBe(dataThemeFor(parseChoice(stored)) ?? undefined);
    }
  });

  it("accepts exactly the explicit choices of THEME_CHOICES", () => {
    const accepted = samples.filter((stored) => runInit(stored) !== undefined);
    expect(accepted.sort()).toEqual(THEME_CHOICES.filter((c) => dataThemeFor(c) !== null).sort());
  });

  it("does nothing when storage is blocked", () => {
    expect(runInit("dark", true)).toBeUndefined();
  });
});
