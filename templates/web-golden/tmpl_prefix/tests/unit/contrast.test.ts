import { describe, expect, it } from "vitest";
import { contrastRatio, parseHex, relativeLuminance } from "../../src/lib/contrast.ts";

describe("parseHex", () => {
  it("reads six-digit colours", () => {
    expect(parseHex("#0a55c2")).toEqual({ r: 10, g: 85, b: 194 });
  });

  it("reads three-digit colours and ignores case", () => {
    expect(parseHex("#FfF")).toEqual({ r: 255, g: 255, b: 255 });
  });

  it("rejects text that is not a hex colour", () => {
    expect(() => parseHex("red")).toThrow(/not a hex colour/);
    expect(() => parseHex("#12345")).toThrow(/not a hex colour/);
  });
});

describe("relativeLuminance", () => {
  it("is 0 for black and 1 for white", () => {
    expect(relativeLuminance({ r: 0, g: 0, b: 0 })).toBe(0);
    expect(relativeLuminance({ r: 255, g: 255, b: 255 })).toBe(1);
  });

  it("matches the WCAG value for mid grey", () => {
    expect(relativeLuminance({ r: 119, g: 119, b: 119 })).toBeCloseTo(0.1845, 4);
  });
});

describe("contrastRatio", () => {
  it("is 21 for black on white, in either order", () => {
    expect(contrastRatio("#000000", "#ffffff")).toBeCloseTo(21, 5);
    expect(contrastRatio("#ffffff", "#000")).toBeCloseTo(21, 5);
  });

  it("is 1 for a colour on itself", () => {
    expect(contrastRatio("#0a55c2", "#0a55c2")).toBe(1);
  });

  it("matches the known ratio of #777 on white", () => {
    expect(contrastRatio("#777777", "#ffffff")).toBeCloseTo(4.48, 2);
  });
});
