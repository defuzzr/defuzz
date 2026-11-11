import { describe, expect, it } from "vitest";
import { yearText } from "../../src/lib/year.ts";

describe("yearText", () => {
  it("returns the four-digit year of a date", () => {
    expect(yearText(new Date(2031, 5, 15))).toBe("2031");
  });

  it("uses local time, so the first moment of a year belongs to that year", () => {
    expect(yearText(new Date(2030, 0, 1, 0, 0, 0))).toBe("2030");
  });
});
