import { expect, test } from "@playwright/test";

test("the home page has one heading and a working skip link", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toHaveCount(1);
  await page.keyboard.press("Tab");
  const skip = page.getByRole("link", { name: "Skip to main content" });
  await expect(skip).toBeFocused();
  await expect(skip).toBeInViewport();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/#main$/);
  await expect(page.getByRole("main")).toBeFocused();
});

test("the shown skip link pushes the header down instead of covering it", async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 640 });
  await page.goto("/");
  await page.keyboard.press("Tab");
  const skip = await page.getByRole("link", { name: "Skip to main content" }).boundingBox();
  const header = await page.locator(".site-header").boundingBox();
  // The focus ring reaches 5px outside the link; leave at least 2px more.
  expect(skip).not.toBeNull();
  expect(header).not.toBeNull();
  expect((header?.y ?? 0) - ((skip?.y ?? 0) + (skip?.height ?? 0))).toBeGreaterThanOrEqual(7);
});

test("the theme switch sets and remembers the theme", async ({ page }) => {
  await page.goto("/");
  const dark = page.getByRole("button", { name: "Dark" });
  await expect(page.getByRole("button", { name: "Auto" })).toHaveAttribute("aria-pressed", "true");
  await dark.click();
  await expect(dark).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await page.goto("/about/");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await page.getByRole("button", { name: "Auto" }).click();
  await expect(page.locator("html")).not.toHaveAttribute("data-theme", /.*/);
});

test("the page fits a 360 pixel wide screen", async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 740 });
  for (const path of ["/", "/about/", "/404.html"]) {
    await page.goto(path);
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    expect(overflow, path).toBe(0);
  }
});

test("the header marks the current page", async ({ page }) => {
  await page.goto("/about/");
  const nav = page.getByRole("navigation", { name: "Main" });
  await expect(nav.getByRole("link", { name: "About" })).toHaveAttribute("aria-current", "page");
  await expect(nav.getByRole("link", { name: "Home" })).not.toHaveAttribute("aria-current", /.*/);
});

test("the home page image loads", async ({ page }) => {
  await page.goto("/");
  const loaded = await page
    .getByRole("img", { name: /Diagram of a page/ })
    .evaluate((img) => img instanceof HTMLImageElement && img.complete && img.naturalWidth > 0);
  expect(loaded).toBe(true);
});

test("the theme switch stays hidden without JavaScript", async ({ browser }) => {
  const context = await browser.newContext({ javaScriptEnabled: false });
  const page = await context.newPage();
  await page.goto("/");
  await expect(page.getByRole("button", { name: "Dark" })).toBeHidden();
  const nav = page.getByRole("navigation", { name: "Main" });
  await expect(nav.getByRole("link", { name: "About" })).toBeVisible();
  await context.close();
});
