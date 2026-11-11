import { defineConfig, devices } from "@playwright/test";

// Browser tests run against the built site, served by "vite preview" on this machine.
const port = 4173;

export default defineConfig({
  testDir: "tests/e2e",
  testMatch: "**/*.e2e.ts",
  forbidOnly: true,
  reporter: "list",
  use: {
    baseURL: `http://localhost:${port}`,
  },
  projects: [
    {
      name: "chromium",
      // The "chromium" channel uses the full Chromium build in headless mode.
      use: { ...devices["Desktop Chrome"], channel: "chromium" },
    },
  ],
  webServer: {
    command: `pnpm preview --port ${port} --strictPort`,
    url: `http://localhost:${port}`,
    reuseExistingServer: false,
  },
});
