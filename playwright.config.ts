import { defineConfig, devices } from "@playwright/test";

/**
 * E2E tests for the Hugo site. Assumes the site is already built (public/).
 * Run: npm run build && npm run test:e2e
 * Or use webServer to build and serve (see below).
 */
export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: "html",
  use: {
    baseURL: "http://localhost:1313",
    trace: "on-first-retry",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  // Serve the built site when running tests (optional: run "npm run build" first)
  webServer: {
    command: "npm run build && npx serve public -l 1313",
    url: "http://localhost:1313",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
