import { defineConfig } from "@playwright/test";

// Tests run against the production build, the way people get the app.
export default defineConfig({
  testDir: "tests/e2e",
  timeout: 60_000,
  expect: { timeout: 20_000 },
  fullyParallel: true,
  reporter: [["list"]],
  use: { baseURL: "http://localhost:4173", channel: "chrome", trace: "retain-on-failure" },
  webServer: { command: "npm run build && npm run preview", url: "http://localhost:4173", timeout: 180_000, reuseExistingServer: false },
});
