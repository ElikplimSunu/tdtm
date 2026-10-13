import { defineConfig } from "@playwright/test";

// Tests run against the production build, the way people get the app.
export default defineConfig({
  testDir: "tests/e2e",
  timeout: 120_000,
  expect: { timeout: 45_000 }, // each test starts its own Python engine; slow machines need time
  fullyParallel: true,
  workers: 3,
  reporter: [["list"]],
  use: { baseURL: `http://localhost:4173${process.env.BASE ?? "/"}`, channel: "chrome", trace: "retain-on-failure" },
  webServer: { command: "npm run build && npm run preview", url: `http://localhost:4173${process.env.BASE ?? "/"}`, timeout: 180_000, reuseExistingServer: false },
});
