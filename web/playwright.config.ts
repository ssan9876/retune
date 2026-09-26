import { defineConfig, devices } from "@playwright/test";

// The browser tests run the built console against a real server and Postgres:
// test/console starts both, seeds simulated devices through the agent API and
// writes what it seeded to e2e/.state/fixture.json. Build the console first
// (`npm run build`); the server embeds whatever build is there.
const port = process.env.E2E_PORT ?? "18443";
const baseURL = `https://127.0.0.1:${port}`;

export default defineConfig({
  testDir: "e2e",
  outputDir: "e2e/.state/results",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: process.env.CI ? 2 : undefined,
  reporter: process.env.CI ? [["list"], ["html", { outputFolder: "e2e/.state/report", open: "never" }]] : "list",
  use: {
    baseURL,
    ignoreHTTPSErrors: true, // the server's own self-signed certificate
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "setup", testMatch: /.*\.setup\.ts/ },
    {
      name: "chromium",
      // *.spec.ts and *.test.ts belong to vitest; these are named apart from them.
      testMatch: /.*\.e2e\.ts/,
      use: { ...devices["Desktop Chrome"], storageState: "e2e/.state/admin.json" },
      dependencies: ["setup"],
    },
  ],
  webServer: {
    command: `go run ../test/console -addr 127.0.0.1:${port} -fixture e2e/.state/fixture.json`,
    url: `${baseURL}/healthz`,
    ignoreHTTPSErrors: true,
    // The first run compiles the server and pulls postgres:17-alpine.
    timeout: 300_000,
    reuseExistingServer: !process.env.CI,
    stdout: "pipe",
    stderr: "pipe",
  },
});
