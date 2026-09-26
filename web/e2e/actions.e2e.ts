import { expect, seeded, test } from "./fixtures";

test("a command queued from a device appears on Commands with its hostname", async ({ page }) => {
  const { devices } = seeded();
  const device = devices.compliant;
  await page.goto(`/devices/${device.id}`);
  await page.getByRole("region", { name: "Device actions" }).getByRole("button", { name: "Refresh inventory" }).click();
  await expect(page.getByText(`Inventory refresh queued for ${device.hostname}.`)).toBeVisible();

  await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "Commands" }).click();
  // Newest first; a reused local server may hold earlier runs' commands too.
  const row = page.getByRole("row").filter({ hasText: "refresh inventory" }).filter({ hasText: device.hostname });
  await expect(row.first()).toContainText("just now");
  await expect(row.first()).toContainText("queued");

  // Filtering by status keeps it while it is queued and drops it otherwise.
  await page.getByRole("combobox", { name: "Status" }).selectOption("queued");
  await expect(row.first()).toBeVisible();
  await page.getByRole("combobox", { name: "Status" }).selectOption("succeeded");
  await expect(row).toHaveCount(0);
});

test("a new enrollment token shows the msiexec line to install with", async ({ page }) => {
  const label = `e2e token ${Date.now()}`;
  await page.goto("/tokens");
  await page.getByRole("button", { name: "Create token" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Label").fill(label);
  await dialog.getByRole("button", { name: /create/i }).click();

  const install = page.getByText(/^msiexec \/i retune-agent\.msi /);
  await expect(install).toBeVisible();
  const line = (await install.textContent()) ?? "";
  expect(line).toContain(`SERVER_URL=${seeded().base_url}`);
  expect(line).toMatch(/ENROLL_TOKEN=\S{16,} /);
  expect(line).toMatch(/\/qn$/);

  await expect(page.getByRole("row").filter({ hasText: label })).toBeVisible();
});

test("opening a remote shell lands on its session, waiting for the device", async ({ page }) => {
  const { devices } = seeded();
  const device = devices.noncompliant;
  const reason = `E2E-${Date.now()} browser test`;
  await page.goto(`/devices/${device.id}`);
  await page.getByRole("button", { name: "Open remote shell…" }).click();

  const dialog = page.getByRole("dialog", { name: `Remote shell on ${device.hostname}` });
  const start = dialog.getByRole("button", { name: "Start session" });
  await expect(start).toBeDisabled(); // a reason is required
  await dialog.getByLabel("Reason").fill(reason);
  await start.click();

  await expect(page).toHaveURL(/\/remote-sessions\/[0-9a-f-]{36}$/);
  await expect(page.getByText("waiting for the device to join")).toBeVisible();
  await expect(page.getByText(reason)).toBeVisible();

  // The session is listed on the device it was opened on.
  await page.goto(`/devices/${device.id}`);
  await expect(page.getByText(reason)).toBeVisible();
});
