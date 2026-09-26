import type { Page } from "@playwright/test";

import { expect, seeded, test } from "./fixtures";

/** hostnames lists the seeded devices the table shows, in order. Other tests
 * never add devices, so the seeded four are the whole fleet. */
async function hostnames(page: Page) {
  const rows = page.getByRole("table").getByRole("link", { name: /^E2E-/ });
  await expect(rows.first()).toBeVisible();
  return rows.allTextContents();
}

test("the device list filters by fleet status", async ({ page }) => {
  const { devices } = seeded();
  await page.goto("/devices");
  const filters = page.getByRole("group", { name: "Filter devices by fleet status" });

  await expect(filters.getByRole("button", { name: /^All/ })).toHaveAttribute("aria-pressed", "true");
  expect(await hostnames(page)).toEqual([
    devices.compliant.hostname,
    devices.noncompliant.hostname,
    devices.retired.hostname,
    devices.stale.hostname,
  ]);

  await filters.getByRole("button", { name: "Active, 2 devices" }).click();
  await expect(page).toHaveURL(/status=active/);
  await expect.poll(() => hostnames(page)).toEqual([devices.compliant.hostname, devices.noncompliant.hostname]);

  await filters.getByRole("button", { name: "Stale, 1 device" }).click();
  await expect.poll(() => hostnames(page)).toEqual([devices.stale.hostname]);
  await expect(page.getByRole("row", { name: new RegExp(devices.stale.hostname) })).toContainText("stale");

  await filters.getByRole("button", { name: "Retired, 1 device" }).click();
  await expect.poll(() => hostnames(page)).toEqual([devices.retired.hostname]);

  // A filtered URL is a link someone can share: a fresh load keeps the filter.
  await page.reload();
  await expect(filters.getByRole("button", { name: "Retired, 1 device" })).toHaveAttribute("aria-pressed", "true");
  await expect.poll(() => hostnames(page)).toEqual([devices.retired.hostname]);
});

test("the overview's non-compliant tile lists the failing device", async ({ page }) => {
  const { devices } = seeded();
  await page.goto("/");
  await page.getByRole("link", { name: /^Non-compliant 1/ }).click();
  await expect(page).toHaveURL(/\/devices\?compliance=non_compliant/);
  await expect.poll(() => hostnames(page)).toEqual([devices.noncompliant.hostname]);
  await expect(page.getByText(/Showing non compliant/)).toBeVisible();
});

test("search narrows the list", async ({ page }) => {
  const { devices } = seeded();
  await page.goto("/devices");
  await page.getByRole("searchbox", { name: "Search devices" }).fill("stale");
  await expect.poll(() => hostnames(page)).toEqual([devices.stale.hostname]);
});

test("a device's page shows what its agent reported", async ({ page }) => {
  const { devices } = seeded();
  await page.goto("/devices");
  await page.getByRole("link", { name: devices.noncompliant.hostname }).click();

  await expect(page).toHaveURL(`/devices/${devices.noncompliant.id}`);
  await expect(page.getByRole("heading", { name: devices.noncompliant.hostname, level: 1 })).toBeVisible();
  await expect(page.getByRole("definition").filter({ hasText: "Retune Simulated" })).toBeVisible();
  await expect(page.getByRole("definition").filter({ hasText: "E2E-SN-1" })).toBeVisible();
  await expect(page.getByText("Overall: non compliant")).toBeVisible();
  await expect(page.getByRole("listitem").filter({ hasText: "BitLocker required" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Device actions" })).toBeVisible();
});

test.describe(() => {
  test.use({ allowConsoleErrors: [/status of 404/] });
  test("an unknown device says so instead of breaking", async ({ page }) => {
    await page.goto("/devices/00000000-0000-7000-8000-000000000000");
    await expect(page.getByRole("alert")).toBeVisible();
  });
});
