import { expect, seeded, signIn, test, totp } from "./fixtures";

// These start signed out, whatever the project's stored session.
test.use({ storageState: { cookies: [], origins: [] } });

test("a password signs in, and signing out ends the session", async ({ page }) => {
  const { admin } = seeded();
  await signIn(page, admin);
  const account = page.getByRole("button", { name: `Account: ${admin.email}` });
  await expect(account).toBeVisible();
  await expect(page.getByRole("heading", { name: "Overview", level: 1 })).toBeVisible();

  await account.click();
  await page.getByRole("menuitem", { name: "Sign out" }).click();
  await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();

  // The session is gone on the server too, not just forgotten by the page.
  await page.reload();
  await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
});

test("a wrong password is refused", async ({ page }) => {
  await signIn(page, { ...seeded().admin, password: "not-the-password-at-all" });
  await expect(page.getByRole("alert")).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Overview" })).toHaveCount(0);
});

test("an account with an authenticator asks for its code", async ({ page }) => {
  test.setTimeout(90_000); // it may wait out one 30-second step, below
  const { totp_admin } = seeded();
  await signIn(page, totp_admin);
  const code = page.getByLabel("Authenticator code");
  await expect(code).toBeVisible();

  await code.fill(totp(totp_admin.totp_secret!));
  await page.getByRole("button", { name: "Sign in" }).click();
  const account = page.getByRole("button", { name: `Account: ${totp_admin.email}` });
  const refused = page.getByRole("alert").filter({ hasText: "invalid authenticator code" });
  await expect(account.or(refused)).toBeVisible();

  // A code is good once: the server refuses one from a time step already
  // signed in with. A retry, or a rerun against a reused server, inside the
  // same 30 seconds meets exactly that, so wait for the next step's code.
  if (await refused.isVisible()) {
    await page.waitForTimeout(30_000 - (Date.now() % 30_000) + 500);
    await code.fill(totp(totp_admin.totp_secret!));
    await page.getByRole("button", { name: "Sign in" }).click();
  }
  await expect(account).toBeVisible();
});

test("an authenticator code from the wrong time is refused", async ({ page }) => {
  const { totp_admin } = seeded();
  // Three steps ahead stays outside the one step of clock skew the server
  // allows even if a step boundary passes before the server checks it.
  const early = totp(totp_admin.totp_secret!, Date.now() + 90_000);
  await signIn(page, totp_admin);
  await page.getByLabel("Authenticator code").fill(early);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("alert")).toContainText("invalid authenticator code");
});
