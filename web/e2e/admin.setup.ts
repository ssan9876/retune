import { expect, seeded, signIn, test } from "./fixtures";

// Signs the seeded admin in once; every other test starts from this session.
test("sign in as the seeded admin", async ({ page }) => {
  await signIn(page, seeded().admin);
  await expect(page.getByRole("button", { name: `Account: ${seeded().admin.email}` })).toBeVisible();
  await page.context().storageState({ path: "e2e/.state/admin.json" });
});
