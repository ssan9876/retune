import { test as base, expect, type Page } from "@playwright/test";
import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";

export interface Account {
  email: string;
  password: string;
  totp_secret?: string;
}

export interface Seeded {
  base_url: string;
  admin: Account;
  totp_admin: Account;
  devices: Record<"compliant" | "noncompliant" | "stale" | "retired", { id: string; hostname: string }>;
}

let cached: Seeded | undefined;

/** seeded is what test/console seeded. It is read on first use: the file is
 * written just before the server answers, after Playwright collects tests. */
export function seeded(): Seeded {
  cached ??= JSON.parse(readFileSync("e2e/.state/fixture.json", "utf8")) as Seeded;
  return cached;
}

// A 401 is how the console learns nobody is signed in, and how a wrong
// password comes back; the browser logs both. Anything else is a failure.
const expectedConsoleErrors = [/Failed to load resource: the server responded with a status of 401/];

/** test fails any test whose page throws or logs an unexpected console error.
 * A test that provokes one on purpose names it with allowConsoleErrors. */
export const test = base.extend<{ page: Page; allowConsoleErrors: RegExp[] }>({
  allowConsoleErrors: [[], { option: true }],
  page: async ({ page, allowConsoleErrors }, use) => {
    const problems: string[] = [];
    const allowed = [...expectedConsoleErrors, ...allowConsoleErrors];
    page.on("pageerror", (err) => problems.push(`uncaught: ${err.message}`));
    page.on("console", (msg) => {
      if (msg.type() !== "error") return;
      if (allowed.some((re) => re.test(msg.text()))) return;
      problems.push(`console.error: ${msg.text()}`);
    });
    await use(page);
    expect(problems, "the page logged errors").toEqual([]);
  },
});

export { expect };

/** signIn fills in the login form; it does not wait for the result. */
export async function signIn(page: Page, account: Account) {
  await page.goto("/");
  await page.getByLabel("Email").fill(account.email);
  await page.getByLabel("Password").fill(account.password);
  await page.getByRole("button", { name: "Sign in" }).click();
}

/** totp is the current RFC 6238 code for a base32 secret (SHA-1, 6 digits, 30 s). */
export function totp(secret: string, now = Date.now()): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of secret.replace(/=+$/, "").toUpperCase()) {
    bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  }
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(now / 1000 / 30)));
  const mac = createHmac("sha1", key).update(counter).digest();
  const offset = mac[mac.length - 1] & 0xf;
  const code = (mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return code.toString().padStart(6, "0");
}
