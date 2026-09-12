import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

// jsdom gives import.meta.url an http scheme, so resolve from the project root.
const tokens = readFileSync(resolve(process.cwd(), "src/styles/tokens.css"), "utf8");

describe("design tokens", () => {
  it("defines the status colors used across the console", () => {
    for (const token of ["--status-active", "--status-stale", "--status-retired"]) {
      expect(tokens).toContain(token);
    }
  });

  it("has a dark mode for every surface token", () => {
    const [, dark] = tokens.split("@media (prefers-color-scheme: dark)");
    for (const token of ["--paper", "--surface", "--ink", "--rule", "--primary"]) {
      expect(dark).toContain(token);
    }
  });

  it("disables motion when the viewer asks for less", () => {
    expect(tokens).toContain("prefers-reduced-motion");
    expect(tokens.slice(tokens.indexOf("prefers-reduced-motion"))).toContain("--transition: 0ms");
  });
});
