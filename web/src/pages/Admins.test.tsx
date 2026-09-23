import { render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Admins from "./Admins";

const fetchMock = vi.fn();
let canWrite = false;

vi.mock("../session/SessionContext", () => ({
  useSession: () => ({ admin: { role: canWrite ? "admin" : "read_only" }, canWrite }),
}));

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
  canWrite = false;
  fetchMock.mockImplementation(() =>
    Promise.resolve(
      new Response(
        JSON.stringify({
          items: [
            {
              id: "a1",
              email: "ops@example.com",
              role: "admin",
              totp_enabled: true,
              disabled: false,
              created_at: "2026-09-12T12:00:00Z",
              auth_source: "local",
            },
            {
              id: "a2",
              email: "ada@example.com",
              role: "read_only",
              totp_enabled: false,
              disabled: false,
              created_at: "2026-09-22T12:00:00Z",
              auth_source: "oidc",
            },
          ],
          total: 2,
          limit: 50,
          offset: 0,
        }),
        { headers: { "Content-Type": "application/json" } },
      ),
    ),
  );
});

describe("Admins", () => {
  it("shows accounts but no controls for a read-only admin", async () => {
    render(<Admins />);
    expect(await screen.findByText("ops@example.com")).toBeInTheDocument();
    expect(screen.getByText("On")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add admin" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Change password" })).not.toBeInTheDocument();
  });

  it("offers management to an admin", async () => {
    canWrite = true;
    render(<Admins />);
    expect(await screen.findByRole("button", { name: "Add admin" })).toBeInTheDocument();
    const row = screen.getByText("ops@example.com").closest("tr") as HTMLElement;
    expect(within(row).getByRole("button", { name: "Turn off authenticator" })).toBeInTheDocument();
    expect(within(row).getByRole("button", { name: "Disable account" })).toBeInTheDocument();
  });

  it("marks SSO accounts, and offers them no password or authenticator", async () => {
    canWrite = true;
    render(<Admins />);
    const row = (await screen.findByText("ada@example.com")).closest("tr") as HTMLElement;
    expect(within(row).getByText("SSO")).toBeInTheDocument();
    expect(within(row).getByText("at the identity provider")).toBeInTheDocument();
    expect(within(row).queryByRole("button", { name: "Change password" })).not.toBeInTheDocument();
    expect(within(row).queryByRole("button", { name: /authenticator/ })).not.toBeInTheDocument();
    expect(within(row).getByRole("button", { name: "Disable account" })).toBeInTheDocument();
  });
});
