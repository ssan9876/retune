import { render, screen } from "@testing-library/react";
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
            },
          ],
          total: 1,
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
    expect(screen.getByRole("button", { name: "Turn off authenticator" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Disable account" })).toBeInTheDocument();
  });
});
