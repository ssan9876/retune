import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import ApiTokens from "./ApiTokens";

const fetchMock = vi.fn();
let canWrite = true;

vi.mock("../session/SessionContext", () => ({
  useSession: () => ({ admin: { role: canWrite ? "admin" : "read_only" }, canWrite }),
}));

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const live = {
  id: "t1",
  name: "ServiceNow",
  role: "admin",
  created_by: "ops@example.com",
  created_at: "2026-09-22T00:00:00Z",
  expires_at: "2099-01-01T00:00:00Z",
};
const revoked = { ...live, id: "t2", name: "Old script", role: "read_only", revoked_at: "2026-09-22T01:00:00Z" };

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
  canWrite = true;
});

describe("ApiTokens", () => {
  it("lists tokens and offers revoke only for live ones", async () => {
    fetchMock.mockImplementation(() => Promise.resolve(json({ items: [live, revoked], total: 2 })));
    render(<ApiTokens />);
    expect(await screen.findByText("ServiceNow")).toBeInTheDocument();
    expect(screen.getByText("revoked")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Revoke" })).toHaveLength(1);
  });

  it("shows a new token once, with its secret", async () => {
    const posted: Record<string, unknown>[] = [];
    fetchMock.mockImplementation((_url: string, init?: { method?: string; body?: string }) => {
      if (init?.method === "POST") {
        posted.push(JSON.parse(init.body ?? "{}"));
        return Promise.resolve(json({ token: "rtk_secret-value", api_token: { ...live, name: "Nightly report" } }, 201));
      }
      return Promise.resolve(json({ items: [], total: 0 }));
    });
    render(<ApiTokens />);
    await screen.findByText("No API tokens yet.");

    await userEvent.click(screen.getByRole("button", { name: "Create token" }));
    await userEvent.type(screen.getByLabelText("Name"), "Nightly report");
    await userEvent.click(screen.getAllByRole("button", { name: "Create token" }).at(-1) as HTMLElement);

    expect(posted[0]).toEqual({ name: "Nightly report", role: "read_only", expires_in_days: 90 });
    expect(await screen.findByText("rtk_secret-value")).toBeInTheDocument();
    expect(screen.getByText(/cannot be shown again/)).toBeInTheDocument();
  });

  it("offers nothing to change for a read-only admin", async () => {
    canWrite = false;
    fetchMock.mockImplementation(() => Promise.resolve(json({ items: [live], total: 1 })));
    render(<ApiTokens />);
    await screen.findByText("ServiceNow");
    expect(screen.queryByRole("button", { name: "Create token" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Revoke" })).not.toBeInTheDocument();
  });
});
