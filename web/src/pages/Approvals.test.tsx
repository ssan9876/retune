import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Approvals from "./Approvals";

const fetchMock = vi.fn();

vi.mock("../session/SessionContext", () => ({
  useSession: () => ({ admin: { role: "admin", email: "me@example.com" }, canWrite: true }),
}));

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const theirs = {
  id: "a1",
  kind: "command",
  request: {},
  summary: "wipe PC-LOST: stolen",
  requested_by: "other@example.com",
  created_at: new Date().toISOString(),
  expires_at: "2099-01-01T00:00:00Z",
  status: "pending",
};
const mine = { ...theirs, id: "a2", summary: "run_powershell on 80 devices", requested_by: "me@example.com" };

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  vi.stubGlobal("confirm", () => true);
  fetchMock.mockReset();
});

describe("Approvals", () => {
  it("offers to approve someone else's request, and only to withdraw your own", async () => {
    fetchMock.mockImplementation(() => Promise.resolve(json({ items: [theirs, mine], total: 2 })));
    render(<Approvals />);
    expect(await screen.findByText("wipe PC-LOST: stolen")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Approve" })).toHaveLength(1);
    expect(screen.getByRole("button", { name: "Reject" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Withdraw" })).toBeInTheDocument();
    expect(String(fetchMock.mock.calls[0][0])).toContain("status=pending");
  });

  it("approves, and says so when the request could not be carried out", async () => {
    fetchMock.mockImplementation((_url: string, init?: { method?: string }) => {
      if (init?.method === "POST") {
        return Promise.resolve(
          json({ approval: { ...theirs, status: "failed", result: { error: "device is not active" } } }),
        );
      }
      return Promise.resolve(json({ items: [theirs], total: 1 }));
    });
    render(<Approvals />);
    await userEvent.click(await screen.findByRole("button", { name: "Approve" }));
    await waitFor(() => {
      const call = fetchMock.mock.calls.find(([, init]) => init?.method === "POST");
      expect(String(call?.[0])).toContain("/approvals/a1/approve");
    });
    expect(await screen.findByText(/could not be carried out: device is not active/)).toBeInTheDocument();
  });
});
