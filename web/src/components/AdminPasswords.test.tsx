import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AdminPasswords } from "./AdminPasswords";

const fetchMock = vi.fn();

vi.mock("../session/SessionContext", () => ({
  useSession: () => ({ admin: { role: "admin" }, canWrite: true }),
}));

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const item = {
  id: "p1",
  device_id: "d1",
  hostname: "LAPTOP",
  account: "Administrator",
  state: "active",
  command_id: "c1",
  created_at: "2026-09-22T10:00:00Z",
  activated_at: "2026-09-22T10:00:05Z",
};

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
});

describe("AdminPasswords", () => {
  it("lists passwords without showing any", async () => {
    fetchMock.mockImplementation(() => Promise.resolve(json({ items: [item] })));
    render(<AdminPasswords deviceId="d1" />);
    expect(await screen.findByText("Administrator")).toBeInTheDocument();
    expect(screen.getByText("In use")).toBeInTheDocument();
    expect(screen.queryByText(/Correct-Horse/)).toBeNull();
  });

  it("needs a reason, then reveals the password", async () => {
    fetchMock.mockImplementation((url: string) =>
      String(url).includes("/reveal")
        ? Promise.resolve(json({ password: "Correct-Horse-Battery-9", admin_password: item }))
        : Promise.resolve(json({ items: [item] })),
    );
    render(<AdminPasswords deviceId="d1" />);
    await userEvent.click(await screen.findByRole("button", { name: "Show the password" }));
    const confirm = screen.getAllByRole("button", { name: "Show the password" }).at(-1)!;
    expect(confirm).toBeDisabled();
    await userEvent.type(screen.getByLabelText("Reason"), "ticket 42");
    await userEvent.click(confirm);
    expect(await screen.findByText("Correct-Horse-Battery-9")).toBeInTheDocument();
    const call = fetchMock.mock.calls.find(([url]) => String(url).includes("/reveal"));
    expect(JSON.parse(String(call?.[1]?.body))).toEqual({ reason: "ticket 42" });
  });

  it("renders nothing for a device with no passwords", async () => {
    fetchMock.mockImplementation(() => Promise.resolve(json({ items: [] })));
    const { container } = render(<AdminPasswords deviceId="d1" />);
    await new Promise((r) => setTimeout(r, 0));
    expect(container).toBeEmptyDOMElement();
  });
});
