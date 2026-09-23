import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { CollectLogsDialog, WipeDialog } from "./RemoteActionDialogs";

const fetchMock = vi.fn();
const session = { signingRequired: false };

vi.mock("../session/SessionContext", () => ({
  useSession: () => ({ admin: { role: "admin" }, canWrite: true, signingRequired: session.signingRequired }),
}));

beforeEach(() => {
  session.signingRequired = false;
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
  fetchMock.mockResolvedValue(
    new Response(JSON.stringify({ commands: [{ id: "c1", device_id: "d1" }] }), {
      status: 201,
      headers: { "Content-Type": "application/json" },
    }),
  );
});

function posted(): Record<string, unknown> {
  const call = fetchMock.mock.calls.find(([url]) => String(url).includes("/commands"));
  return JSON.parse(String(call?.[1]?.body));
}

describe("WipeDialog", () => {
  it("stays disabled until the hostname matches and there is a reason", async () => {
    const onQueued = vi.fn();
    render(<WipeDialog deviceId="d1" hostname="LAPTOP-042" open onClose={() => {}} onQueued={onQueued} />);
    const button = screen.getByRole("button", { name: "Wipe LAPTOP-042" });
    expect(button).toBeDisabled();

    await userEvent.type(screen.getByLabelText("Confirm hostname"), "LAPTOP-043");
    await userEvent.type(screen.getByLabelText("Reason"), "stolen");
    expect(button).toBeDisabled();

    await userEvent.clear(screen.getByLabelText("Confirm hostname"));
    await userEvent.type(screen.getByLabelText("Confirm hostname"), "laptop-042");
    expect(button).toBeEnabled();

    await userEvent.click(button);
    expect(posted()).toEqual({
      device_ids: ["d1"],
      type: "wipe",
      protected: false,
      confirm_hostname: "laptop-042",
      reason: "stolen",
    });
    expect(onQueued).toHaveBeenCalled();
  });

  it("stays open to say a wipe is waiting for approval", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ approval: { id: "a1", status: "pending" } }), {
        status: 202,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const onClose = vi.fn();
    render(<WipeDialog deviceId="d1" hostname="PC-1" open onClose={onClose} onQueued={() => {}} />);
    await userEvent.type(screen.getByLabelText("Confirm hostname"), "PC-1");
    await userEvent.type(screen.getByLabelText("Reason"), "lost");
    await userEvent.click(screen.getByRole("button", { name: "Wipe PC-1" }));
    expect(await screen.findByText(/Sent for approval/)).toBeInTheDocument();
    expect(onClose).not.toHaveBeenCalled();
  });

  it("warns plainly what a wipe does", () => {
    render(<WipeDialog deviceId="d1" hostname="PC-1" open onClose={() => {}} onQueued={() => {}} />);
    expect(screen.getByRole("alert")).toHaveTextContent(/can't be undone/i);
  });
});

describe("CollectLogsDialog", () => {
  it("queues collect_logs with the hours chosen", async () => {
    render(<CollectLogsDialog deviceId="d1" open onClose={() => {}} onQueued={() => {}} />);
    const hours = screen.getByLabelText(/Event logs from the last/);
    await userEvent.clear(hours);
    await userEvent.type(hours, "48");
    await userEvent.click(screen.getByRole("button", { name: "Collect logs" }));
    expect(posted()).toEqual({ device_ids: ["d1"], type: "collect_logs", hours: 48 });
  });

  it("refuses more than a week", async () => {
    render(<CollectLogsDialog deviceId="d1" open onClose={() => {}} onQueued={() => {}} />);
    const hours = screen.getByLabelText(/Event logs from the last/);
    await userEvent.clear(hours);
    await userEvent.type(hours, "200");
    expect(screen.getByRole("button", { name: "Collect logs" })).toBeDisabled();
  });
});

describe("WipeDialog with signing required", () => {
  it("needs a signed order for this device, and sends it", async () => {
    session.signingRequired = true;
    render(<WipeDialog deviceId="d1" hostname="PC-1" open onClose={() => {}} onQueued={() => {}} />);
    await userEvent.type(screen.getByLabelText("Confirm hostname"), "PC-1");
    await userEvent.type(screen.getByLabelText("Reason"), "lost");
    const button = screen.getByRole("button", { name: "Wipe PC-1" });
    expect(button).toBeDisabled();
    expect(screen.getByText(/retune-sign sign-wipe --key operations.key --device d1/)).toBeInTheDocument();

    const field = screen.getByLabelText("Signed wipe order");
    const paste = (text: string) => {
      fireEvent.change(field, { target: { value: text } });
    };
    // Another device's order doesn't fit.
    paste(JSON.stringify({ device: "d2", protected: false, expires: "2026-09-23T14:00:00Z", key_id: "k", signature: "s" }));
    expect(button).toBeDisabled();

    paste(JSON.stringify({ device: "d1", protected: true, expires: "2026-09-23T14:00:00Z", key_id: "k", signature: "s" }));
    expect(button).toBeEnabled();
    await userEvent.click(button);
    expect(posted()).toEqual({
      device_ids: ["d1"],
      type: "wipe",
      protected: true,
      confirm_hostname: "PC-1",
      reason: "lost",
      expires: "2026-09-23T14:00:00Z",
      signature: { key_id: "k", signature: "s" },
    });
  });
});

