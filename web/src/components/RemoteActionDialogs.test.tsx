import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { CollectLogsDialog, WipeDialog } from "./RemoteActionDialogs";

const fetchMock = vi.fn();

beforeEach(() => {
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
