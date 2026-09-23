import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Reports, { describeSchedule } from "./Reports";

const fetchMock = vi.fn();

vi.mock("../session/SessionContext", () => ({
  useSession: () => ({ admin: { role: "admin" }, canWrite: true }),
}));

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const weekly = {
  id: "r1",
  name: "Failing devices",
  kind: "compliance",
  policy_id: "p1",
  state: "non_compliant",
  recipients: ["it@example.com"],
  frequency: "weekly",
  weekday: 1,
  hour: 7,
  timezone: "Europe/London",
  enabled: true,
  next_run_at: "2026-09-28T06:00:00Z",
  last_error: "relay refused",
};

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
});

describe("Reports", () => {
  it("describes a schedule", () => {
    expect(describeSchedule(weekly as never)).toBe("Every Monday at 07:00 Europe/London");
    expect(describeSchedule({ frequency: "daily", weekday: 0, hour: 18, timezone: "UTC" })).toBe(
      "Every day at 18:00 UTC",
    );
  });

  it("lists reports, with a failed last attempt, and sends one now", async () => {
    fetchMock.mockImplementation((url: string, init?: { method?: string }) =>
      Promise.resolve(init?.method === "POST" ? json(weekly) : json({ items: String(url).includes("/reports") ? [weekly] : [] })),
    );
    render(<Reports />);
    expect(await screen.findByText("Failing devices")).toBeInTheDocument();
    expect(screen.getByText("Every Monday at 07:00 Europe/London")).toBeInTheDocument();
    expect(screen.getByText(/Last attempt failed: relay refused/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Send now" }));
    await waitFor(() => {
      const call = fetchMock.mock.calls.find(([, init]) => init?.method === "POST");
      expect(String(call?.[0])).toContain("/reports/r1/send");
    });
    expect(await screen.findByText("Sent Failing devices to it@example.com.")).toBeInTheDocument();
  });

  it("schedules a device report", async () => {
    const posted: unknown[] = [];
    fetchMock.mockImplementation((_url: string, init?: { method?: string; body?: string }) => {
      if (init?.method === "POST") {
        posted.push(JSON.parse(init.body ?? "{}"));
        return Promise.resolve(json(weekly, 201));
      }
      return Promise.resolve(json({ items: [] }));
    });
    render(<Reports />);
    await screen.findByText("No scheduled reports yet.");
    await userEvent.click(screen.getByRole("button", { name: "Schedule report" }));
    await userEvent.type(screen.getByLabelText("Name"), "Fleet");
    await userEvent.type(screen.getByLabelText(/Send to/), "a@example.com, b@example.com");
    await userEvent.clear(screen.getByLabelText(/Time zone/));
    await userEvent.type(screen.getByLabelText(/Time zone/), "UTC");
    await userEvent.click(screen.getAllByRole("button", { name: "Schedule report" }).at(-1) as HTMLElement);
    await waitFor(() =>
      expect(posted[0]).toMatchObject({
        name: "Fleet",
        kind: "devices",
        recipients: ["a@example.com", "b@example.com"],
        frequency: "weekly",
        weekday: 1,
        hour: 7,
        timezone: "UTC",
        enabled: true,
      }),
    );
  });
});
