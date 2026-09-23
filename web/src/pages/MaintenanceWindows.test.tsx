import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import MaintenanceWindows, { describeWindow } from "./MaintenanceWindows";

const fetchMock = vi.fn();

vi.mock("../session/SessionContext", () => ({
  useSession: () => ({ admin: { role: "admin" }, canWrite: true }),
}));

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const weekend = {
  id: "w1",
  name: "Weekend nights",
  description: "",
  days: ["sat", "sun"],
  start: "22:00",
  duration_minutes: 270,
  created_by: "ops@example.com",
};

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
});

describe("describeWindow", () => {
  it("says when a window is open", () => {
    expect(describeWindow(weekend)).toBe("Sat, Sun, from 22:00 for 4 h 30 min");
    expect(describeWindow({ days: [], start: "02:00", duration_minutes: 60 })).toBe("Every day, from 02:00 for 1 h");
  });
});

describe("MaintenanceWindows", () => {
  it("lists windows with where they are assigned", async () => {
    fetchMock.mockImplementation((url: string) =>
      Promise.resolve(
        String(url).includes("/assignments")
          ? json({ items: [{ id: "a1", group_name: "Kiosks", mode: "include" }] })
          : json({ items: [weekend], total: 1 }),
      ),
    );
    render(<MaintenanceWindows />);
    expect(await screen.findByText("Weekend nights")).toBeInTheDocument();
    expect(screen.getByText("Sat, Sun, from 22:00 for 4 h 30 min")).toBeInTheDocument();
    expect(await screen.findByText(/Kiosks/)).toBeInTheDocument();
  });

  it("creates a window", async () => {
    const posted: unknown[] = [];
    fetchMock.mockImplementation((_url: string, init?: { method?: string; body?: string }) => {
      if (init?.method === "POST") {
        posted.push(JSON.parse(init.body ?? "{}"));
        return Promise.resolve(json(weekend, 201));
      }
      return Promise.resolve(json({ items: [], total: 0 }));
    });
    render(<MaintenanceWindows />);
    await screen.findByText("No maintenance windows yet.");
    await userEvent.click(screen.getByRole("button", { name: "Create window" }));
    await userEvent.type(screen.getByLabelText("Name"), "Weeknights");
    await userEvent.click(screen.getByLabelText("Mon"));
    await userEvent.click(screen.getAllByRole("button", { name: "Create window" }).at(-1) as HTMLElement);
    await waitFor(() =>
      expect(posted[0]).toEqual({
        name: "Weeknights",
        description: "",
        days: ["mon"],
        start: "22:00",
        duration_minutes: 240,
      }),
    );
  });
});
