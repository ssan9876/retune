import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { validComputerName } from "../components/RemoteActionDialogs";
import Provisioning from "./Provisioning";

const fetchMock = vi.fn();

vi.mock("../session/SessionContext", () => ({
  useSession: () => ({ admin: { role: "admin" }, canWrite: true }),
}));

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const groups = [
  { id: "g1", name: "Sales laptops", kind: "static" },
  { id: "g2", name: "All devices", kind: "builtin" },
];
const waiting = { id: "r1", serial: "PF3ABC12", device_name: "SALES-01", group_ids: ["g1"], created_at: "2026-09-23T00:00:00Z" };
const enrolled = { ...waiting, id: "r2", serial: "PF3XYZ99", device_name: "", group_ids: [], device_id: "d1", enrolled_at: new Date().toISOString() };

function renderPage() {
  return render(
    <MemoryRouter>
      <Provisioning />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
});

describe("validComputerName", () => {
  it("matches the server's rule", () => {
    expect(validComputerName("SALES-01")).toBe(true);
    for (const bad of ["", "12345", "-A", "A-", "ABCDEFGHIJKLMNOP", "A B", "A_B"]) expect(validComputerName(bad)).toBe(false);
  });
});

describe("Provisioning", () => {
  it("lists registrations, waiting and enrolled", async () => {
    fetchMock.mockImplementation((url: string) =>
      Promise.resolve(String(url).includes("/groups") ? json({ items: groups }) : json({ items: [waiting, enrolled], total: 2 })),
    );
    renderPage();
    expect(await screen.findByText("PF3ABC12")).toBeInTheDocument();
    expect(screen.getByText("SALES-01")).toBeInTheDocument();
    expect(await screen.findByText("Sales laptops")).toBeInTheDocument();
    expect(screen.getByText("waiting")).toBeInTheDocument();
    expect(screen.getByText(/^enrolled/)).toBeInTheDocument();
  });

  it("shows every problem in a CSV that was refused", async () => {
    fetchMock.mockImplementation((url: string, init?: { method?: string }) => {
      if (init?.method === "POST") {
        return Promise.resolve(
          json({ problems: [{ line: 2, message: "there is no group called Nobody" }, { line: 3, message: "serial must be 1 to 64 characters" }] }, 400),
        );
      }
      return Promise.resolve(String(url).includes("/groups") ? json({ items: groups }) : json({ items: [], total: 0 }));
    });
    renderPage();
    await screen.findByText("No devices registered yet.");
    await userEvent.click(screen.getByRole("button", { name: "Import CSV" }));
    await userEvent.type(screen.getByLabelText("CSV"), "SN-1,,Nobody");
    await userEvent.click(screen.getByRole("button", { name: "Import" }));
    expect(await screen.findByText("Line 2: there is no group called Nobody")).toBeInTheDocument();
    expect(screen.getByText("Line 3: serial must be 1 to 64 characters")).toBeInTheDocument();
  });

  it("registers a device into a static group", async () => {
    const posted: unknown[] = [];
    fetchMock.mockImplementation((url: string, init?: { method?: string; body?: string }) => {
      if (init?.method === "POST") {
        posted.push(JSON.parse(init.body ?? "{}"));
        return Promise.resolve(json(waiting, 201));
      }
      return Promise.resolve(String(url).includes("/groups") ? json({ items: groups }) : json({ items: [], total: 0 }));
    });
    renderPage();
    await screen.findByText("No devices registered yet.");
    await userEvent.click(screen.getByRole("button", { name: "Register device" }));
    await userEvent.type(screen.getByLabelText("Serial number"), "PF3ABC12");
    await userEvent.type(screen.getByLabelText(/Computer name/), "SALES-01");
    await userEvent.click(await screen.findByLabelText("Sales laptops"));
    expect(screen.queryByLabelText("All devices")).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Register" }));
    await waitFor(() =>
      expect(posted[0]).toEqual({ serial: "PF3ABC12", device_name: "SALES-01", group_ids: ["g1"], notes: "" }),
    );
  });
});
