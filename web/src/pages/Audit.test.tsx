import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Audit, { dayBound } from "./Audit";

const fetchMock = vi.fn();

function entry(overrides: Record<string, unknown> = {}) {
  return {
    id: "e-1",
    actor: "alice",
    action: "device.delete",
    target_kind: "device",
    target_id: "0190aaaa-bbbb",
    details: { hostname: "PC-1" },
    at: "2026-09-20T10:00:00Z",
    ...overrides,
  };
}

function mockList(items: unknown[]) {
  fetchMock.mockImplementation(() =>
    Promise.resolve(
      new Response(JSON.stringify({ items, total: items.length, limit: 50, offset: 0 }), {
        headers: { "Content-Type": "application/json" },
      }),
    ),
  );
}

function lastURL(): string {
  return String(fetchMock.mock.calls[fetchMock.mock.calls.length - 1][0]);
}

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
});

describe("Audit", () => {
  it("lists entries", async () => {
    mockList([entry()]);
    render(
      <MemoryRouter>
        <Audit />
      </MemoryRouter>,
    );
    expect(await screen.findByText("device.delete")).toBeInTheDocument();
    expect(screen.getByText("hostname=PC-1")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Export CSV" })).toHaveAttribute("href", "/api/admin/v1/audit/export.csv");
  });

  it("filters the listing and the export alike", async () => {
    mockList([]);
    render(
      <MemoryRouter>
        <Audit />
      </MemoryRouter>,
    );
    expect(await screen.findByText("Nothing has happened yet.")).toBeInTheDocument();

    await userEvent.type(screen.getByLabelText("Who"), "bob");
    await userEvent.type(screen.getByLabelText("Action"), "script.");
    await waitFor(() => expect(lastURL()).toContain("actor=bob"));
    expect(lastURL()).toContain("action=script.");
    expect(await screen.findByText("Nothing matches these filters.")).toBeInTheDocument();

    const href = screen.getByRole("link", { name: "Export CSV" }).getAttribute("href") ?? "";
    expect(href).toMatch(/^\/api\/admin\/v1\/audit\/export\.csv\?/);
    expect(href).toContain("actor=bob");
    expect(href).toContain("action=script.");
  });
});

describe("dayBound", () => {
  it("is the start of the day, or of the next for an end date", () => {
    expect(dayBound("")).toBeUndefined();
    expect(dayBound("2026-09-20")).toBe(new Date("2026-09-20T00:00:00").toISOString());
    expect(dayBound("2026-09-20", true)).toBe(new Date("2026-09-21T00:00:00").toISOString());
  });
});
