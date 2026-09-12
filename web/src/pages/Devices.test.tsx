import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Devices, { relative } from "./Devices";

const fetchMock = vi.fn();

vi.mock("../session/SessionContext", () => ({
  useSession: () => ({ admin: { role: "admin" }, canWrite: true, loading: false, needsSetup: false }),
}));

function device(overrides: Record<string, unknown> = {}) {
  return {
    id: "01a0-1",
    hostname: "PC-ALPHA",
    status: "active",
    os_version: "Microsoft Windows 11 Pro 10.0.26200",
    os_build: "26200",
    manufacturer: "Contoso",
    model: "Book 9",
    serial: "SN-1",
    smbios_uuid: "U-1",
    agent_version: "0.1.0",
    enrolled_at: "2026-09-12T12:00:00Z",
    last_seen_at: new Date().toISOString(),
    cert_expires_at: "2026-12-12T12:00:00Z",
    stale: false,
    ...overrides,
  };
}

function mockList(items: unknown[], total = items.length) {
  fetchMock.mockImplementation(() =>
    Promise.resolve(
      new Response(JSON.stringify({ items, total, limit: 50, offset: 0 }), {
        headers: { "Content-Type": "application/json" },
      }),
    ),
  );
}

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
});

describe("Devices", () => {
  it("lists devices with their status", async () => {
    mockList([device(), device({ id: "01a0-2", hostname: "PC-BETA", stale: true })]);
    render(
      <MemoryRouter>
        <Devices />
      </MemoryRouter>,
    );
    expect(await screen.findByRole("link", { name: "PC-ALPHA" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "PC-BETA" })).toBeInTheDocument();
    expect(screen.getAllByText("active").length).toBeGreaterThan(0);
    expect(screen.getAllByText("stale").length).toBeGreaterThan(0);
  });

  it("explains an empty fleet", async () => {
    mockList([]);
    render(
      <MemoryRouter>
        <Devices />
      </MemoryRouter>,
    );
    expect(await screen.findByText("No devices yet.")).toBeInTheDocument();
    expect(screen.getByText("No devices enrolled yet")).toBeInTheDocument();
  });

  it("searches", async () => {
    mockList([]);
    render(
      <MemoryRouter>
        <Devices />
      </MemoryRouter>,
    );
    await screen.findByText("No devices yet.");
    await userEvent.type(screen.getByRole("searchbox", { name: "Search devices" }), "beta");
    await waitFor(() => {
      const urls = fetchMock.mock.calls.map(([url]) => String(url));
      expect(urls.some((url) => url.includes("search=beta"))).toBe(true);
    });
  });
});

describe("relative", () => {
  it("describes recent and missing timestamps", () => {
    expect(relative()).toBe("never");
    expect(relative(new Date().toISOString())).toBe("just now");
    expect(relative(new Date(Date.now() - 3 * 60_000).toISOString())).toBe("3 minutes ago");
    expect(relative(new Date(Date.now() - 2 * 3600_000).toISOString())).toBe("2 hours ago");
  });
});
