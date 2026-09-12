import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import DeviceDetail from "./DeviceDetail";

const fetchMock = vi.fn();
let canWrite = true;

vi.mock("../session/SessionContext", () => ({
  useSession: () => ({ admin: { role: canWrite ? "admin" : "read_only" }, canWrite }),
}));

const detail = {
  device: {
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
  },
  inventory: {
    collected_at: new Date().toISOString(),
    received_at: new Date().toISOString(),
    ram_gb: 16,
    disk_free_gb: 240.5,
    document: {},
  },
  software: [
    { name: "7-Zip", version: "24.08", publisher: "Igor Pavlov", install_date: "", scope: "machine" },
  ],
  commands: [],
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function renderDetail() {
  return render(
    <MemoryRouter initialEntries={["/devices/01a0-1"]}>
      <Routes>
        <Route path="/devices/:id" element={<DeviceDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
  canWrite = true;
});

describe("DeviceDetail", () => {
  it("shows identity and inventory", async () => {
    fetchMock.mockImplementation(() => Promise.resolve(json(detail)));
    renderDetail();
    expect(await screen.findByRole("heading", { name: "PC-ALPHA" })).toBeInTheDocument();
    expect(screen.getByText("Contoso Book 9")).toBeInTheDocument();
    expect(screen.getByText("16 GB")).toBeInTheDocument();
    expect(screen.getByText("7-Zip")).toBeInTheDocument();
  });

  it("queues a script", async () => {
    fetchMock.mockImplementation((_url: string, init?: { method?: string }) => {
      if (init?.method === "POST") return Promise.resolve(json({ commands: [{ id: "c1" }] }, 201));
      return Promise.resolve(json(detail));
    });
    renderDetail();
    await screen.findByRole("heading", { name: "PC-ALPHA" });

    await userEvent.click(screen.getByRole("button", { name: "Run script" }));
    await userEvent.type(screen.getByLabelText("PowerShell script"), "Get-Date");
    await userEvent.click(screen.getByRole("button", { name: "Queue script" }));

    await waitFor(() => {
      const call = fetchMock.mock.calls.find(([url]) => String(url).endsWith("/commands"));
      expect(call).toBeDefined();
      expect(JSON.parse(call![1].body)).toMatchObject({
        device_ids: ["01a0-1"],
        type: "run_powershell",
        script: "Get-Date",
      });
    });
  });

  it("hides write actions from a read-only admin", async () => {
    canWrite = false;
    fetchMock.mockImplementation(() => Promise.resolve(json(detail)));
    renderDetail();
    await screen.findByRole("heading", { name: "PC-ALPHA" });
    expect(screen.queryByRole("button", { name: "Run script" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Retire device" })).not.toBeInTheDocument();
  });
});
