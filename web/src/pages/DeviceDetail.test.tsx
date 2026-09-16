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

const emptyCompliance = { overall: "not_evaluated", policies: [] };

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/** mockDetail answers the device detail, compliance, and policy-list GETs; a POST goes to onPost if given. */
function mockDetail(
  detailBody: unknown = detail,
  complianceBody: unknown = emptyCompliance,
  onPost?: (url: string, body: unknown) => unknown,
  policies: unknown[] = [],
) {
  fetchMock.mockImplementation((url: string, init?: { method?: string; body?: string }) => {
    if (init?.method === "POST" && onPost) {
      return Promise.resolve(json(onPost(String(url), init.body ? JSON.parse(init.body) : undefined)));
    }
    if (String(url).endsWith("/compliance")) return Promise.resolve(json(complianceBody));
    if (String(url).includes("/compliance-policies")) {
      return Promise.resolve(json({ items: policies, total: policies.length, limit: 200, offset: 0 }));
    }
    return Promise.resolve(json(detailBody));
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
    mockDetail();
    renderDetail();
    expect(await screen.findByRole("heading", { name: "PC-ALPHA" })).toBeInTheDocument();
    expect(screen.getByText("Contoso Book 9")).toBeInTheDocument();
    expect(screen.getByText("16 GB")).toBeInTheDocument();
    expect(screen.getByText("7-Zip")).toBeInTheDocument();
  });

  it("shows the device's compliance state and any policy failures", async () => {
    mockDetail(detail, {
      overall: "non_compliant",
      policies: [
        {
          policy_id: "11111111-1111-1111-1111-111111111111",
          state: "non_compliant",
          failures: [{ rule: "min_os_build", state: "non_compliant", detail: "OS build 22000 below minimum 26100" }],
          evaluated_at: new Date().toISOString(),
        },
      ],
    });
    renderDetail();
    await screen.findByRole("heading", { name: "PC-ALPHA" });
    expect(screen.getByText("Overall: non compliant")).toBeInTheDocument();
    // No policy list was fetched successfully here, so the raw id is shown.
    expect(screen.getByText("11111111-1111-1111-1111-111111111111")).toBeInTheDocument();
    expect(screen.getByText("OS build 22000 below minimum 26100")).toBeInTheDocument();
  });

  it("resolves a policy_id to its name using the fetched policy list", async () => {
    mockDetail(
      detail,
      {
        overall: "compliant",
        policies: [
          {
            policy_id: "11111111-1111-1111-1111-111111111111",
            state: "compliant",
            failures: [],
            evaluated_at: new Date().toISOString(),
          },
        ],
      },
      undefined,
      [{ id: "11111111-1111-1111-1111-111111111111", name: "Baseline security" }],
    );
    renderDetail();
    await screen.findByRole("heading", { name: "PC-ALPHA" });
    expect(await screen.findByText("Baseline security")).toBeInTheDocument();
    expect(screen.queryByText("11111111-1111-1111-1111-111111111111")).not.toBeInTheDocument();
  });

  it("falls back to the raw policy_id when it is missing from the policy list", async () => {
    mockDetail(
      detail,
      {
        overall: "compliant",
        policies: [
          {
            policy_id: "22222222-2222-2222-2222-222222222222",
            state: "compliant",
            failures: [],
            evaluated_at: new Date().toISOString(),
          },
        ],
      },
      undefined,
      [{ id: "11111111-1111-1111-1111-111111111111", name: "Baseline security" }],
    );
    renderDetail();
    await screen.findByRole("heading", { name: "PC-ALPHA" });
    expect(await screen.findByText("22222222-2222-2222-2222-222222222222")).toBeInTheDocument();
  });

  it("says so when no compliance policies apply", async () => {
    mockDetail();
    renderDetail();
    await screen.findByRole("heading", { name: "PC-ALPHA" });
    expect(screen.getByText("No compliance policies apply to this device.")).toBeInTheDocument();
  });

  it("queues a script", async () => {
    mockDetail(detail, emptyCompliance, () => ({ commands: [{ id: "c1" }] }));
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
    mockDetail();
    renderDetail();
    await screen.findByRole("heading", { name: "PC-ALPHA" });
    expect(screen.queryByRole("button", { name: "Run script" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Retire device" })).not.toBeInTheDocument();
  });
});
