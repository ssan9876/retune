import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Compliance from "./Compliance";

const fetchMock = vi.fn();

vi.mock("../session/SessionContext", () => ({
  useSession: () => ({ admin: { role: "admin" }, canWrite: true }),
}));

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function list(items: unknown[]) {
  return json({ items, total: items.length, limit: 50, offset: 0 });
}

const policy = {
  id: "pol-1",
  name: "Baseline security",
  description: "What a healthy workstation looks like",
  rules: [{ type: "bitlocker", volumes: "system" }],
  created_at: "2026-09-13T00:00:00Z",
  updated_at: "2026-09-13T00:00:00Z",
  created_by: "ops@example.com",
  device_counts: { compliant: 3, non_compliant: 1, unknown: 0 },
};

/** listOnly answers every GET with an empty page, except /compliance-policies
 * (the policy list itself), which returns `policies`. */
function listOnly(policies: unknown[] = [policy]) {
  fetchMock.mockImplementation((url: string) => {
    if (String(url).includes("/compliance-policies?")) {
      return Promise.resolve(list(policies));
    }
    return Promise.resolve(list([]));
  });
}

function render_() {
  return render(
    <MemoryRouter>
      <Compliance />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
});

describe("Compliance", () => {
  it("lists policies with their rule count", async () => {
    listOnly();
    render_();
    await screen.findByText("Baseline security");
    expect(screen.getByText("What a healthy workstation looks like")).toBeInTheDocument();
    const row = screen.getByText("Baseline security").closest("tr");
    if (!row) throw new Error("row not found");
    expect(within(row).getByRole("cell", { name: "1" })).toBeInTheDocument();
  });

  it("renders the rollup from the list response's own device_counts, with a single request", async () => {
    listOnly();
    render_();
    await screen.findByText("Baseline security");

    const row = screen.getByText("Baseline security").closest("tr");
    if (!row) throw new Error("row not found");
    expect(row.textContent).toContain("3");
    expect(row.textContent).toContain("0");

    // No per-policy /devices?state= calls: the rollup comes from the list
    // response alone, not a fan-out of extra requests per policy.
    const rollupCalls = fetchMock.mock.calls.filter((call: unknown[]) => String(call[0]).includes("/devices?state="));
    expect(rollupCalls).toHaveLength(0);
  });

  it("creates a policy and sends the right rules JSON", async () => {
    const posted: Record<string, unknown>[] = [];
    fetchMock.mockImplementation((_url: string, init?: { method?: string; body?: string }) => {
      if (init?.method === "POST") {
        posted.push(JSON.parse(init.body ?? "{}"));
        return Promise.resolve(json({ ...policy, id: "pol-2" }, 201));
      }
      return Promise.resolve(list([]));
    });
    render_();
    await screen.findByText("No compliance policies yet.");

    await userEvent.click(screen.getByRole("button", { name: "New policy" }));
    await userEvent.type(screen.getByLabelText("Name"), "Workstation baseline");
    await userEvent.click(screen.getByRole("button", { name: "Add a rule" }));

    // The default rule type is os_build_min; fill in a valid build.
    await userEvent.type(screen.getByLabelText("Minimum OS build"), "26100");

    await userEvent.click(screen.getByRole("button", { name: "Add a rule" }));
    await userEvent.selectOptions(screen.getByLabelText("Rule 2 type"), "max_local_admins");
    const count = screen.getByLabelText("Maximum local admins");
    await userEvent.clear(count);
    await userEvent.type(count, "2");

    await userEvent.click(screen.getByRole("button", { name: "Create policy" }));

    expect(posted).toHaveLength(1);
    expect(posted[0]).toMatchObject({ name: "Workstation baseline" });
    expect(posted[0].rules).toMatchObject([
      { type: "os_build_min", build: "26100" },
      { type: "max_local_admins", count: 2 },
    ]);
  });

  it("renders the right inputs for every rule type", async () => {
    listOnly();
    render_();
    await screen.findByText("Baseline security");

    await userEvent.click(screen.getByRole("button", { name: "New policy" }));
    await userEvent.click(screen.getByRole("button", { name: "Add a rule" }));
    const kindSelect = screen.getByLabelText("Rule 1 type");

    const expectations: [string, string][] = [
      ["os_build_min", "Minimum OS build"],
      ["agent_version_min", "Minimum agent version"],
      ["bitlocker", "Volumes"],
      ["tpm", "Minimum TPM version"],
      ["checked_in_within", "Checked in within (hours)"],
      ["inventory_within", "Inventory received within (hours)"],
      ["updates_within", "Updates installed within (days)"],
      ["max_local_admins", "Maximum local admins"],
      ["forbidden_software", "Forbidden software name"],
      ["required_software", "Required software name"],
      ["profile_applied", "Profile"],
    ];

    for (const [value, label] of expectations) {
      await userEvent.selectOptions(kindSelect, value);
      expect(screen.getByLabelText(label)).toBeInTheDocument();
    }

    // no_pending_reboot takes no parameters at all.
    await userEvent.selectOptions(kindSelect, "no_pending_reboot");
    expect(screen.getByText(/No parameters/)).toBeInTheDocument();
  });

  it("rejects an out-of-bounds value before the request is ever sent", async () => {
    listOnly();
    render_();
    await screen.findByText("Baseline security");

    await userEvent.click(screen.getByRole("button", { name: "New policy" }));
    await userEvent.type(screen.getByLabelText("Name"), "Broken");
    await userEvent.click(screen.getByRole("button", { name: "Add a rule" }));
    await userEvent.selectOptions(screen.getByLabelText("Rule 1 type"), "checked_in_within");
    const hours = screen.getByLabelText("Checked in within (hours)");
    await userEvent.clear(hours);
    await userEvent.type(hours, "9000");

    expect(screen.getByText("Between 1 and 8760 hours.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create policy" })).toBeDisabled();
  });

  it("assigns a policy to a group with no options", async () => {
    const posted: Record<string, unknown>[] = [];
    fetchMock.mockImplementation((url: string, init?: { method?: string; body?: string }) => {
      if (init?.method === "POST") {
        posted.push(JSON.parse(init.body ?? "{}"));
        return Promise.resolve(json({}));
      }
      if (String(url).includes("/groups")) {
        return Promise.resolve(list([{ id: "g1", name: "All devices", kind: "builtin" }]));
      }
      if (String(url).includes("/compliance-policies?")) {
        return Promise.resolve(list([policy]));
      }
      return Promise.resolve(list([]));
    });
    render_();
    await screen.findByText("Baseline security");

    await userEvent.click(screen.getByRole("button", { name: "Assign" }));
    await screen.findByLabelText("Group");
    await userEvent.click(screen.getByRole("button", { name: "Assign to group" }));

    expect(posted).toHaveLength(1);
    expect(posted[0]).toMatchObject({
      item_kind: "compliance",
      item_id: "pol-1",
      group_id: "g1",
      mode: "include",
    });
    expect(posted[0].options).toBeUndefined();
  });

  it("links Export CSV to the policy's export endpoint", async () => {
    listOnly();
    render_();
    await screen.findByText("Baseline security");

    await userEvent.click(screen.getByText("Baseline security"));
    const link = await screen.findByRole("link", { name: "Export CSV" });
    expect(link).toHaveAttribute("href", "/api/admin/v1/compliance-policies/pol-1/devices/export.csv");
  });
});
