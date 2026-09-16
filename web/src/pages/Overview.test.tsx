import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Overview from "./Overview";

const fetchMock = vi.fn();

function dashboard(overrides: Record<string, unknown> = {}) {
  return {
    devices: { active: 8, stale: 2, retired: 1, total: 11 },
    compliance: { compliant: 5, non_compliant: 2, unknown: 1, not_evaluated: 0 },
    failed_deployments: { script: 1, app: 0, profile: 0, agent: 0 },
    agent_versions: [{ version: "0.3.0", count: 6 }],
    os_builds: [{ build: "26200", count: 6 }],
    ...overrides,
  };
}

// The stats link to the pages that explain them, so the page needs a router.
function renderOverview() {
  return render(
    <MemoryRouter>
      <Overview />
    </MemoryRouter>,
  );
}

function mockDashboard(body: unknown, status = 200) {
  fetchMock.mockImplementation(() =>
    Promise.resolve(
      new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }),
    ),
  );
}

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
});

describe("Overview", () => {
  it("shows fleet, compliance and deployment counts", async () => {
    mockDashboard(dashboard());
    renderOverview();
    expect(await screen.findByRole("heading", { name: "Overview" })).toBeInTheDocument();

    expect(screen.getByText("Active").closest(".overview__stat")).toHaveTextContent("8");
    expect(screen.getByText("Stale").closest(".overview__stat")).toHaveTextContent("2");
    expect(screen.getByText("Retired").closest(".overview__stat")).toHaveTextContent("1");

    expect(screen.getByText("Compliant").closest(".overview__stat")).toHaveTextContent("5");
    expect(screen.getByText("Non-compliant").closest(".overview__stat")).toHaveTextContent("2");
    expect(screen.getByText("Unknown").closest(".overview__stat")).toHaveTextContent("1");
    expect(screen.getByText("Not evaluated").closest(".overview__stat")).toHaveTextContent("0");

    expect(screen.getByText("Scripts").closest(".overview__stat")).toHaveTextContent("1");

    // A count is a way in to the page that can explain it.
    expect(screen.getByText("Scripts").closest("a")).toHaveAttribute("href", "/scripts");
    expect(screen.getByText("Apps").closest("a")).toHaveAttribute("href", "/apps");
    expect(screen.getByText("Profiles").closest("a")).toHaveAttribute("href", "/profiles");
    expect(screen.getByText("Agent").closest("a")).toHaveAttribute("href", "/agent-versions");
    expect(screen.getByText("Non-compliant").closest("a")).toHaveAttribute("href", "/compliance");

    expect(screen.getByText("0.3.0")).toBeInTheDocument();
    expect(screen.getByText("26200")).toBeInTheDocument();
  });

  it("says so when no agent versions or builds have been reported", async () => {
    mockDashboard(dashboard({ agent_versions: [], os_builds: [] }));
    renderOverview();
    await screen.findByRole("heading", { name: "Overview" });
    expect(screen.getAllByText("No data reported yet.")).toHaveLength(2);
  });

  it("shows an error when the dashboard fails to load", async () => {
    mockDashboard({ code: "internal", message: "something broke" }, 500);
    renderOverview();
    expect(await screen.findByText("something broke")).toBeInTheDocument();
  });
});
