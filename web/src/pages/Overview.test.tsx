import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Overview from "./Overview";

const fetchMock = vi.fn();

function dashboard(overrides: Record<string, unknown> = {}) {
  return {
    devices: { active: 8, stale: 2, retired: 1, total: 11 },
    compliance: { compliant: 5, non_compliant: 2, unknown: 1, not_evaluated: 0 },
    failed_deployments: { script: 1, app: 0, profile: 0, agent: 0 },
    checkin_recency: { hour: 6, day: 2, week: 1, older: 1, never: 0 },
    enrollment_trend: [
      { day: "2026-09-14", count: 0 },
      { day: "2026-09-15", count: 3 },
    ],
    agent_versions: [{ version: "0.3.0", count: 6 }],
    os_builds: [{ build: "26200", count: 6 }],
    ...overrides,
  };
}

// The dashboard's tiles link to the pages that explain them, so the page
// needs a router.
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

/** kpi finds a headline tile by its label and returns the tile itself, so a
 * test asserts on that number rather than on the first match for it anywhere
 * on a page full of numbers. The search is confined to the headline band,
 * because "Compliant" is also a slice of the donut below it. */
function kpi(label: string): HTMLElement {
  const band = document.querySelector(".kpis");
  if (!band) throw new Error("no KPI band");
  const el = within(band as HTMLElement)
    .getByText(label)
    .closest(".kpi");
  if (!el) throw new Error(`no KPI labelled ${label}`);
  return el as HTMLElement;
}

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
});

describe("Overview", () => {
  it("leads with the headline numbers", async () => {
    mockDashboard(dashboard());
    renderOverview();
    expect(await screen.findByRole("heading", { name: "Overview" })).toBeInTheDocument();

    expect(kpi("Devices")).toHaveTextContent("11");
    expect(kpi("Devices")).toHaveTextContent("8 active now");
    // 5 compliant of the 8 that were scored; not_evaluated is not a verdict.
    expect(kpi("Compliant")).toHaveTextContent("63%");
    expect(kpi("Compliant")).toHaveTextContent("5 of 8 scored");
    expect(kpi("Non-compliant")).toHaveTextContent("2");
    expect(kpi("Stale")).toHaveTextContent("2");
    expect(kpi("Failed deployments")).toHaveTextContent("1");
  });

  it("says no answer rather than 0% when nothing has been scored", async () => {
    mockDashboard(
      dashboard({ compliance: { compliant: 0, non_compliant: 0, unknown: 0, not_evaluated: 11 } }),
    );
    renderOverview();
    await screen.findByRole("heading", { name: "Overview" });
    expect(kpi("Compliant")).toHaveTextContent("—");
    expect(kpi("Compliant")).toHaveTextContent("no policy assigned yet");
  });

  it("draws each chart with its own numbers beside it", async () => {
    mockDashboard(dashboard());
    renderOverview();
    await screen.findByRole("heading", { name: "Overview" });

    // Every chart is labelled for a screen reader, not left as a bare shape.
    expect(
      screen.getByRole("img", { name: /5 compliant, 2 non-compliant, 1 unknown, 0 not evaluated/ }),
    ).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /8 active, 2 stale, 1 retired/ })).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /6 within the hour/ })).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /Devices enrolled per day: 3 in total/ })).toBeInTheDocument();

    const versions = screen.getByRole("heading", { name: "Agent versions" }).closest(".tile");
    expect(within(versions as HTMLElement).getByText("0.3.0")).toBeInTheDocument();
    expect(within(versions as HTMLElement).getByText("6")).toBeInTheDocument();
  });

  it("links the tiles to the pages that explain them", async () => {
    mockDashboard(dashboard());
    renderOverview();
    await screen.findByRole("heading", { name: "Overview" });

    expect(kpi("Devices").closest("a")).toHaveAttribute("href", "/devices");
    expect(kpi("Non-compliant").closest("a")).toHaveAttribute("href", "/devices?compliance=non_compliant");
    expect(kpi("Stale").closest("a")).toHaveAttribute("href", "/devices?status=stale");
    expect(kpi("Failed deployments").closest("a")).toHaveAttribute("href", "/#failed-deployments");
    expect(screen.getByRole("link", { name: "Scripts" })).toHaveAttribute("href", "/scripts");
    expect(screen.getByRole("link", { name: "Apps" })).toHaveAttribute("href", "/apps");
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
