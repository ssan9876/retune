import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AutoRolloutPanel, ReleasesPanel } from "./AgentUpdates";

const fetchMock = vi.fn();

vi.mock("react-router-dom", () => ({
  Link: ({ children }: { children: unknown }) => children,
}));

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const releases = {
  feed: {
    enabled: true,
    url: "https://example.com/releases",
    interval_hours: 6,
    prereleases: false,
    checked_at: "2026-09-26T10:00:00Z",
  },
  items: [
    {
      version: "1.3.0",
      prerelease: false,
      published_at: "2026-09-25T10:00:00Z",
      notes: "## Changes\n- faster",
      key_id: "0123456789abcdef",
      verified_at: "2026-09-26T10:00:00Z",
      agent_version_id: "v13",
    },
    {
      version: "1.2.0",
      prerelease: false,
      published_at: "2026-09-01T10:00:00Z",
      notes: "",
      key_id: "0123456789abcdef",
      verified_at: "2026-09-02T10:00:00Z",
      import_error: "retune-agent.exe hashes to x, not the manifest's y",
    },
  ],
};

const rollout = {
  policy: { enabled: true, pilot_group_id: "g1", pilot_group_name: "Pilot", delay_hours: 24 },
  rollouts: [
    {
      id: "r2",
      agent_version_id: "v13",
      version: "1.3.0",
      state: "halted",
      delay_hours: 24,
      detail: "1 pilot device(s) failed to run it: PC-01 (rolled back from 1.3.0 to 1.2.0)",
      created_at: "2026-09-26T10:00:00Z",
      updated_at: "2026-09-26T11:00:00Z",
    },
    {
      id: "r1",
      agent_version_id: "v12",
      version: "1.2.0",
      state: "promoting",
      delay_hours: 24,
      approval_id: "a1",
      detail: "the pilot passed; waiting for a second administrator to approve All devices",
      created_at: "2026-09-02T10:00:00Z",
      updated_at: "2026-09-03T10:00:00Z",
    },
  ],
};

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
});

describe("ReleasesPanel", () => {
  it("lists verified releases and says which agents were imported", async () => {
    fetchMock.mockResolvedValue(json(releases));
    render(<ReleasesPanel canWrite onImported={() => {}} />);
    expect(await screen.findByText("1.3.0")).toBeInTheDocument();
    expect(screen.getByText(/agent imported/)).toBeInTheDocument();
    expect(screen.getByText(/agent not imported: retune-agent.exe hashes to x/)).toBeInTheDocument();
    expect(screen.getByText(/every 6 hours/)).toBeInTheDocument();
  });

  it("checks now and shows a failed check", async () => {
    fetchMock.mockResolvedValueOnce(json(releases));
    fetchMock.mockResolvedValueOnce(json({ ...releases, feed: { ...releases.feed, error: "feed answered 503" } }));
    const onImported = vi.fn();
    render(<ReleasesPanel canWrite onImported={onImported} />);
    await userEvent.click(await screen.findByRole("button", { name: "Check now" }));
    expect(await screen.findByText(/The last check failed: feed answered 503/)).toBeInTheDocument();
    const [url, init] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(url).toContain("/releases/check");
    expect(init.method).toBe("POST");
    expect(onImported).toHaveBeenCalled();
  });

  it("says so when the server does not watch for releases", async () => {
    fetchMock.mockResolvedValue(json({ feed: { ...releases.feed, enabled: false }, items: [] }));
    render(<ReleasesPanel canWrite onImported={() => {}} />);
    expect(await screen.findByText(/does not look for releases/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Check now" })).not.toBeInTheDocument();
  });
});

describe("AutoRolloutPanel", () => {
  it("shows the policy and why a rollout halted, with a way to resume it", async () => {
    fetchMock.mockResolvedValue(json(rollout));
    render(<AutoRolloutPanel canWrite />);
    expect(await screen.findByText(/goes to Pilot first/)).toBeInTheDocument();
    expect(screen.getByText("Halted")).toBeInTheDocument();
    expect(screen.getByText(/PC-01 \(rolled back from 1.3.0 to 1.2.0\)/)).toBeInTheDocument();
    expect(screen.getByText("Waiting for approval")).toBeInTheDocument();
    expect(screen.getByText(/Review it under Approvals/)).toBeInTheDocument();

    fetchMock.mockResolvedValueOnce(json(rollout));
    await userEvent.click(screen.getByRole("button", { name: "Resume" }));
    const [url, init] = fetchMock.mock.calls.at(-1) as [string, RequestInit];
    expect(url).toContain("/agent-rollouts/r2/resume");
    expect(init.method).toBe("POST");
  });

  it("turns automatic rollout on with a pilot group and delay", async () => {
    fetchMock.mockImplementation((url: string) => {
      if (String(url).includes("/groups")) {
        return Promise.resolve(
          json({
            items: [
              { id: "all", name: "All devices", kind: "builtin" },
              { id: "g1", name: "Pilot", kind: "static" },
            ],
          }),
        );
      }
      return Promise.resolve(json({ policy: { enabled: false, delay_hours: 24 }, rollouts: [] }));
    });
    render(<AutoRolloutPanel canWrite />);
    expect(await screen.findByText(/Off: imported builds wait here/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Change" }));
    await userEvent.click(screen.getByRole("checkbox"));
    const pilot = screen.getByRole("combobox");
    expect(await screen.findByRole("option", { name: "Pilot" })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "All devices" })).not.toBeInTheDocument();
    await userEvent.selectOptions(pilot, "g1");
    const delay = screen.getByRole("spinbutton");
    await userEvent.clear(delay);
    await userEvent.type(delay, "48");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));

    const call = fetchMock.mock.calls.find(([u]) => String(u).includes("/agent-rollout/policy"));
    expect(call).toBeDefined();
    const body = JSON.parse(String((call![1] as RequestInit).body)) as Record<string, unknown>;
    expect(body).toEqual({ enabled: true, pilot_group_id: "g1", delay_hours: 48 });
  });

  it("hides changes from a read-only account", async () => {
    fetchMock.mockResolvedValue(json(rollout));
    render(<AutoRolloutPanel canWrite={false} />);
    expect(await screen.findByText("Halted")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Change" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Resume" })).not.toBeInTheDocument();
  });
});
