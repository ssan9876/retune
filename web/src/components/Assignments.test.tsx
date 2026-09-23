import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AssignedTo, RolloutFields, describeRollout, rolloutBody } from "./Assignments";
import type { Rollout } from "./Assignments";

const fetchMock = vi.fn();

vi.mock("../session/SessionContext", () => ({
  useSession: () => ({ admin: { role: "admin" }, canWrite: false }),
}));

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
});

describe("rollouts", () => {
  it("describes how far a rollout has got", () => {
    expect(describeRollout({ percent: 10 })).toBe("10% of the group, until changed");
    expect(describeRollout({ percent: 10, current_percent: 30, full_at: "2026-10-01T00:00:00Z" })).toMatch(
      /^30% of the group, all of it by /,
    );
  });

  it("sends a rollout only for a phased include", () => {
    expect(rolloutBody("include", null)).toBeUndefined();
    expect(rolloutBody("exclude", { percent: 10 })).toBeUndefined();
    expect(rolloutBody("include", { percent: 10, step_percent: 20, step_hours: 24 })).toEqual({
      percent: 10,
      step_percent: 20,
      step_hours: 24,
    });
  });

  it("lists assignments with their rollout", async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          items: [{ id: "a1", group_name: "All devices", mode: "include", rollout: { percent: 10, current_percent: 10 } }],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    render(<AssignedTo kind="script" id="s1" />);
    expect(await screen.findByText(/All devices/)).toBeInTheDocument();
    expect(screen.getByText(/10% of the group/)).toBeInTheDocument();
  });

  it("turns phasing on with sensible steps", async () => {
    let latest: Rollout | null = null;
    function Harness() {
      const [r, setR] = useState<Rollout | null>(null);
      latest = r;
      return <RolloutFields value={r} onChange={setR} />;
    }
    render(<Harness />);
    await userEvent.click(screen.getByLabelText("Roll out in phases"));
    expect(latest).toEqual({ percent: 10, step_percent: 20, step_hours: 24 });
    await userEvent.clear(screen.getByLabelText("Then add (%)"));
    expect(latest).toMatchObject({ step_percent: 0, step_hours: 0 });
  });
});
