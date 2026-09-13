import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Profiles from "./Profiles";

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

const profile = {
  id: "p1",
  name: "Baseline",
  description: "How a workstation should be",
  current_version: 3,
  created_at: "2026-09-13T00:00:00Z",
  updated_at: "2026-09-13T00:00:00Z",
  created_by: "ops@example.com",
};

function listOnly() {
  fetchMock.mockImplementation((url: string) => {
    if (String(url).includes("/profiles?")) {
      return Promise.resolve(json({ items: [profile], total: 1, limit: 50, offset: 0 }));
    }
    return Promise.resolve(json({ items: [], total: 0, limit: 50, offset: 0 }));
  });
}

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
});

describe("Profiles", () => {
  it("lists profiles with their current version", async () => {
    listOnly();
    render(<Profiles />);

    await screen.findByText("Baseline");
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(screen.getByText("How a workstation should be")).toBeInTheDocument();
  });

  it("builds a profile one setting at a time", async () => {
    const posted: Record<string, unknown>[] = [];
    fetchMock.mockImplementation((_url: string, init?: { method?: string; body?: string }) => {
      if (init?.method === "POST") {
        posted.push(JSON.parse(init.body ?? "{}"));
        return Promise.resolve(json({ ...profile, id: "p2" }, 201));
      }
      return Promise.resolve(json({ items: [], total: 0, limit: 50, offset: 0 }));
    });
    render(<Profiles />);
    await screen.findByText("No profiles yet.");

    await userEvent.click(screen.getByRole("button", { name: "New profile" }));
    await userEvent.type(screen.getByLabelText("Name"), "Workstation baseline");
    await userEvent.click(screen.getByRole("button", { name: "Add a setting" }));

    // A registry setting is the default; switch it to a service.
    await userEvent.selectOptions(screen.getByLabelText("Setting 1 kind"), "service");
    await userEvent.type(screen.getByLabelText("Service name"), "Spooler");
    await userEvent.selectOptions(screen.getByLabelText("It should be"), "stopped");

    await userEvent.click(screen.getByRole("button", { name: "Create profile" }));

    expect(posted).toHaveLength(1);
    expect(posted[0]).toMatchObject({ name: "Workstation baseline" });
    expect(posted[0].settings).toMatchObject([{ kind: "service", name: "Spooler", state: "stopped" }]);
  });

  it("shows only the fields the chosen kind needs", async () => {
    listOnly();
    render(<Profiles />);
    await screen.findByText("Baseline");

    await userEvent.click(screen.getByRole("button", { name: "New profile" }));
    await userEvent.click(screen.getByRole("button", { name: "Add a setting" }));

    // Registry by default.
    expect(screen.getByLabelText("Value name")).toBeInTheDocument();
    expect(screen.queryByLabelText("Service name")).not.toBeInTheDocument();

    await userEvent.selectOptions(screen.getByLabelText("Setting 1 kind"), "local_group_members");
    expect(screen.getByLabelText("Members")).toBeInTheDocument();
    expect(screen.queryByLabelText("Value name")).not.toBeInTheDocument();
  });

  it("explains that exact mode spares the built-in Administrator", async () => {
    listOnly();
    render(<Profiles />);
    await screen.findByText("Baseline");

    await userEvent.click(screen.getByRole("button", { name: "New profile" }));
    await userEvent.click(screen.getByRole("button", { name: "Add a setting" }));
    await userEvent.selectOptions(screen.getByLabelText("Setting 1 kind"), "local_group_members");
    await userEvent.selectOptions(screen.getByLabelText("Mode"), "exact");

    expect(screen.getByText(/never removed/)).toBeInTheDocument();
  });

  it("surfaces a rejected setting with the server's reason", async () => {
    fetchMock.mockImplementation((_url: string, init?: { method?: string }) => {
      if (init?.method === "POST") {
        return Promise.resolve(
          json({ code: "bad_request", message: "setting 1: invalid setting: HKCU settings are not supported yet" }, 400),
        );
      }
      return Promise.resolve(json({ items: [], total: 0, limit: 50, offset: 0 }));
    });
    render(<Profiles />);
    await screen.findByText("No profiles yet.");

    await userEvent.click(screen.getByRole("button", { name: "New profile" }));
    await userEvent.type(screen.getByLabelText("Name"), "Broken");
    await userEvent.click(screen.getByRole("button", { name: "Add a setting" }));
    await userEvent.click(screen.getByRole("button", { name: "Create profile" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("HKCU settings are not supported yet");
  });

  it("offers to put previous values back when a profile is unassigned", async () => {
    fetchMock.mockImplementation((url: string) => {
      if (String(url).includes("/groups")) {
        return Promise.resolve(json({ items: [{ id: "g1", name: "All devices", kind: "builtin" }] }));
      }
      return Promise.resolve(json({ items: [profile], total: 1, limit: 50, offset: 0 }));
    });
    render(<Profiles />);
    await screen.findByText("Baseline");

    await userEvent.click(screen.getByRole("button", { name: "Assign" }));
    await screen.findByLabelText("When it stops applying");
    expect(screen.getByText(/Restores what was there before/)).toBeInTheDocument();
  });
});
