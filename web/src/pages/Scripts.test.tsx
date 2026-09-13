import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Scripts from "./Scripts";

const fetchMock = vi.fn();

vi.mock("../session/SessionContext", () => ({
  useSession: () => ({ admin: { role: "admin" }, canWrite: true }),
}));

vi.mock("react-router-dom", () => ({
  Link: ({ children }: { children: unknown }) => children,
}));

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const script = {
  id: "s1",
  name: "Install 7-Zip",
  description: "Keeps 7-Zip present",
  current_version: 2,
  created_at: "2026-09-13T00:00:00Z",
  updated_at: "2026-09-13T00:00:00Z",
  created_by: "ops@example.com",
};

function listOnly() {
  fetchMock.mockImplementation((url: string) => {
    if (String(url).includes("/scripts?")) {
      return Promise.resolve(json({ items: [script], total: 1, limit: 50, offset: 0 }));
    }
    return Promise.resolve(json({ items: [], total: 0, limit: 50, offset: 0 }));
  });
}

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
});

describe("Scripts", () => {
  it("lists scripts with their current version", async () => {
    listOnly();
    render(<Scripts />);

    await screen.findByText("Install 7-Zip");
    expect(screen.getByText("2")).toBeInTheDocument();
    expect(screen.getByText("Keeps 7-Zip present")).toBeInTheDocument();
  });

  it("saves a new script", async () => {
    const posted: unknown[] = [];
    fetchMock.mockImplementation((url: string, init?: { method?: string; body?: string }) => {
      if (init?.method === "POST") {
        posted.push(JSON.parse(init.body ?? "{}"));
        return Promise.resolve(json({ ...script, id: "s2" }, 201));
      }
      if (String(url).includes("/scripts?")) {
        return Promise.resolve(json({ items: [], total: 0, limit: 50, offset: 0 }));
      }
      return Promise.resolve(json({ items: [], total: 0, limit: 50, offset: 0 }));
    });
    render(<Scripts />);
    await screen.findByText("No scripts yet.");

    await userEvent.click(screen.getByRole("button", { name: "New script" }));
    await userEvent.type(screen.getByLabelText("Name"), "Fix printers");
    await userEvent.type(screen.getByLabelText("PowerShell script"), "Restart-Service Spooler");
    await userEvent.click(screen.getByRole("button", { name: "Create script" }));

    expect(posted).toHaveLength(1);
    expect(posted[0]).toMatchObject({ name: "Fix printers", body: "Restart-Service Spooler" });
  });

  it("explains what the detection script does", async () => {
    listOnly();
    render(<Scripts />);
    await screen.findByText("Install 7-Zip");

    await userEvent.click(screen.getByRole("button", { name: "New script" }));
    expect(screen.getByText(/Exit 0 means there is nothing to do/)).toBeInTheDocument();
  });

  it("assigns a script to a group with its options", async () => {
    const posted: Record<string, unknown>[] = [];
    fetchMock.mockImplementation((url: string, init?: { method?: string; body?: string }) => {
      if (init?.method === "POST") {
        posted.push(JSON.parse(init.body ?? "{}"));
        return Promise.resolve(json({ id: "a1" }, 201));
      }
      if (String(url).includes("/groups")) {
        return Promise.resolve(json({ items: [{ id: "g1", name: "All devices", kind: "builtin" }] }));
      }
      return Promise.resolve(json({ items: [script], total: 1, limit: 50, offset: 0 }));
    });
    render(<Scripts />);
    await screen.findByText("Install 7-Zip");

    await userEvent.click(screen.getByRole("button", { name: "Assign" }));
    await screen.findByLabelText("Group");
    await userEvent.selectOptions(screen.getByLabelText("How often"), "recurring");
    await userEvent.click(screen.getByRole("button", { name: "Assign to group" }));

    const assignment = posted.find((body) => body.item_kind === "script");
    expect(assignment).toMatchObject({
      item_kind: "script",
      item_id: "s1",
      group_id: "g1",
      mode: "include",
    });
    expect(assignment?.options).toMatchObject({ frequency: "recurring", run_as: "system" });
  });

  it("warns that running as the signed-in user is not supported yet", async () => {
    fetchMock.mockImplementation((url: string) => {
      if (String(url).includes("/groups")) {
        return Promise.resolve(json({ items: [{ id: "g1", name: "All devices", kind: "builtin" }] }));
      }
      return Promise.resolve(json({ items: [script], total: 1, limit: 50, offset: 0 }));
    });
    render(<Scripts />);
    await screen.findByText("Install 7-Zip");

    await userEvent.click(screen.getByRole("button", { name: "Assign" }));
    await screen.findByLabelText("Run as");
    await userEvent.selectOptions(screen.getByLabelText("Run as"), "logged_in_user");

    expect(screen.getByText(/Not supported yet/)).toBeInTheDocument();
  });
});
