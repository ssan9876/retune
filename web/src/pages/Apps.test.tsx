import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Apps from "./Apps";

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

const app = {
  id: "a1",
  name: "7-Zip",
  description: "archiver",
  package_id: "7zip.7zip",
  pinned_version: "",
  scope: "machine",
  current_version: 1,
  created_at: "2026-09-13T00:00:00Z",
  updated_at: "2026-09-13T00:00:00Z",
  created_by: "ops@example.com",
};

function listOnly() {
  fetchMock.mockImplementation((url: string) => {
    if (String(url).includes("/apps?")) {
      return Promise.resolve(json({ items: [app], total: 1, limit: 50, offset: 0 }));
    }
    if (String(url).includes("/groups")) {
      return Promise.resolve(json({ items: [{ id: "g1", name: "All devices", kind: "builtin" }] }));
    }
    return Promise.resolve(json({ items: [], total: 0, limit: 50, offset: 0 }));
  });
}

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
});

describe("Apps", () => {
  it("lists apps with the package they install", async () => {
    listOnly();
    render(<Apps />);
    expect(await screen.findByText("7-Zip")).toBeInTheDocument();
    expect(screen.getByText("7zip.7zip")).toBeInTheDocument();
  });

  it("warns that an uninstall assignment removes software", async () => {
    listOnly();
    render(<Apps />);
    await screen.findByText("7-Zip");

    await userEvent.click(screen.getByRole("button", { name: "Assign" }));
    await screen.findByLabelText("What to do");
    await userEvent.selectOptions(screen.getByLabelText("What to do"), "uninstall");

    expect(screen.getByText(/removes it from every device/i)).toBeInTheDocument();
  });

  it("sends the intent with the assignment", async () => {
    listOnly();
    render(<Apps />);
    await screen.findByText("7-Zip");

    await userEvent.click(screen.getByRole("button", { name: "Assign" }));
    await screen.findByLabelText("What to do");
    await userEvent.click(screen.getByRole("button", { name: "Assign to group" }));

    const call = fetchMock.mock.calls.find(([url]) => String(url).includes("/assignments"));
    expect(JSON.parse(String(call?.[1]?.body)).options).toMatchObject({ intent: "install" });
  });

  it("saves a new app", async () => {
    const posted: Record<string, unknown>[] = [];
    fetchMock.mockImplementation((url: string, init?: { method?: string; body?: string }) => {
      if (init?.method === "POST") {
        posted.push(JSON.parse(init.body ?? "{}"));
        return Promise.resolve(json({ ...app, id: "a2" }, 201));
      }
      if (String(url).includes("/apps?")) {
        return Promise.resolve(json({ items: [], total: 0, limit: 50, offset: 0 }));
      }
      return Promise.resolve(json({ items: [], total: 0, limit: 50, offset: 0 }));
    });
    render(<Apps />);
    await screen.findByText("No apps yet.");

    await userEvent.click(screen.getByRole("button", { name: "New app" }));
    await userEvent.type(screen.getByLabelText("Name"), "Firefox");
    await userEvent.type(screen.getByLabelText("Package ID"), "Mozilla.Firefox");
    await userEvent.click(screen.getByRole("button", { name: "Create app" }));

    expect(posted).toHaveLength(1);
    expect(posted[0]).toMatchObject({ name: "Firefox", package_id: "Mozilla.Firefox" });
  });

  it("explains that a blank pinned version tracks whatever is current", async () => {
    listOnly();
    render(<Apps />);
    await screen.findByText("7-Zip");

    await userEvent.click(screen.getByRole("button", { name: "New app" }));
    expect(screen.getByText(/whatever is current/i)).toBeInTheDocument();
  });
});
