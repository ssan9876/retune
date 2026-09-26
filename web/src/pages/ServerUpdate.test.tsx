import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { ServerInfo } from "../api/serverupdate";
import ServerUpdate from "./ServerUpdate";

const fetchMock = vi.fn();
let role = "admin";

vi.mock("../session/SessionContext", () => ({
  useSession: () => ({ admin: { role, email: "me@example.com", scope: null }, canWrite: role === "admin" }),
}));

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const available: ServerInfo = {
  version: "1.1.0",
  stamped: true,
  mode: "docker",
  latest: { version: "1.2.0", prerelease: false, published_at: new Date().toISOString(), notes: "Faster check-ins." },
  update_available: true,
  approvals_required: false,
};

function renderPage() {
  return render(
    <MemoryRouter>
      <ServerUpdate />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  role = "admin";
  vi.stubGlobal("fetch", fetchMock);
  vi.stubGlobal("confirm", () => true);
  fetchMock.mockReset();
});

describe("ServerUpdate", () => {
  it("offers the newest release with its notes, and updates to it", async () => {
    let posted: unknown = null;
    fetchMock.mockImplementation((_url: string, init?: RequestInit) => {
      if (init?.method === "POST") {
        posted = JSON.parse(String(init.body));
        return Promise.resolve(
          json({ state: { id: "u1", version: "1.2.0", phase: "queued", started_at: "", updated_at: "" } }, 202),
        );
      }
      return Promise.resolve(json(available));
    });
    renderPage();
    expect(await screen.findByText("Retune 1.2.0 is available")).toBeInTheDocument();
    expect(screen.getByText("Faster check-ins.")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Update to 1.2.0" }));
    await waitFor(() => expect(posted).toEqual({ version: "1.2.0" }));
  });

  it("does not offer read-only admins an update", async () => {
    role = "read_only";
    fetchMock.mockImplementation(() => Promise.resolve(json(available)));
    renderPage();
    expect(await screen.findByText("Retune 1.2.0 is available")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Update to/ })).not.toBeInTheDocument();
  });

  it("says why when nothing can apply the update", async () => {
    fetchMock.mockImplementation(() =>
      Promise.resolve(json({ ...available, mode: "none", mode_note: "No updater is running." })),
    );
    renderPage();
    expect(await screen.findByText("No updater is running.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Update to/ })).not.toBeInTheDocument();
  });

  it("shows an update in progress, and how a failed one was rolled back", async () => {
    fetchMock.mockImplementation(() =>
      Promise.resolve(
        json({
          ...available,
          state: {
            id: "u1",
            version: "1.2.0",
            from_version: "1.1.0",
            phase: "rolled_back",
            error: "the new server is unhealthy",
            backup: "/backups/retune-1.1.0-to-1.2.0.dump",
            started_at: "",
            updated_at: new Date().toISOString(),
          },
        }),
      ),
    );
    renderPage();
    expect(await screen.findByText(/Rolled back/)).toBeInTheDocument();
    expect(screen.getByText("the new server is unhealthy")).toBeInTheDocument();
    expect(screen.getByText("/backups/retune-1.1.0-to-1.2.0.dump")).toBeInTheDocument();
  });

  it("says the server is up to date", async () => {
    fetchMock.mockImplementation(() => Promise.resolve(json({ ...available, version: "1.2.0", update_available: false })));
    renderPage();
    expect(await screen.findByText("This server is up to date.")).toBeInTheDocument();
  });

  it("holds the request for a second administrator when approvals are on", async () => {
    fetchMock.mockImplementation((_url: string, init?: RequestInit) =>
      Promise.resolve(
        init?.method === "POST"
          ? json({ approval: { id: "a1", kind: "server_update", status: "pending" } }, 202)
          : json({ ...available, approvals_required: true }),
      ),
    );
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Request update to 1.2.0" }));
    await waitFor(() => expect(fetchMock.mock.calls.some(([, init]) => init?.method === "POST")).toBe(true));
  });
});
