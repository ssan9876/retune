import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import AgentVersions from "./AgentVersions";

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

const build = {
  id: "v1",
  version: "1.2.3",
  sha256: "abc123",
  size_bytes: 5242880,
  notes: "pilot build",
  created_at: "2026-09-13T00:00:00Z",
  created_by: "ops@example.com",
  key_id: "0123456789abcdef",
};

function listOnly() {
  fetchMock.mockImplementation((url: string) => {
    if (String(url).includes("/agent-versions?")) {
      return Promise.resolve(json({ items: [build], total: 1, limit: 50, offset: 0 }));
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

describe("AgentVersions", () => {
  it("lists builds with their version, size and uploader", async () => {
    listOnly();
    render(<AgentVersions />);
    expect(await screen.findByText("1.2.3")).toBeInTheDocument();
    expect(screen.getByText("5.0 MB")).toBeInTheDocument();
    expect(screen.getByText("ops@example.com")).toBeInTheDocument();
  });

  it("states plainly what assigning a build does", async () => {
    listOnly();
    render(<AgentVersions />);
    await screen.findByText("1.2.3");

    await userEvent.click(screen.getByRole("button", { name: "Assign" }));
    expect(
      await screen.findByText(/replaces the agent on every device in the group/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/goes back to what it was running by itself/i)).toBeInTheDocument();
  });

  it("shows the rollback deadline hint", async () => {
    listOnly();
    render(<AgentVersions />);
    await screen.findByText("1.2.3");

    await userEvent.click(screen.getByRole("button", { name: "Assign" }));
    await screen.findByLabelText("Group");
    expect(
      screen.getByText(/if the new agent has not checked in by then, the previous build is put back/i),
    ).toBeInTheDocument();
  });

  it("sends the chosen deadline with the assignment", async () => {
    listOnly();
    render(<AgentVersions />);
    await screen.findByText("1.2.3");

    await userEvent.click(screen.getByRole("button", { name: "Assign" }));
    await screen.findByLabelText("Group");
    const deadlineInput = screen.getByLabelText(/rollback deadline/i);
    await userEvent.clear(deadlineInput);
    await userEvent.type(deadlineInput, "120");
    await userEvent.click(screen.getByRole("button", { name: "Assign to group" }));

    const call = fetchMock.mock.calls.find(([url]) => String(url).includes("/assignments"));
    const posted = JSON.parse(String(call?.[1]?.body));
    expect(posted.item_kind).toBe("agent");
    expect(posted.options).toMatchObject({ deadline_seconds: 120 });
  });

  it("uploads the file as a raw body, not JSON", async () => {
    fetchMock.mockImplementation((url: string, init?: { method?: string; body?: unknown }) => {
      if (init?.method === "POST" && String(url).includes("/agent-versions?")) {
        return Promise.resolve(json({ ...build, id: "v2" }, 201));
      }
      return Promise.resolve(json({ items: [], total: 0, limit: 50, offset: 0 }));
    });
    render(<AgentVersions />);
    await screen.findByText("No builds yet.");

    await userEvent.click(screen.getByRole("button", { name: "Upload build" }));
    const file = new File(["binary content"], "agent-1.2.3.exe", { type: "application/octet-stream" });
    await userEvent.upload(screen.getByLabelText("Build file"), file);
    const sigFile = new File(["{}"], "agent-1.2.3.exe.sig", { type: "application/octet-stream" });
    await userEvent.upload(screen.getByLabelText("Signature file"), sigFile);
    await userEvent.click(screen.getByRole("button", { name: "Upload" }));

    const call = fetchMock.mock.calls.find(
      (args: unknown[]) =>
        String(args[0]).includes("/agent-versions?") &&
        (args[1] as { method?: string } | undefined)?.method === "POST",
    );
    expect(call).toBeTruthy();
    const [url, init] = call as [string, { method?: string; body?: unknown; headers?: Record<string, string> }];
    expect(url).toContain("version=1.2.3");
    expect(init.body).toBe(file);
    expect(init.headers?.["Content-Type"]).toBe("application/octet-stream");
  });

  it("uploads the build with its signature sidecar in the header", async () => {
    fetchMock.mockImplementation((url: string, init?: { method?: string; body?: unknown }) => {
      if (init?.method === "POST" && String(url).includes("/agent-versions?")) {
        return Promise.resolve(json({ ...build, id: "v2" }, 201));
      }
      return Promise.resolve(json({ items: [], total: 0, limit: 50, offset: 0 }));
    });
    render(<AgentVersions />);
    await screen.findByText("No builds yet.");

    await userEvent.click(screen.getByRole("button", { name: "Upload build" }));
    const file = new File(["binary content"], "agent-1.2.3.exe", { type: "application/octet-stream" });
    await userEvent.upload(screen.getByLabelText("Build file"), file);
    const sigContents = JSON.stringify({ version: "1.2.3", sha256: "ab", key_id: "k", signature: "AAAA" });
    const sigFile = new File([sigContents], "agent-1.2.3.exe.sig", { type: "application/octet-stream" });
    await userEvent.upload(screen.getByLabelText("Signature file"), sigFile);
    await userEvent.click(screen.getByRole("button", { name: "Upload" }));

    const call = fetchMock.mock.calls.find(
      (args: unknown[]) =>
        String(args[0]).includes("/agent-versions?") &&
        (args[1] as { method?: string } | undefined)?.method === "POST",
    );
    expect(call).toBeTruthy();
    const [, init] = call as [string, { method?: string; body?: unknown; headers?: Record<string, string> }];
    expect(init.body).toBe(file);
    expect(init.headers?.["X-Retune-Signature"]).toBe(btoa(sigContents));
  });

  it("the upload button stays disabled until both files are picked", async () => {
    listOnly();
    render(<AgentVersions />);
    await screen.findByText("1.2.3");

    await userEvent.click(screen.getByRole("button", { name: "Upload build" }));
    const uploadButton = screen.getByRole("button", { name: "Upload" });
    expect(uploadButton).toBeDisabled();

    const file = new File(["binary content"], "agent-1.2.3.exe", { type: "application/octet-stream" });
    await userEvent.upload(screen.getByLabelText("Build file"), file);
    expect(uploadButton).toBeDisabled();

    const sigFile = new File(["{}"], "agent-1.2.3.exe.sig", { type: "application/octet-stream" });
    await userEvent.upload(screen.getByLabelText("Signature file"), sigFile);
    expect(uploadButton).not.toBeDisabled();
  });

  it("lists the key id beside each build", async () => {
    listOnly();
    render(<AgentVersions />);
    expect(await screen.findByText("1.2.3")).toBeInTheDocument();
    expect(screen.getByText("0123456789abcdef")).toBeInTheDocument();
  });
});
