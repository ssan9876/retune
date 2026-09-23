import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Apps, { cleanRule, installerTypeOf, parseExitCodes } from "./Apps";

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

  it("sends uninstall intent when that is what was chosen", async () => {
    listOnly();
    render(<Apps />);
    await screen.findByText("7-Zip");

    await userEvent.click(screen.getByRole("button", { name: "Assign" }));
    await screen.findByLabelText("What to do");
    await userEvent.selectOptions(screen.getByLabelText("What to do"), "uninstall");
    await userEvent.click(screen.getByRole("button", { name: "Assign to group" }));

    const call = fetchMock.mock.calls.find(([url]) => String(url).includes("/assignments"));
    expect(JSON.parse(String(call?.[1]?.body)).options).toMatchObject({ intent: "uninstall" });
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

  it("uploads an installer, then creates the app from it", async () => {
    const calls: { url: string; body: unknown }[] = [];
    fetchMock.mockImplementation((url: string, init?: { method?: string; body?: unknown }) => {
      if (init?.method === "POST") {
        calls.push({ url: String(url), body: init.body });
        if (String(url).includes("/app-packages")) {
          return Promise.resolve(json({ file_sha256: "ab".repeat(32), size_bytes: 6 }, 201));
        }
        return Promise.resolve(json({ ...app, id: "a3" }, 201));
      }
      return Promise.resolve(json({ items: [], total: 0, limit: 50, offset: 0 }));
    });
    render(<Apps />);
    await screen.findByText("No apps yet.");

    await userEvent.click(screen.getByRole("button", { name: "New app" }));
    await userEvent.type(screen.getByLabelText("Name"), "Contoso");
    await userEvent.click(screen.getByLabelText(/installer I upload/i));
    const file = new File(["an msi"], "Contoso Setup.msi", { type: "application/octet-stream" });
    await userEvent.upload(screen.getByLabelText("Installer file"), file);
    await userEvent.type(screen.getByLabelText("Product code"), "{{23170F69-40C1-2702-2600-000001000000}");
    await userEvent.click(screen.getByRole("button", { name: "Create app" }));

    await screen.findByText("No apps yet.");
    expect(calls).toHaveLength(2);
    expect(calls[0].url).toContain("/app-packages?file_name=Contoso%20Setup.msi");
    expect(calls[0].body).toBe(file);
    expect(JSON.parse(String(calls[1].body))).toMatchObject({
      name: "Contoso",
      source: "package",
      installer_type: "msi",
      file_name: "Contoso Setup.msi",
      file_sha256: "ab".repeat(32),
      success_exit_codes: [0, 3010, 1641],
      detection: { type: "msi_product_code", product_code: "{23170F69-40C1-2702-2600-000001000000}" },
    });
  });

  it("won't create a package app without an installer", async () => {
    listOnly();
    render(<Apps />);
    await screen.findByText("7-Zip");
    await userEvent.click(screen.getByRole("button", { name: "New app" }));
    await userEvent.type(screen.getByLabelText("Name"), "Contoso");
    await userEvent.click(screen.getByLabelText(/installer I upload/i));
    expect(screen.getByRole("button", { name: "Create app" })).toBeDisabled();
  });

  it("shows an uploaded app's file name in the list", async () => {
    fetchMock.mockImplementation(() =>
      Promise.resolve(
        json({
          items: [{ ...app, package_id: "", source: "package", file_name: "Contoso.msi" }],
          total: 1,
          limit: 50,
          offset: 0,
        }),
      ),
    );
    render(<Apps />);
    expect(await screen.findByText("Contoso.msi")).toBeInTheDocument();
  });
});

describe("package helpers", () => {
  it("reads exit codes", () => {
    expect(parseExitCodes("0, 3010,1641")).toEqual([0, 3010, 1641]);
    expect(parseExitCodes("0 1")).toEqual([0, 1]);
    expect(parseExitCodes("0, x")).toBeNull();
    expect(parseExitCodes("1.5")).toBeNull();
  });

  it("tells MSI from EXE by the file name", () => {
    expect(installerTypeOf("Setup.MSI")).toBe("msi");
    expect(installerTypeOf("setup.exe")).toBe("exe");
    expect(installerTypeOf("setup.msix")).toBe("");
  });

  it("keeps only the fields a rule's type uses", () => {
    expect(cleanRule({ type: "file", path: "C:\a.exe", key: "leftover", product_code: "" })).toEqual({
      type: "file",
      path: "C:\a.exe",
    });
    expect(
      cleanRule({ type: "registry", key: "SOFTWARE\X", value: "V", equals: "1", version_at_least: "2" }),
    ).toEqual({ type: "registry", key: "SOFTWARE\X", value: "V", equals: "1" });
  });
});
