import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Tokens, { downloadLink, macSettings } from "./Tokens";

const fetchMock = vi.fn();

const session = { agentDownloadUrl: "https://github.com/ssan9876/retune/releases/latest" as string | null };

vi.mock("../session/SessionContext", () => ({
  useSession: () => ({ admin: { role: "admin" }, canWrite: true, agentDownloadUrl: session.agentDownloadUrl }),
}));

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function mockTokens(items: unknown[]) {
  fetchMock.mockImplementation((_url: string, init?: { method?: string }) => {
    if (init?.method === "POST") {
      return Promise.resolve(
        json({ id: "t1", token: "rt_secret", label: "Office laptops" }, 201),
      );
    }
    return Promise.resolve(json({ items, total: items.length, limit: 50, offset: 0 }));
  });
}

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
  session.agentDownloadUrl = "https://github.com/ssan9876/retune/releases/latest";
});

describe("Tokens", () => {
  it("creates a token and shows it once with the install command", async () => {
    mockTokens([]);
    render(<Tokens />);
    await screen.findByText("No enrollment tokens yet.");

    await userEvent.click(screen.getByRole("button", { name: "Create token" }));
    await userEvent.type(screen.getByLabelText("Label"), "Office laptops");
    await userEvent.click(screen.getByRole("button", { name: "Create" }));

    expect(await screen.findByText("rt_secret")).toBeInTheDocument();
    expect(screen.getByText(/msiexec/)).toHaveTextContent("rt_secret");
    expect(screen.getByRole("link", { name: "retune-agent.msi" })).toHaveAttribute(
      "href",
      "https://github.com/ssan9876/retune/releases/latest/download/retune-agent.msi",
    );
    expect(screen.getByRole("link", { name: "retune-agent.pkg" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy macOS settings" })).toBeInTheDocument();
  });

  it("leaves out download guidance when the server names no download URL", async () => {
    session.agentDownloadUrl = null;
    mockTokens([]);
    render(<Tokens />);
    await screen.findByText("No enrollment tokens yet.");
    await userEvent.click(screen.getByRole("button", { name: "Create token" }));
    await userEvent.click(screen.getByRole("button", { name: "Create" }));

    expect(await screen.findByText("rt_secret")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "retune-agent.msi" })).not.toBeInTheDocument();
  });

  it("builds download links for GitHub releases and for a plain folder", () => {
    expect(downloadLink("https://github.com/o/r/releases/latest/", "retune-agent.pkg")).toBe(
      "https://github.com/o/r/releases/latest/download/retune-agent.pkg",
    );
    expect(downloadLink("https://files.example.com/retune/", "retune-agent.msi")).toBe(
      "https://files.example.com/retune/retune-agent.msi",
    );
  });

  it("escapes the Mac settings it writes", () => {
    const plist = macSettings("https://mdm.example.com", "a<b&c");
    expect(plist).toContain("<string>https://mdm.example.com</string>");
    expect(plist).toContain("<string>a&lt;b&amp;c</string>");
  });

  it("lists tokens without any plaintext", async () => {
    mockTokens([
      {
        id: "t1",
        label: "Office laptops",
        max_uses: 5,
        use_count: 2,
        created_by: "ops@example.com",
        created_at: "2026-09-12T12:00:00Z",
      },
    ]);
    render(<Tokens />);
    expect(await screen.findByText("Office laptops")).toBeInTheDocument();
    expect(screen.getByText("2 of 5")).toBeInTheDocument();
    expect(screen.queryByText(/rt_/)).not.toBeInTheDocument();
  });
});
