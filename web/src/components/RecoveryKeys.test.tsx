import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { RecoveryKeys } from "./RecoveryKeys";

const fetchMock = vi.fn();

vi.mock("../session/SessionContext", () => ({
  useSession: () => ({ admin: { role: "admin" }, canWrite: true, canOperate: true }),
}));

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const key = {
  id: "k1",
  device_id: "d1",
  hostname: "LAPTOP",
  volume_id: "C:",
  method: "XtsAes256",
  created_at: "2026-09-13T00:00:00Z",
  updated_at: "2026-09-13T00:00:00Z",
};

const password = "123456-234567-345678";

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
});

describe("RecoveryKeys", () => {
  it("lists escrowed volumes without the key", async () => {
    fetchMock.mockImplementation(() => Promise.resolve(json({ items: [key] })));
    render(<RecoveryKeys deviceId="d1" />);

    await screen.findByText("C:");
    expect(screen.getByText("XtsAes256")).toBeInTheDocument();
    expect(screen.queryByText(password)).not.toBeInTheDocument();
  });

  it("shows nothing at all when no key is escrowed", async () => {
    fetchMock.mockImplementation(() => Promise.resolve(json({ items: [] })));
    const { container } = render(<RecoveryKeys deviceId="d1" />);
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });

  it("warns that revealing a key is recorded, then shows it", async () => {
    const posted: { url: string; body: unknown }[] = [];
    fetchMock.mockImplementation((url: string, init?: { method?: string; body?: string }) => {
      if (init?.method === "POST") {
        posted.push({ url: String(url), body: JSON.parse(init.body ?? "{}") });
        return Promise.resolve(json({ ...key, recovery_password: password }));
      }
      return Promise.resolve(json({ items: [key] }));
    });
    render(<RecoveryKeys deviceId="d1" />);
    await screen.findByText("C:");

    await userEvent.click(screen.getByRole("button", { name: "Show the key" }));
    expect(screen.getByText(/is recorded against your account/)).toBeInTheDocument();

    await userEvent.type(screen.getByLabelText("Why do you need it?"), "help desk call 1234");
    const confirm = screen.getAllByRole("button", { name: "Show the key" });
    await userEvent.click(confirm[confirm.length - 1]);

    expect(await screen.findByText(password)).toBeInTheDocument();
    expect(posted).toHaveLength(1);
    expect(posted[0].url).toContain("/bitlocker-keys/k1/reveal");
    expect(posted[0].body).toMatchObject({ reason: "help desk call 1234" });
  });

  it("surfaces a refusal rather than a key", async () => {
    fetchMock.mockImplementation((_url: string, init?: { method?: string }) => {
      if (init?.method === "POST") {
        return Promise.resolve(json({ code: "forbidden", message: "admin role required" }, 403));
      }
      return Promise.resolve(json({ items: [key] }));
    });
    render(<RecoveryKeys deviceId="d1" />);
    await screen.findByText("C:");

    await userEvent.click(screen.getByRole("button", { name: "Show the key" }));
    const confirm = screen.getAllByRole("button", { name: "Show the key" });
    await userEvent.click(confirm[confirm.length - 1]);

    expect(await screen.findByRole("alert")).toHaveTextContent("admin role required");
    expect(screen.queryByText(password)).not.toBeInTheDocument();
  });
});
