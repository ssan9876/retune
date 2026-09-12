import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { SessionProvider, useSession } from "./SessionContext";

const fetchMock = vi.fn();

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
});

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const admin = {
  id: "1",
  email: "ops@example.com",
  role: "admin",
  totp_enabled: false,
  disabled: false,
  created_at: "2026-09-12T12:00:00Z",
};

function Probe() {
  const { admin: current, loading, needsSetup, signIn, signOut, canWrite } = useSession();
  if (loading) return <p>Checking…</p>;
  return (
    <div>
      <p>{current ? `Signed in as ${current.email}` : "Signed out"}</p>
      <p>{needsSetup ? "Needs setup" : "Ready"}</p>
      <p>{canWrite ? "Can write" : "Read only"}</p>
      <button onClick={() => void signIn("ops@example.com", "correct horse battery")}>Sign in</button>
      <button onClick={() => void signOut()}>Sign out</button>
    </div>
  );
}

describe("SessionProvider", () => {
  it("starts signed out and signs in", async () => {
    fetchMock
      .mockResolvedValueOnce(json({ code: "unauthenticated", message: "sign in" }, 401))
      .mockResolvedValueOnce(json({ needs_setup: false }))
      .mockResolvedValueOnce(
        json({ admin, csrf_token: "csrf-1", expires_at: "2026-09-13T00:00:00Z" }),
      );

    render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await screen.findByText("Signed out");
    expect(screen.getByText("Ready")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await screen.findByText("Signed in as ops@example.com");
    expect(screen.getByText("Can write")).toBeInTheDocument();
  });

  it("reports a read-only admin", async () => {
    fetchMock
      .mockResolvedValueOnce(
        json({ admin: { ...admin, role: "read_only" }, csrf_token: "c", expires_at: "x" }),
      )
      .mockResolvedValueOnce(json({ needs_setup: false }));

    render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await screen.findByText("Signed in as ops@example.com");
    expect(screen.getByText("Read only")).toBeInTheDocument();
  });

  it("signs out", async () => {
    fetchMock
      .mockResolvedValueOnce(json({ admin, csrf_token: "csrf-1", expires_at: "x" }))
      .mockResolvedValueOnce(json({ needs_setup: false }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));

    render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await screen.findByText("Signed in as ops@example.com");
    await userEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await waitFor(() => expect(screen.getByText("Signed out")).toBeInTheDocument());
  });
});
