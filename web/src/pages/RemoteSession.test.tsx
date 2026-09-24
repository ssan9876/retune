import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import RemoteSession from "./RemoteSession";

const fetchMock = vi.fn();

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const session = {
  id: "s1",
  device_id: "d1",
  started_by: "ops@example.com",
  reason: "ticket 7",
  status: "active",
  created_at: new Date().toISOString(),
};

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/remote-sessions/s1"]}>
      <Routes>
        <Route path="/remote-sessions/:id" element={<RemoteSession />} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
});

describe("RemoteSession", () => {
  it("shows the transcript, sends lines, and ends the session", async () => {
    const posts: { url: string; body: unknown }[] = [];
    let polls = 0;
    fetchMock.mockImplementation((url: string, init?: { method?: string; body?: string }) => {
      if (init?.method === "POST") {
        posts.push({ url: String(url), body: init.body ? JSON.parse(init.body) : undefined });
        return Promise.resolve(new Response(null, { status: 204 }));
      }
      polls++;
      if (polls === 1) {
        return Promise.resolve(
          json({
            session,
            chunks: [
              { seq: 1, stream: "in", data: "hostname\n", at: "" },
              { seq: 2, stream: "out", data: "PC-042\n", at: "" },
            ],
          }),
        );
      }
      // Later polls wait; answer slowly so the test controls the pace.
      return new Promise((resolve) => setTimeout(() => resolve(json({ session, chunks: [] })), 200));
    });
    renderPage();
    expect(await screen.findByText("PS> hostname")).toBeInTheDocument();
    expect(screen.getByText("PC-042")).toBeInTheDocument();
    expect(screen.getByText("connected")).toBeInTheDocument();

    await userEvent.type(screen.getByLabelText("Command"), "Get-Date{Enter}");
    await waitFor(() => expect(posts[0]).toEqual({ url: expect.stringContaining("/remote-sessions/s1/input"), body: { data: "Get-Date\n" } }));
    expect(screen.getByLabelText("Command")).toHaveValue("");

    await userEvent.click(screen.getByRole("button", { name: "End session" }));
    await waitFor(() => expect(posts.some((p) => p.url.includes("/remote-sessions/s1/end"))).toBe(true));
  });

  it("shows an ended session read-only, with why it ended", async () => {
    fetchMock.mockResolvedValue(
      json({ session: { ...session, status: "ended", end_reason: "nothing was typed for fifteen minutes" }, chunks: [] }),
    );
    renderPage();
    expect(await screen.findByText(/nothing was typed for fifteen minutes/)).toBeInTheDocument();
    expect(screen.queryByLabelText("Command")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "End session" })).not.toBeInTheDocument();
  });
});
