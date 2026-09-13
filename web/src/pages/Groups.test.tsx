import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Groups from "./Groups";

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

const builtin = {
  id: "g-all",
  name: "All devices",
  description: "Every active device.",
  kind: "builtin",
  rule: "",
  member_count: 3,
  created_at: "2026-09-12T00:00:00Z",
  updated_at: "2026-09-12T00:00:00Z",
  evaluated_at: null,
};

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
});

describe("Groups", () => {
  it("lists groups with their kind and size", async () => {
    fetchMock.mockImplementation(() => Promise.resolve(json({ items: [builtin] })));
    render(<Groups />);

    await screen.findByText("All devices");
    expect(screen.getByText("Built in")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
  });

  it("offers no edit or delete for the built-in group", async () => {
    fetchMock.mockImplementation(() => Promise.resolve(json({ items: [builtin] })));
    render(<Groups />);

    await screen.findByText("All devices");
    expect(screen.queryByRole("button", { name: "Delete" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Edit" })).not.toBeInTheDocument();
  });

  it("previews how many devices a rule matches", async () => {
    fetchMock.mockImplementation((url: string, init?: { method?: string }) => {
      if (String(url).includes("/groups/preview")) {
        return Promise.resolve(
          json({
            items: [{ id: "d1", hostname: "DESKTOP-A" }],
            total: 1,
            limit: 50,
            offset: 0,
          }),
        );
      }
      if (init?.method === "POST") return Promise.resolve(json({ ...builtin, id: "g-new" }, 201));
      return Promise.resolve(json({ items: [builtin] }));
    });
    render(<Groups />);
    await screen.findByText("All devices");

    await userEvent.click(screen.getByRole("button", { name: "New group" }));
    await userEvent.type(screen.getByLabelText("Rule"), "ram_gb >= 16");

    expect(await screen.findByText("Matches 1 device.", {}, { timeout: 3000 })).toBeInTheDocument();
    expect(screen.getByText("DESKTOP-A")).toBeInTheDocument();
  });

  it("shows why a rule does not parse", async () => {
    fetchMock.mockImplementation((url: string) => {
      if (String(url).includes("/groups/preview")) {
        return Promise.resolve(
          json({ code: "invalid_rule", message: 'unknown field "nope"', offset: 0 }, 400),
        );
      }
      return Promise.resolve(json({ items: [builtin] }));
    });
    render(<Groups />);
    await screen.findByText("All devices");

    await userEvent.click(screen.getByRole("button", { name: "New group" }));
    await userEvent.type(screen.getByLabelText("Rule"), "nope = 'x'");

    expect(await screen.findByRole("alert", {}, { timeout: 3000 })).toHaveTextContent(
      'unknown field "nope"',
    );
  });

  it("hides the rule editor for a group picked by hand", async () => {
    fetchMock.mockImplementation(() => Promise.resolve(json({ items: [builtin] })));
    render(<Groups />);
    await screen.findByText("All devices");

    await userEvent.click(screen.getByRole("button", { name: "New group" }));
    expect(screen.getByLabelText("Rule")).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText("Membership"), "static");
    expect(screen.queryByLabelText("Rule")).not.toBeInTheDocument();
  });
});
