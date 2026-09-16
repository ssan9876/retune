import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Alerts from "./Alerts";

const fetchMock = vi.fn();
let canWrite = false;

vi.mock("../session/SessionContext", () => ({
  useSession: () => ({ admin: { role: canWrite ? "admin" : "read_only" }, canWrite }),
}));

const firing = [
  {
    rule_id: "r1",
    rule_name: "Quiet machines",
    rule_kind: "device_stale",
    subject_key: "device:d1",
    subject: "PC-QUIET has never checked in",
    firing_since: "2026-09-16T09:00:00Z",
    notified_at: "2026-09-16T09:05:00Z",
  },
];

const rules = [
  {
    id: "r1",
    name: "Quiet machines",
    kind: "device_stale",
    params: { hours: 24 },
    description: "a device has not checked in for 24 hours",
    channel_id: "c1",
    channel_name: "Ops mailbox",
    channel_kind: "email",
    enabled: true,
    created_at: "2026-09-16T08:00:00Z",
    updated_at: "2026-09-16T08:00:00Z",
    created_by: "ops@example.com",
  },
];

const channels = [
  {
    id: "c1",
    name: "Ops mailbox",
    kind: "email",
    config: { to: ["ops@example.com"] },
    enabled: true,
    has_secret: false,
    created_at: "2026-09-16T08:00:00Z",
    updated_at: "2026-09-16T08:00:00Z",
    created_by: "ops@example.com",
  },
  {
    id: "c2",
    name: "Ops webhook",
    kind: "webhook",
    config: { url: "https://hooks.example.com/retune" },
    enabled: true,
    has_secret: true,
    created_at: "2026-09-16T08:00:00Z",
    updated_at: "2026-09-16T08:00:00Z",
    created_by: "ops@example.com",
  },
];

const deliveries = [
  {
    id: "d1",
    rule_id: "r1",
    rule_name: "Quiet machines",
    channel_name: "Ops mailbox",
    at: "2026-09-16T09:05:00Z",
    ok: false,
    detail: "dial smtp.example.com:587: connection refused",
    firing: 1,
    resolved: 0,
  },
];

/** route answers each of the page's four listings from its own fixture, so a
 * test can change one without rewriting the others. */
function route(url: string): unknown {
  if (url.includes("/alert-rules")) return { items: rules };
  if (url.includes("/alert-deliveries")) return { items: deliveries };
  if (url.includes("/notification-channels")) return { items: channels };
  return { items: firing };
}

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
  canWrite = false;
  fetchMock.mockImplementation((input: RequestInfo) =>
    Promise.resolve(
      new Response(JSON.stringify(route(String(input))), {
        headers: { "Content-Type": "application/json" },
      }),
    ),
  );
});

/** section returns one of the page's four panes by its heading, so a test
 * asserts on the table it means rather than the first match on a page that
 * shows the same rule name four times. */
function section(name: string): HTMLElement {
  const pane = screen.getByRole("heading", { name }).closest(".alerts__section");
  if (!pane) throw new Error(`no section ${name}`);
  return pane as HTMLElement;
}

describe("Alerts", () => {
  it("leads with what is wrong right now", async () => {
    render(<Alerts />);
    const now = await waitFor(() => section("Firing now"));
    expect(within(now).getByText("PC-QUIET has never checked in")).toBeInTheDocument();
    expect(within(now).getByText("sent")).toBeInTheDocument();
  });

  it("explains each rule in the server's own words", async () => {
    render(<Alerts />);
    const pane = await waitFor(() => section("Rules"));
    expect(within(pane).getByText("a device has not checked in for 24 hours")).toBeInTheDocument();
    expect(within(pane).getByText("Ops mailbox")).toBeInTheDocument();
  });

  it("says a webhook is signed without showing the secret", async () => {
    render(<Alerts />);
    const pane = await waitFor(() => section("Channels"));
    expect(within(pane).getByText("https://hooks.example.com/retune")).toBeInTheDocument();
    expect(within(pane).getByText("signed")).toBeInTheDocument();
  });

  it("says why a delivery failed", async () => {
    render(<Alerts />);
    const pane = await waitFor(() => section("Recent deliveries"));
    expect(within(pane).getByText(/connection refused/)).toBeInTheDocument();
    expect(within(pane).getByText("failed")).toBeInTheDocument();
  });

  it("offers no controls to a read-only admin", async () => {
    render(<Alerts />);
    await waitFor(() => section("Rules"));
    expect(screen.queryByRole("button", { name: "Add rule" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Send test" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Pause" })).not.toBeInTheDocument();
  });

  it("lets an admin add a rule, offering only the chosen kind's parameter", async () => {
    canWrite = true;
    render(<Alerts />);
    await userEvent.click(await screen.findByRole("button", { name: "Add rule" }));
    const dialog = screen.getByRole("dialog", { name: "Add a rule" });

    // The stale rule is the only kind with a threshold, so the field appears
    // with it rather than sitting on the form for every kind.
    expect(screen.queryByLabelText("Hours of silence")).not.toBeInTheDocument();
    await userEvent.selectOptions(
      within(dialog).getByLabelText("Fires when"),
      "A device stops checking in",
    );
    expect(within(dialog).getByLabelText("Hours of silence")).toBeInTheDocument();

    await userEvent.type(within(dialog).getByLabelText("Name"), "Quiet machines");
    await userEvent.click(within(dialog).getByRole("button", { name: "Add rule" }));

    await waitFor(() => {
      const posted = fetchMock.mock.calls.find(
        (call) => String(call[0]).includes("/alert-rules") && call[1]?.method === "POST",
      );
      expect(posted).toBeDefined();
      expect(JSON.parse(String(posted?.[1]?.body))).toMatchObject({
        name: "Quiet machines",
        kind: "device_stale",
        params: { hours: 24 },
      });
    });
  });
});
