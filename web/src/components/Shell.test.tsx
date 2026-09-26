import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import { Shell } from "./Shell";

const signOut = vi.fn();
let role = "admin";
let scope: string[] | null = null;

vi.mock("../session/SessionContext", () => ({
  useSession: () => ({ admin: { email: "ops@example.com", role, scope }, canWrite: role === "admin", signOut }),
}));

function renderShell(path = "/devices") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Shell>
        <h1>Devices</h1>
      </Shell>
    </MemoryRouter>,
  );
}

describe("Shell", () => {
  it("groups the nav and marks the page you are on", () => {
    renderShell("/compliance");
    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(within(nav).getByText("Endpoint security")).toBeInTheDocument();
    expect(within(nav).getByRole("link", { name: "Compliance policies" })).toHaveAttribute(
      "aria-current",
      "page",
    );
    expect(within(nav).getByRole("link", { name: "All devices" })).not.toHaveAttribute("aria-current");
  });

  it("names the route in the breadcrumb, section included", () => {
    renderShell("/profiles");
    const crumbs = screen.getByRole("navigation", { name: "Breadcrumb" });
    expect(crumbs).toHaveTextContent("Home");
    expect(crumbs).toHaveTextContent("Deployment");
    expect(crumbs).toHaveTextContent("Configuration profiles");
  });

  // A device's own page is not a nav entry, but it is still under Devices.
  it("keeps a detail page under its section", () => {
    renderShell("/devices/01a0-1");
    expect(screen.getByRole("navigation", { name: "Breadcrumb" })).toHaveTextContent("All devices");
  });

  it("collapses the rail to icons and back", async () => {
    const { container } = renderShell();
    expect(container.querySelector(".shell")).not.toHaveClass("shell--collapsed");
    await userEvent.click(screen.getByRole("button", { name: "Collapse navigation" }));
    expect(container.querySelector(".shell")).toHaveClass("shell--collapsed");
    // The links survive the collapse; it is their labels that are hidden, so
    // the rail stays navigable by keyboard and to a screen reader.
    expect(screen.getByRole("link", { name: "All devices" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Expand navigation" }));
    expect(container.querySelector(".shell")).not.toHaveClass("shell--collapsed");
  });

  it("searches the pages rather than pretending to search the fleet", async () => {
    renderShell();
    await userEvent.type(screen.getByRole("searchbox", { name: "Search pages" }), "compl");
    const hit = screen.getByRole("button", { name: /Compliance policies/ });
    expect(hit).toBeInTheDocument();
    await userEvent.click(hit);
    expect(screen.getByRole("navigation", { name: "Breadcrumb" })).toHaveTextContent(
      "Compliance policies",
    );
  });

  it("puts the account and sign-out behind the avatar", async () => {
    renderShell();
    await userEvent.click(screen.getByRole("button", { name: "Account: ops@example.com" }));
    expect(screen.getByText("ops@example.com")).toBeInTheDocument();
    expect(screen.getByText("Administrator")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("menuitem", { name: "Sign out" }));
    expect(signOut).toHaveBeenCalled();
  });

  it("says when the account is read-only", () => {
    role = "read_only";
    renderShell();
    expect(screen.getByText("Read-only")).toBeInTheDocument();
    role = "admin";
  });

  it("leaves out the fleet pages for an admin limited to some groups", () => {
    scope = ["g1"];
    try {
      renderShell("/devices");
      const nav = screen.getByRole("navigation", { name: "Main" });
      expect(within(nav).getByRole("link", { name: "All devices" })).toBeInTheDocument();
      for (const name of ["Enrollment", "Alerts", "Admins", "API tokens", "Audit log"]) {
        expect(within(nav).queryByRole("link", { name })).not.toBeInTheDocument();
      }
    } finally {
      scope = null;
    }
  });

  describe("with a newer release out", () => {
    const server = {
      version: "1.1.0",
      stamped: true,
      mode: "docker",
      update_available: true,
      approvals_required: false,
      latest: { version: "1.2.0", prerelease: false, published_at: "", notes: "" },
    };
    afterEach(() => {
      vi.unstubAllGlobals();
      role = "admin";
    });
    function serve() {
      vi.stubGlobal(
        "fetch",
        vi.fn(() =>
          Promise.resolve(
            new Response(JSON.stringify(server), { status: 200, headers: { "Content-Type": "application/json" } }),
          ),
        ),
      );
    }

    it("tells an administrator, and shows the running version", async () => {
      serve();
      renderShell();
      expect(await screen.findByText(/Retune 1.2.0 is available/)).toBeInTheDocument();
      expect(screen.getByRole("link", { name: "Review and update" })).toHaveAttribute("href", "/server-update");
      expect(screen.getByText("Retune 1.1.0")).toBeInTheDocument();
    });

    it("does not nag read-only admins", async () => {
      role = "read_only";
      serve();
      renderShell();
      expect(await screen.findByText("Retune 1.1.0")).toBeInTheDocument();
      expect(screen.queryByText(/is available/)).not.toBeInTheDocument();
    });
  });
});
