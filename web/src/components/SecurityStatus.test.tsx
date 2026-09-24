import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SecurityStatus } from "./SecurityStatus";

function value(label: string): string {
  const term = screen.getByText(label, { selector: "dt" });
  return within(term.parentElement as HTMLElement).getByRole("definition").textContent ?? "";
}

describe("SecurityStatus", () => {
  it("shows what Defender and the firewall reported", () => {
    render(
      <SecurityStatus
        document={{
          defender: {
            running_mode: "Normal",
            antivirus_enabled: true,
            realtime_enabled: true,
            tamper_protected: false,
            signature_version: "1.459.335.0",
            signature_updated_at: new Date().toISOString(),
          },
          firewall: [
            { profile: "domain", enabled: true },
            { profile: "public", enabled: false },
          ],
        }}
      />,
    );
    expect(value("Defender")).toBe("Normal");
    expect(value("Real-time protection")).toBe("on");
    expect(value("Tamper Protection")).toBe("off");
    expect(value("Signatures")).toContain("1.459.335.0");
    expect(value("Last scans")).toBe("quick never, full never");
    expect(value("Firewall, domain")).toBe("on");
    expect(value("Firewall, public")).toBe("off");
    // Reported, but this profile was not among the answers.
    expect(value("Firewall, private")).toBe("not reported");
  });

  it("says not reported, never off, for an agent that sends neither block", () => {
    render(<SecurityStatus document={{ hostname: "OLD-AGENT" }} />);
    for (const label of ["Defender", "Real-time protection", "Tamper Protection", "Firewall, domain"]) {
      expect(value(label)).toBe("not reported");
    }
  });
});

describe("SecurityStatus Windows Update", () => {
  it("lists missing updates, security first", () => {
    render(
      <SecurityStatus
        document={{
          windows_updates: {
            scanned_at: new Date().toISOString(),
            pending: [
              { title: "A driver", security: false },
              { title: "2026-09 Cumulative Update (KB5065426)", kb: "KB5065426", severity: "Critical", security: true, reboot_required: true },
            ],
          },
        }}
      />,
    );
    expect(screen.getByText(/2 updates missing, 1 of them security/)).toBeInTheDocument();
    const items = screen.getAllByRole("listitem");
    expect(items[0]).toHaveTextContent("Critical security: 2026-09 Cumulative Update (KB5065426) (needs a restart)");
    expect(items[1]).toHaveTextContent("A driver");
  });

  it("says when nothing is missing, a search failed, or none has been reported", () => {
    const { rerender } = render(<SecurityStatus document={{ windows_updates: { scanned_at: new Date().toISOString(), pending: [] } }} />);
    expect(screen.getByText(/nothing missing/)).toBeInTheDocument();
    rerender(<SecurityStatus document={{ windows_updates: { scanned_at: new Date().toISOString(), pending: [], error: "0x8024402C" } }} />);
    expect(screen.getByText(/failed: 0x8024402C/)).toBeInTheDocument();
    rerender(<SecurityStatus document={{}} />);
    expect(screen.getByText(/not reported yet/)).toBeInTheDocument();
  });
});
