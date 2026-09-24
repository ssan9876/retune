import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { FleetBar } from "./FleetBar";

describe("FleetBar", () => {
  it("sizes each segment by its share of the fleet", () => {
    const { container } = render(
      <FleetBar counts={{ active: 30, stale: 10, retired: 10 }} active="" onSelect={vi.fn()} />,
    );
    expect(container.querySelector(".fleet__segment--active")).toHaveStyle({ flexGrow: "30" });
    expect(container.querySelector(".fleet__segment--stale")).toHaveStyle({ flexGrow: "10" });
  });

  it("filters when a segment is chosen, and clears when chosen again", async () => {
    const onSelect = vi.fn();
    const { rerender } = render(
      <FleetBar counts={{ active: 1, stale: 0, retired: 0 }} active="" onSelect={onSelect} />,
    );
    await userEvent.click(screen.getByRole("button", { name: "Active, 1 device" }));
    expect(onSelect).toHaveBeenCalledWith("active");

    rerender(<FleetBar counts={{ active: 1, stale: 0, retired: 0 }} active="active" onSelect={onSelect} />);
    await userEvent.click(screen.getByRole("button", { name: "Active, 1 device" }));
    expect(onSelect).toHaveBeenLastCalledWith("");
  });

  it("says so when no devices are enrolled", () => {
    render(<FleetBar counts={{ active: 0, stale: 0, retired: 0 }} active="" onSelect={vi.fn()} />);
    expect(screen.getByText("No devices enrolled yet")).toBeInTheDocument();
  });
});
