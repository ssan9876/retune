import { StatusDot } from "./StatusDot";
import "./FleetBar.css";

export interface FleetCounts {
  active: number;
  stale: number;
  retired: number;
}

const SEGMENTS: { key: keyof FleetCounts; label: string }[] = [
  { key: "active", label: "Active" },
  { key: "stale", label: "Stale" },
  { key: "retired", label: "Retired" },
];

/**
 * FleetBar shows the shape of the fleet as one proportional bar. Each segment
 * is also the filter for that status.
 */
export function FleetBar({
  counts,
  active,
  onSelect,
}: {
  counts: FleetCounts;
  active: string;
  onSelect: (filter: string) => void;
}) {
  const total = counts.active + counts.stale + counts.retired;
  if (total === 0) {
    return <p className="fleet__empty">No devices enrolled yet</p>;
  }
  return (
    <div className="fleet">
      <div className="fleet__bar" aria-hidden="true">
        {SEGMENTS.filter((segment) => counts[segment.key] > 0).map((segment) => {
          const count = counts[segment.key];
          return (
            <span
              key={segment.key}
              className={`fleet__segment fleet__segment--${segment.key}`}
              style={{ flexGrow: count, flexBasis: 0 }}
            />
          );
        })}
      </div>
      <div className="fleet__legend" role="group" aria-label="Filter devices by fleet status">
        <button type="button" aria-pressed={active === ""} onClick={() => onSelect("")}>All <b>{total}</b></button>
        {SEGMENTS.map((segment) => (
          <button
            type="button"
            key={segment.key}
            aria-label={`${segment.label}, ${counts[segment.key]} ${counts[segment.key] === 1 ? "device" : "devices"}`}
            aria-pressed={active === segment.key}
            onClick={() => onSelect(active === segment.key ? "" : segment.key)}
          >
            <StatusDot status={segment.key} label={segment.label} /> <b>{counts[segment.key]}</b>
          </button>
        ))}
      </div>
    </div>
  );
}
