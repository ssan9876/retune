import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { api } from "../api/client";
import type { Device, ListResponse } from "../api/types";
import { FleetBar } from "../components/FleetBar";
import type { FleetCounts } from "../components/FleetBar";
import { StatusDot } from "../components/StatusDot";
import { Button, EmptyState, ErrorNote, Spinner } from "../components/ui";
import { useList } from "../hooks/useList";
import "./Devices.css";

/** relative renders a timestamp as "3 minutes ago", or "never". */
export function relative(value?: string): string {
  if (!value) return "never";
  const seconds = Math.round((Date.now() - new Date(value).getTime()) / 1000);
  if (seconds < 60) return "just now";
  const steps: [number, string][] = [
    [60, "minute"],
    [24, "hour"],
    [7, "day"],
    [52, "week"],
  ];
  let amount = seconds / 60;
  let unit = "minute";
  for (const [size, name] of steps) {
    unit = name;
    if (amount < size) break;
    amount /= size;
  }
  const rounded = Math.round(amount);
  return `${rounded} ${unit}${rounded === 1 ? "" : "s"} ago`;
}

export default function Devices() {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("");
  const [counts, setCounts] = useState<FleetCounts>({ active: 0, stale: 0, retired: 0 });

  // "stale" is a property of active devices, so it filters client-side.
  const status = filter === "stale" ? "active" : filter === "retired" ? "retired" : "";
  const { items, total, loading, error, offset, setOffset } = useList<Device>("/devices", {
    search,
    status,
  });

  // The fleet bar summarises the whole fleet, not just the current page.
  useEffect(() => {
    api
      .get<ListResponse<Device>>("/devices?limit=200")
      .then((page) => {
        const summary: FleetCounts = { active: 0, stale: 0, retired: 0 };
        for (const device of page.items) {
          if (device.status !== "active") summary.retired++;
          else if (device.stale) summary.stale++;
          else summary.active++;
        }
        setCounts(summary);
      })
      .catch(() => setCounts({ active: 0, stale: 0, retired: 0 }));
  }, [items]);

  const shown = filter === "stale" ? items.filter((device) => device.stale) : items;

  return (
    <>
      <div className="content__head">
        <h1>Devices</h1>
        <input
          className="devices__search"
          type="search"
          aria-label="Search devices"
          placeholder="Hostname, serial or model"
          value={search}
          onChange={(event) => {
            setOffset(0);
            setSearch(event.target.value);
          }}
        />
      </div>

      <FleetBar
        counts={counts}
        active={filter}
        onSelect={(next) => {
          setOffset(0);
          setFilter(next);
        }}
      />

      <ErrorNote error={error} />
      {loading ? <Spinner /> : null}

      {!loading && shown.length === 0 ? (
        search || filter ? (
          <EmptyState title="No devices match this search." />
        ) : (
          <EmptyState title="No devices yet.">
            <p>Create an enrollment token, then install the agent on a machine.</p>
            <p>
              <Link to="/tokens">Create a token</Link>
            </p>
          </EmptyState>
        )
      ) : null}

      {shown.length > 0 ? (
        <table className="devices__table">
          <thead>
            <tr>
              <th>Hostname</th>
              <th>Status</th>
              <th>Operating system</th>
              <th>Last seen</th>
              <th>Agent</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((device) => (
              <tr key={device.id}>
                <td>
                  <Link to={`/devices/${device.id}`}>{device.hostname}</Link>
                </td>
                <td>
                  <StatusDot
                    status={device.status === "active" && device.stale ? "stale" : device.status}
                  />
                </td>
                <td>{device.os_version || "—"}</td>
                <td>{relative(device.last_seen_at)}</td>
                <td className="mono">{device.agent_version || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}

      {total > items.length ? (
        <div className="pager">
          <Button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 50))}>
            Previous
          </Button>
          <span>
            {offset + 1}–{offset + items.length} of {total}
          </span>
          <Button disabled={offset + items.length >= total} onClick={() => setOffset(offset + 50)}>
            Next
          </Button>
        </div>
      ) : null}
    </>
  );
}
