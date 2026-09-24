import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { api } from "../api/client";
import type { Dashboard, Device } from "../api/types";
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
  const [params, setParams] = useSearchParams();
  const search = params.get("search") ?? "";
  const filter = params.get("status") ?? "";
  const compliance = params.get("compliance") ?? "";
  const [counts, setCounts] = useState<FleetCounts | null>(null);
  const [countsError, setCountsError] = useState<unknown>(null);

  const { items, total, loading, error, offset, setOffset } = useList<Device>("/devices", {
    search,
    status: filter,
    compliance,
  });

  function setFilterParam(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setOffset(0);
    setParams(next, { replace: true });
  }

  function clearFilters() {
    const next = new URLSearchParams(params);
    next.delete("search");
    next.delete("status");
    next.delete("compliance");
    setOffset(0);
    setParams(next, { replace: true });
  }

  // The fleet bar summarises the whole fleet, not just the current page, so
  // it comes from the dashboard's SQL-computed buckets rather than a capped
  // device page - and for the same reason it is fetched once on mount rather
  // than following `items`, which would re-run five fleet-wide aggregates on
  // every search keystroke and every page turn.
  useEffect(() => {
    api
      .get<Dashboard>("/dashboard")
      .then((dashboard) => {
        const { active, stale, retired } = dashboard.devices;
        setCounts({ active, stale, retired });
        setCountsError(null);
      })
      .catch(setCountsError);
  }, []);

  const hasFilters = Boolean(search || filter || compliance);

  return (
    <>
      <div className="content__head">
        <h1>Devices</h1>
        <div className="devices__head-actions">
          <input
            className="devices__search"
            type="search"
            aria-label="Search devices"
            placeholder="Hostname, serial or model"
            value={search}
            onChange={(event) => {
              setFilterParam("search", event.target.value);
            }}
          />
          <a className="button" href="/api/admin/v1/devices/export.csv">
            Export all devices
          </a>
        </div>
      </div>

      {counts ? <FleetBar counts={counts} active={filter} onSelect={(next) => setFilterParam("status", next)} /> : null}
      <ErrorNote error={countsError} />

      {hasFilters ? (
        <div className="devices__filters" role="status">
          <span>
            Showing {compliance ? compliance.replace(/_/g, " ") + " " : ""}
            {filter || "all"} devices{search ? ` matching “${search}”` : ""}.
          </span>
          <Button variant="quiet" onClick={clearFilters}>Clear filters</Button>
        </div>
      ) : null}

      <ErrorNote error={error} />
      {loading ? <Spinner /> : null}

      {!loading && !error && items.length === 0 ? (
        hasFilters ? (
          <EmptyState title="No devices match these filters.">
            <p>Try another search or clear the current filters.</p>
            <p><Button onClick={clearFilters}>Clear filters</Button></p>
          </EmptyState>
        ) : (
          <EmptyState title="No devices yet.">
            <p>Create an enrollment token, then install the agent on a machine.</p>
            <p>
              <Link to="/tokens">Create a token</Link>
            </p>
          </EmptyState>
        )
      ) : null}

      {items.length > 0 ? (
        <div className="table-scroll">
          <table className="devices__table">
            <thead>
              <tr>
                <th>Hostname</th>
                <th>Status</th>
                <th>Compliance</th>
                <th>Operating system</th>
                <th>Last seen</th>
                <th>Agent</th>
              </tr>
            </thead>
            <tbody>
              {items.map((device) => (
                <tr key={device.id}>
                  <td>
                    <Link to={`/devices/${device.id}`}>{device.hostname}</Link>
                  </td>
                  <td>
                    <StatusDot
                      status={device.status === "active" && device.stale ? "stale" : device.status}
                    />
                  </td>
                  <td>
                    <StatusDot status={device.compliance} />
                  </td>
                  <td>{device.os_version || "—"}</td>
                  <td>{relative(device.last_seen_at)}</td>
                  <td className="mono">{device.agent_version || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
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
