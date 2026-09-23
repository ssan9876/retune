import { useState } from "react";

import type { AuditEntry } from "../api/types";
import { Button, EmptyState, ErrorNote, Spinner } from "../components/ui";
import { useList } from "../hooks/useList";
import "./Audit.css";

/** describe flattens an entry's details into readable key=value pairs. */
function describe(details: Record<string, unknown>): string {
  return Object.entries(details ?? {})
    .map(([key, value]) => `${key}=${String(value)}`)
    .join(" ");
}

/**
 * dayBound turns a date input's YYYY-MM-DD into the RFC 3339 instant the
 * API wants: the start of that day, local time, or of the day after for an
 * inclusive "to" date.
 */
export function dayBound(day: string, endOfDay = false): string | undefined {
  if (!day) return undefined;
  const at = new Date(`${day}T00:00:00`);
  if (Number.isNaN(at.getTime())) return undefined;
  if (endOfDay) at.setDate(at.getDate() + 1);
  return at.toISOString();
}

export default function Audit() {
  const [actor, setActor] = useState("");
  const [action, setAction] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const filters = { actor, action, since: dayBound(from), until: dayBound(to, true) };
  const { items, total, loading, error, offset, setOffset } = useList<AuditEntry>("/audit", filters);

  const exportQuery = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) {
    if (value) exportQuery.set(key, value);
  }
  const exportSearch = exportQuery.toString();
  const exportHref = `/api/admin/v1/audit/export.csv${exportSearch ? `?${exportSearch}` : ""}`;
  const filtered = Boolean(actor || action || from || to);

  // Every filter change goes back to the first page.
  const change = (set: (value: string) => void) => (event: { target: { value: string } }) => {
    setOffset(0);
    set(event.target.value);
  };

  return (
    <>
      <div className="content__head">
        <h1>Audit</h1>
        <a className="button audit__export" href={exportHref}>
          Export CSV
        </a>
      </div>

      <div className="audit__filters">
        <label>
          Who
          <input type="search" value={actor} placeholder="Any admin" onChange={change(setActor)} />
        </label>
        <label>
          Action
          <input type="search" value={action} placeholder="e.g. device." onChange={change(setAction)} />
        </label>
        <label>
          From
          <input type="date" value={from} onChange={change(setFrom)} />
        </label>
        <label>
          To
          <input type="date" value={to} onChange={change(setTo)} />
        </label>
      </div>

      <ErrorNote error={error} />
      {loading ? <Spinner /> : null}
      {!loading && items.length === 0 ? (
        <EmptyState title={filtered ? "Nothing matches these filters." : "Nothing has happened yet."} />
      ) : null}

      {items.length > 0 ? (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Action</th>
                <th>Who</th>
                <th>Target</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {items.map((entry) => (
                <tr key={entry.id}>
                  <td>{new Date(entry.at).toLocaleString()}</td>
                  <td>{entry.action}</td>
                  <td>{entry.actor}</td>
                  <td className="mono">
                    {entry.target_kind}/{entry.target_id.slice(0, 8)}
                  </td>
                  <td className="mono">{describe(entry.details)}</td>
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
