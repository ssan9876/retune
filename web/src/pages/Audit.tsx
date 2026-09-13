import type { AuditEntry } from "../api/types";
import { Button, EmptyState, ErrorNote, Spinner } from "../components/ui";
import { useList } from "../hooks/useList";

/** describe flattens an entry's details into readable key=value pairs. */
function describe(details: Record<string, unknown>): string {
  return Object.entries(details ?? {})
    .map(([key, value]) => `${key}=${String(value)}`)
    .join(" ");
}

export default function Audit() {
  const { items, total, loading, error, offset, setOffset } = useList<AuditEntry>("/audit");

  return (
    <>
      <div className="content__head">
        <h1>Audit</h1>
      </div>

      <ErrorNote error={error} />
      {loading ? <Spinner /> : null}
      {!loading && items.length === 0 ? <EmptyState title="Nothing has happened yet." /> : null}

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
                <tr key={`${entry.at}-${entry.action}-${entry.target_id}`}>
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
