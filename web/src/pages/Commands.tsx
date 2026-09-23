import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { api } from "../api/client";
import type { Command, CommandResult } from "../api/types";
import { StatusDot } from "../components/StatusDot";
import { Button, EmptyState, ErrorNote, Spinner } from "../components/ui";
import { useList } from "../hooks/useList";
import { useSession } from "../session/SessionContext";
import { relative } from "./Devices";

interface CommandDetail {
  command: Command;
  result?: CommandResult;
}

const STATUSES = ["", "queued", "delivered", "running", "succeeded", "failed", "timed_out", "expired"];

export default function Commands() {
  const { canWrite } = useSession();
  const [params, setParams] = useSearchParams();
  const deviceID = params.get("device_id") ?? "";
  const [status, setStatus] = useState("");
  const [open, setOpen] = useState<CommandDetail | null>(null);
  const { items, total, loading, error, offset, setOffset } = useList<Command>("/commands", {
    status,
    device_id: deviceID,
  });

  async function show(id: string) {
    if (open?.command.id === id) {
      setOpen(null);
      return;
    }
    try {
      setOpen(await api.get<CommandDetail>(`/commands/${id}`));
    } catch {
      setOpen(null);
    }
  }

  return (
    <>
      <div className="content__head">
        <h1>Commands</h1>
        <div className="actions" style={{ marginTop: 0 }}>
          <label className="mono" style={{ fontSize: "var(--text-sm)" }}>
            Status{" "}
            <select value={status} onChange={(event) => setStatus(event.target.value)}>
              {STATUSES.map((value) => (
                <option key={value} value={value}>
                  {value === "" ? "any" : value.replace(/_/g, " ")}
                </option>
              ))}
            </select>
          </label>
          {deviceID ? (
            <Button
              variant="quiet"
              onClick={() => {
                params.delete("device_id");
                setParams(params);
              }}
            >
              Clear device filter
            </Button>
          ) : null}
        </div>
      </div>

      <ErrorNote error={error} />
      {loading ? <Spinner /> : null}
      {!loading && items.length === 0 ? (
        <EmptyState title="No commands yet.">
          <p>Open a device and run a script, refresh its inventory, or restart it.</p>
        </EmptyState>
      ) : null}

      {items.length > 0 ? (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Type</th>
                <th>Status</th>
                <th>Device</th>
                <th>Queued</th>
                <th>By</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {items.map((command) => (
                <tr key={command.id}>
                  <td>{command.type.replace(/_/g, " ")}</td>
                  <td>
                    <StatusDot status={command.status} />
                  </td>
                  <td>
                    <Link className="mono" to={`/devices/${command.device_id}`}>
                      {command.device_id.slice(0, 8)}
                    </Link>
                  </td>
                  <td>{relative(command.created_at)}</td>
                  <td>{command.created_by}</td>
                  <td>
                    <Button variant="quiet" onClick={() => void show(command.id)}>
                      {open?.command.id === command.id ? "Hide output" : "Show output"}
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {open ? (
        <section style={{ marginTop: "var(--space-6)" }}>
          <h2>Result</h2>
          {open.result ? (
            <>
              <p style={{ color: "var(--ink-muted)", fontSize: "var(--text-sm)" }}>
                Exit code {open.result.exit_code}
                {open.result.error ? ` · ${open.result.error}` : ""}
              </p>
              {open.command.type === "collect_logs" && open.command.status === "succeeded" && canWrite ? (
                <p>
                  <a className="button" href={`/api/admin/v1/commands/${open.command.id}/artifact`}>
                    Download logs
                  </a>
                </p>
              ) : null}
              {open.result.stdout ? (
                <pre className="mono" style={{ whiteSpace: "pre-wrap" }}>
                  {open.result.stdout}
                </pre>
              ) : null}
              {open.result.stderr ? (
                <pre className="mono" style={{ whiteSpace: "pre-wrap", color: "var(--status-retired)" }}>
                  {open.result.stderr}
                </pre>
              ) : null}
            </>
          ) : (
            <p style={{ color: "var(--ink-muted)", fontSize: "var(--text-sm)" }}>
              This command has not reported back yet.
            </p>
          )}
        </section>
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
