import { Fragment, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { api } from "../api/client";
import type { Command, CommandResult } from "../api/types";
import { StatusDot } from "../components/StatusDot";
import { Button, EmptyState, ErrorNote, Spinner } from "../components/ui";
import { useList } from "../hooks/useList";
import { useSession } from "../session/SessionContext";
import { relative } from "./Devices";
import "./Commands.css";

interface CommandDetail {
  command: Command;
  result?: CommandResult;
}

const STATUSES = ["", "queued", "delivered", "running", "succeeded", "failed", "timed_out", "expired"];

export default function Commands() {
  const { canOperate } = useSession();
  const [params, setParams] = useSearchParams();
  const deviceID = params.get("device_id") ?? "";
  const commandID = params.get("command_id") ?? "";
  const status = params.get("status") ?? "";
  const [open, setOpen] = useState<CommandDetail | null>(null);
  const [detailError, setDetailError] = useState<unknown>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const { items, total, loading, error, offset, setOffset, reload, lastUpdated } = useList<Command>("/commands", {
    status,
    device_id: deviceID,
  });

  async function show(id: string) {
    if (open?.command.id === id) {
      setOpen(null);
      return;
    }
    setDetailLoading(true);
    setDetailError(null);
    try {
      setOpen(await api.get<CommandDetail>(`/commands/${id}`));
    } catch (err) {
      setOpen(null);
      setDetailError(err);
    } finally {
      setDetailLoading(false);
    }
  }

  useEffect(() => {
    if (!commandID || open?.command.id === commandID) return;
    void show(commandID);
  }, [commandID]);

  useEffect(() => {
    if (!items.some((command) => ["queued", "delivered", "running"].includes(command.status))) return;
    const timer = window.setInterval(reload, 5000);
    return () => window.clearInterval(timer);
  }, [items, reload]);

  function updateParam(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setOffset(0);
    setParams(next, { replace: true });
  }

  return (
    <>
      <div className="content__head">
        <div>
          <h1>Commands</h1>
          <p className="commands__updated">
            {lastUpdated ? `Updated ${lastUpdated.toLocaleTimeString([], { hour: "numeric", minute: "2-digit", second: "2-digit" })}` : "Loading command status…"}
          </p>
        </div>
        <div className="actions commands__filters">
          <label>
            Status{" "}
            <select value={status} onChange={(event) => updateParam("status", event.target.value)}>
              {STATUSES.map((value) => (
                <option key={value} value={value}>
                  {value === "" ? "any" : value.replace(/_/g, " ")}
                </option>
              ))}
            </select>
          </label>
          <Button variant="quiet" onClick={reload} disabled={loading}>Refresh now</Button>
          {deviceID ? (
            <Button
              variant="quiet"
              onClick={() => {
                updateParam("device_id", "");
              }}
            >
              Clear device filter
            </Button>
          ) : null}
        </div>
      </div>

      <ErrorNote error={error} />
      <ErrorNote error={detailError} />
      {loading ? <Spinner /> : null}
      {detailLoading ? <Spinner label="Loading command details…" /> : null}
      {!loading && !error && items.length === 0 ? (
        <EmptyState title={status || deviceID ? "No commands match these filters." : "No commands yet."}>
          <p>{status || deviceID ? "Clear a filter or choose another status." : "Open a device and run a script, refresh its inventory, or restart it."}</p>
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
                <Fragment key={command.id}>
                <tr>
                  <td>{command.type.replace(/_/g, " ")}</td>
                  <td>
                    <StatusDot status={command.status} />
                  </td>
                  <td>
                    <Link className="mono" to={`/devices/${command.device_id}`}>
                      {command.hostname || command.device_id.slice(0, 8)}
                    </Link>
                  </td>
                  <td>{relative(command.created_at)}</td>
                  <td>{command.created_by}</td>
                  <td>
                    <Button variant="quiet" onClick={() => void show(command.id)}>
                      {open?.command.id === command.id ? "Hide details" : "View details"}
                    </Button>
                  </td>
                </tr>
                {open?.command.id === command.id ? (
                  <tr className="command-detail-row">
                    <td colSpan={6}>
                      <CommandDetails detail={open} canOperate={canOperate} />
                    </td>
                  </tr>
                ) : null}
                </Fragment>
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

function CommandDetails({ detail, canOperate }: { detail: CommandDetail; canOperate: boolean }) {
  return (
    <section className="command-details" aria-label="Command result">
      {detail.result ? (
        <>
          <p>
            Exit code {detail.result.exit_code}
            {detail.result.error ? ` · ${detail.result.error}` : ""}
          </p>
          {detail.command.type === "collect_logs" && detail.command.status === "succeeded" && canOperate ? (
            <p><a className="button" href={`/api/admin/v1/commands/${detail.command.id}/artifact`}>Download logs</a></p>
          ) : null}
          {detail.result.stdout ? <pre className="mono">{detail.result.stdout}</pre> : null}
          {detail.result.stderr ? <pre className="mono command-details__stderr">{detail.result.stderr}</pre> : null}
        </>
      ) : (
        <p>This command is {detail.command.status.replace(/_/g, " ")} and has not reported a result yet. Retune refreshes active command status automatically.</p>
      )}
    </section>
  );
}
