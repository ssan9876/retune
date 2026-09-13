import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { api } from "../api/client";
import type { DeviceDetail as Detail } from "../api/types";
import { RunScriptDialog } from "../components/RunScriptDialog";
import { StatusDot } from "../components/StatusDot";
import { Button, ErrorNote, Spinner } from "../components/ui";
import { useSession } from "../session/SessionContext";
import { relative } from "./Devices";
import "./DeviceDetail.css";

export default function DeviceDetail() {
  const { id = "" } = useParams();
  const { canWrite } = useSession();
  const [detail, setDetail] = useState<Detail | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [tab, setTab] = useState<"software" | "commands">("software");
  const [scriptOpen, setScriptOpen] = useState(false);

  const load = useCallback(() => {
    api
      .get<Detail>(`/devices/${id}`)
      .then((next) => {
        setDetail(next);
        setError(null);
      })
      .catch(setError);
  }, [id]);

  useEffect(load, [load]);

  async function act(path: string, confirmation: string) {
    if (!window.confirm(confirmation)) return;
    try {
      await api.post(`/devices/${id}/${path}`);
      load();
    } catch (err) {
      setError(err);
    }
  }

  async function queueSimple(type: string) {
    try {
      await api.post("/commands", { device_ids: [id], type });
      load();
    } catch (err) {
      setError(err);
    }
  }

  if (error && !detail) return <ErrorNote error={error} />;
  if (!detail) return <Spinner />;
  const { device, inventory, software, commands } = detail;

  return (
    <>
      <div className="content__head">
        <div>
          <h1>{device.hostname}</h1>
          <p className="detail__lede">
            <StatusDot status={device.status === "active" && device.stale ? "stale" : device.status} />
            <span>last seen {relative(device.last_seen_at)}</span>
          </p>
        </div>
        <Link to="/devices">Back to devices</Link>
      </div>

      <ErrorNote error={error} />

      <dl className="detail__grid">
        <div>
          <dt>Hardware</dt>
          <dd>{[device.manufacturer, device.model].filter(Boolean).join(" ") || "—"}</dd>
        </div>
        <div>
          <dt>Operating system</dt>
          <dd>{device.os_version || "—"}</dd>
        </div>
        <div>
          <dt>Serial</dt>
          <dd className="mono">{device.serial || "—"}</dd>
        </div>
        <div>
          <dt>Memory</dt>
          <dd>{inventory ? `${inventory.ram_gb} GB` : "—"}</dd>
        </div>
        <div>
          <dt>Free disk</dt>
          <dd>{inventory ? `${inventory.disk_free_gb} GB` : "—"}</dd>
        </div>
        <div>
          <dt>Agent</dt>
          <dd className="mono">{device.agent_version || "—"}</dd>
        </div>
        <div>
          <dt>Certificate expires</dt>
          <dd>{new Date(device.cert_expires_at).toLocaleDateString()}</dd>
        </div>
        <div>
          <dt>Inventory collected</dt>
          <dd>{inventory ? relative(inventory.collected_at) : "never"}</dd>
        </div>
      </dl>

      {canWrite && device.status === "active" ? (
        <div className="actions" style={{ marginBottom: "var(--space-6)" }}>
          <Button variant="primary" onClick={() => setScriptOpen(true)}>
            Run script
          </Button>
          <Button onClick={() => void queueSimple("refresh_inventory")}>Refresh inventory</Button>
          <Button onClick={() => void queueSimple("restart")}>Restart</Button>
          <Button
            variant="danger"
            onClick={() => void act("retire", `Stop accepting check-ins from ${device.hostname}?`)}
          >
            Retire device
          </Button>
          <Button
            variant="danger"
            onClick={() =>
              void act("unenroll", `Tell ${device.hostname} to delete its identity and stop managing it?`)
            }
          >
            Unenroll device
          </Button>
        </div>
      ) : null}

      <div className="tabs" role="tablist">
        <button role="tab" aria-selected={tab === "software"} onClick={() => setTab("software")}>
          Software ({software.length})
        </button>
        <button role="tab" aria-selected={tab === "commands"} onClick={() => setTab("commands")}>
          Commands ({commands.length})
        </button>
      </div>

      {tab === "software" ? (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Version</th>
                <th>Publisher</th>
                <th>Scope</th>
              </tr>
            </thead>
            <tbody>
              {software.map((item) => (
                <tr key={`${item.name}-${item.version}-${item.scope}`}>
                  <td>{item.name}</td>
                  <td className="mono">{item.version || "—"}</td>
                  <td>{item.publisher || "—"}</td>
                  <td>{item.scope}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Type</th>
                <th>Status</th>
                <th>Queued</th>
                <th>By</th>
              </tr>
            </thead>
            <tbody>
              {commands.map((command) => (
                <tr key={command.id}>
                  <td>
                    <Link to={`/commands?device_id=${device.id}`}>{command.type}</Link>
                  </td>
                  <td>
                    <StatusDot status={command.status} />
                  </td>
                  <td>{relative(command.created_at)}</td>
                  <td>{command.created_by}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <RunScriptDialog
        deviceIds={[device.id]}
        open={scriptOpen}
        onClose={() => setScriptOpen(false)}
        onQueued={load}
      />
    </>
  );
}
