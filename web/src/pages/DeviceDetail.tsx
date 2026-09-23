import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { api } from "../api/client";
import type { DeviceCompliance, DeviceDetail as Detail } from "../api/types";
import { AdminPasswords } from "../components/AdminPasswords";
import { RecoveryKeys } from "../components/RecoveryKeys";
import { CollectLogsDialog, WipeDialog } from "../components/RemoteActionDialogs";
import { RunScriptDialog } from "../components/RunScriptDialog";
import { SecurityStatus } from "../components/SecurityStatus";
import { StatusDot } from "../components/StatusDot";
import { Button, ErrorNote, Spinner } from "../components/ui";
import { useSession } from "../session/SessionContext";
import { relative } from "./Devices";
import "./DeviceDetail.css";

export default function DeviceDetail() {
  const { id = "" } = useParams();
  const { canWrite, canOperate } = useSession();
  const [detail, setDetail] = useState<Detail | null>(null);
  const [compliance, setCompliance] = useState<DeviceCompliance | null>(null);
  const [complianceError, setComplianceError] = useState<unknown>(null);
  const [error, setError] = useState<unknown>(null);
  const [tab, setTab] = useState<"software" | "commands">("software");
  const [scriptOpen, setScriptOpen] = useState(false);
  const [logsOpen, setLogsOpen] = useState(false);
  const [wipeOpen, setWipeOpen] = useState(false);
  const [passwordsToken, setPasswordsToken] = useState(0);

  const load = useCallback(() => {
    api
      .get<Detail>(`/devices/${id}`)
      .then((next) => {
        setDetail(next);
        setError(null);
      })
      .catch(setError);
    api
      .get<DeviceCompliance>(`/devices/${id}/compliance`)
      .then((next) => {
        setCompliance(next);
        setComplianceError(null);
      })
      .catch(setComplianceError);
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

  async function queueSimple(type: string, confirmation?: string) {
    if (confirmation && !window.confirm(confirmation)) return;
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

      <section className="compliance">
        <h2>Compliance</h2>
        <ErrorNote error={complianceError} />
        {!compliance && !complianceError ? (
          <Spinner />
        ) : compliance && compliance.policies.length === 0 ? (
          <p className="compliance__empty">No compliance policies apply to this device.</p>
        ) : compliance ? (
          <>
            <p className="compliance__overall">
              <StatusDot status={compliance.overall} label={`Overall: ${compliance.overall.replace(/_/g, " ")}`} />
            </p>
            <ul className="compliance__policies">
              {compliance.policies.map((policy) => (
                <li key={policy.policy_id}>
                  <StatusDot status={policy.state} />
                  <span>{policy.policy_name}</span>
                  <span className="compliance__evaluated">evaluated {relative(policy.evaluated_at)}</span>
                  {policy.failures.length > 0 ? (
                    <ul className="compliance__failures">
                      {policy.failures.map((failure, index) => (
                        <li key={index}>{failure.detail}</li>
                      ))}
                    </ul>
                  ) : null}
                </li>
              ))}
            </ul>
          </>
        ) : null}
      </section>

      <SecurityStatus document={inventory?.document} />

      {(canWrite || canOperate) && device.status === "active" ? (
        <div className="actions" style={{ marginBottom: "var(--space-6)" }}>
          {canWrite ? (
            <Button variant="primary" onClick={() => setScriptOpen(true)}>
              Run script
            </Button>
          ) : null}
          <Button onClick={() => void queueSimple("refresh_inventory")}>Refresh inventory</Button>
          <Button onClick={() => void queueSimple("restart")}>Restart</Button>
          <Button
            onClick={() =>
              void queueSimple("lock", `Lock ${device.hostname}? Whoever is signed in will need their password.`)
            }
          >
            Lock
          </Button>
          <Button onClick={() => setLogsOpen(true)}>Collect logs</Button>
          <Button
            onClick={() =>
              void queueSimple(
                "rotate_local_admin_password",
                `Set a new random password on ${device.hostname}'s built-in Administrator account? The old one stops working; the new one is kept here.`,
              ).then(() => setPasswordsToken((n) => n + 1))
            }
          >
            Rotate admin password
          </Button>
          {canWrite ? (
            <>
              <Button variant="danger" onClick={() => setWipeOpen(true)}>
                Wipe…
              </Button>
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
            </>
          ) : null}
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

      <RecoveryKeys deviceId={device.id} />
      <AdminPasswords deviceId={device.id} reloadToken={passwordsToken} />

      <RunScriptDialog
        deviceIds={[device.id]}
        open={scriptOpen}
        onClose={() => setScriptOpen(false)}
        onQueued={load}
      />
      <CollectLogsDialog deviceId={device.id} open={logsOpen} onClose={() => setLogsOpen(false)} onQueued={load} />
      <WipeDialog
        deviceId={device.id}
        hostname={device.hostname}
        open={wipeOpen}
        onClose={() => setWipeOpen(false)}
        onQueued={load}
      />
    </>
  );
}
