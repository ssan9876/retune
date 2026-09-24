import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { api } from "../api/client";
import type { DeviceCompliance, DeviceDetail as Detail } from "../api/types";
import { AdminPasswords } from "../components/AdminPasswords";
import { RecoveryKeys } from "../components/RecoveryKeys";
import {
  CollectLogsDialog,
  InstallUpdatesDialog,
  RemoteShellDialog,
  RenameDialog,
  WipeDialog,
} from "../components/RemoteActionDialogs";
import { RunScriptDialog } from "../components/RunScriptDialog";
import { SecurityStatus } from "../components/SecurityStatus";
import { StatusDot } from "../components/StatusDot";
import { Button, Dialog, ErrorNote, Spinner, SuccessNote } from "../components/ui";
import { useSession } from "../session/SessionContext";
import { relative } from "./Devices";
import type { RemoteSessionInfo } from "./RemoteSession";
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
  const [renameOpen, setRenameOpen] = useState(false);
  const [updatesOpen, setUpdatesOpen] = useState(false);
  const [shellOpen, setShellOpen] = useState(false);
  const [restartOpen, setRestartOpen] = useState(false);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [receipt, setReceipt] = useState<{ label: string; commandID?: string } | null>(null);
  const navigate = useNavigate();
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
    setBusyAction(path);
    setError(null);
    try {
      await api.post(`/devices/${id}/${path}`);
      setReceipt({ label: `${path === "retire" ? "Retirement" : "Unenrollment"} submitted for ${detail?.device.hostname ?? "this device"}.` });
      load();
    } catch (err) {
      setError(err);
    } finally {
      setBusyAction(null);
    }
  }

  async function queueSimple(type: string, label: string): Promise<boolean> {
    setBusyAction(type);
    setError(null);
    try {
      const response = await api.post<{ commands?: { id: string }[] }>("/commands", { device_ids: [id], type });
      setReceipt({ label: `${label} queued for ${detail?.device.hostname ?? "this device"}.`, commandID: response.commands?.[0]?.id });
      setTab("commands");
      load();
      return true;
    } catch (err) {
      setError(err);
      return false;
    } finally {
      setBusyAction(null);
    }
  }

  function recordQueued(label: string) {
    setReceipt({ label: `${label} submitted for ${detail?.device.hostname ?? "this device"}.` });
    setTab("commands");
    load();
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
      {receipt ? (
        <SuccessNote>
          <div className="action-receipt">
            <span>{receipt.label} It will run after the device checks in.</span>
            <Link to={`/commands?device_id=${device.id}${receipt.commandID ? `&command_id=${receipt.commandID}` : ""}`}>
              View command status
            </Link>
            <Button variant="quiet" onClick={() => setReceipt(null)}>Dismiss</Button>
          </div>
        </SuccessNote>
      ) : null}

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
        <section className="device-actions" aria-labelledby="device-actions-title">
          <div className="device-actions__head">
            <div>
              <h2 id="device-actions-title">Device actions</h2>
              <p>Requests run after {device.hostname} checks in. Their progress and results stay available in Commands.</p>
            </div>
            {busyAction ? <span className="device-actions__busy" role="status">Submitting request…</span> : null}
          </div>
          <div className="device-actions__group">
            <h3>Common</h3>
            <div className="actions">
              {canWrite ? <Button variant="primary" disabled={Boolean(busyAction)} onClick={() => setScriptOpen(true)}>Run script</Button> : null}
              <Button disabled={Boolean(busyAction)} onClick={() => void queueSimple("refresh_inventory", "Inventory refresh")}>Refresh inventory</Button>
              <Button disabled={Boolean(busyAction)} onClick={() => setLogsOpen(true)}>Collect logs</Button>
              <Button disabled={Boolean(busyAction)} onClick={() => setUpdatesOpen(true)}>Install updates…</Button>
            </div>
          </div>
          <div className="device-actions__group">
            <h3>Support and access</h3>
            <div className="actions">
              <Button
                disabled={Boolean(busyAction)}
                onClick={() => {
                  if (window.confirm(`Lock ${device.hostname} now? The person using it will be interrupted.`)) {
                    void queueSimple("lock", "Device lock");
                  }
                }}
              >
                Lock device
              </Button>
              <Button
                disabled={Boolean(busyAction)}
                onClick={() => {
                  if (!window.confirm(`Rotate the local administrator password on ${device.hostname}?`)) return;
                  void queueSimple("rotate_local_admin_password", "Administrator password rotation").then((ok) => {
                    if (ok) setPasswordsToken((n) => n + 1);
                  });
                }}
              >
                Rotate admin password
              </Button>
              {canWrite ? <Button disabled={Boolean(busyAction)} onClick={() => setShellOpen(true)}>Open remote shell…</Button> : null}
            </div>
          </div>
          {canWrite || canOperate ? (
            <details className="device-actions__lifecycle">
              <summary>Lifecycle and disruptive actions</summary>
              <p>These actions can interrupt the person using this device or stop its management.</p>
              <div className="actions">
                <Button disabled={Boolean(busyAction)} onClick={() => setRestartOpen(true)}>Restart device…</Button>
                {canWrite ? <Button disabled={Boolean(busyAction)} onClick={() => setRenameOpen(true)}>Rename device…</Button> : null}
                {canWrite ? <Button variant="danger" disabled={Boolean(busyAction)} onClick={() => setWipeOpen(true)}>Wipe device…</Button> : null}
                {canWrite ? <Button variant="danger" disabled={Boolean(busyAction)} onClick={() => void act("retire", `Stop accepting check-ins from ${device.hostname}?`)}>Retire device</Button> : null}
                {canWrite ? <Button variant="danger" disabled={Boolean(busyAction)} onClick={() => void act("unenroll", `Tell ${device.hostname} to delete its identity and stop managing it?`)}>Unenroll device</Button> : null}
              </div>
            </details>
          ) : null}
        </section>
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
      {canWrite ? <RemoteSessions deviceId={device.id} /> : null}

      <RunScriptDialog
        deviceIds={[device.id]}
        open={scriptOpen}
        onClose={() => setScriptOpen(false)}
        onQueued={() => recordQueued("Script")}
      />
      <CollectLogsDialog deviceId={device.id} open={logsOpen} onClose={() => setLogsOpen(false)} onQueued={() => recordQueued("Log collection")} />
      <RemoteShellDialog
        deviceId={device.id}
        hostname={device.hostname}
        open={shellOpen}
        onClose={() => setShellOpen(false)}
        onStarted={(sessionId) => navigate(`/remote-sessions/${sessionId}`)}
      />
      <InstallUpdatesDialog
        deviceId={device.id}
        hostname={device.hostname}
        open={updatesOpen}
        onClose={() => setUpdatesOpen(false)}
        onQueued={() => recordQueued("Update installation")}
      />
      <RenameDialog
        deviceId={device.id}
        hostname={device.hostname}
        open={renameOpen}
        onClose={() => setRenameOpen(false)}
        onQueued={() => recordQueued("Rename")}
      />
      <WipeDialog
        deviceId={device.id}
        hostname={device.hostname}
        open={wipeOpen}
        onClose={() => setWipeOpen(false)}
        onQueued={() => recordQueued("Wipe request")}
      />
      <Dialog title={`Restart ${device.hostname}?`} open={restartOpen} onClose={() => setRestartOpen(false)}>
        <p>
          Anyone using this device will be interrupted. The restart is queued now and runs after the device checks in.
        </p>
        <div className="actions">
          <Button
            variant="danger"
            disabled={busyAction === "restart"}
            onClick={() => void queueSimple("restart", "Restart").then((ok) => {
              if (ok) setRestartOpen(false);
            })}
          >
            {busyAction === "restart" ? "Queueing restart…" : `Restart ${device.hostname}`}
          </Button>
          <Button variant="quiet" onClick={() => setRestartOpen(false)}>Cancel</Button>
        </div>
      </Dialog>
    </>
  );
}

/** RemoteSessions lists a device's recent remote sessions, each linking to
 * its transcript. */
function RemoteSessions({ deviceId }: { deviceId: string }) {
  const [items, setItems] = useState<RemoteSessionInfo[] | null>(null);
  useEffect(() => {
    api
      .get<{ items: RemoteSessionInfo[] }>(`/devices/${deviceId}/remote-sessions?limit=5`)
      .then((r) => setItems(r.items ?? []))
      .catch(() => setItems([]));
  }, [deviceId]);
  if (!items || items.length === 0) return null;
  return (
    <section>
      <h2>Remote sessions</h2>
      <ul>
        {items.map((s) => (
          <li key={s.id}>
            <Link to={`/remote-sessions/${s.id}`}>{relative(s.created_at)}</Link> by {s.started_by}: {s.reason}{" "}
            <span className="hint">({s.status})</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
