import { useEffect, useState } from "react";

import { api } from "../api/client";
import { StatusDot } from "../components/StatusDot";
import { Button, Dialog, EmptyState, ErrorNote, Field, Spinner } from "../components/ui";
import { useList } from "../hooks/useList";
import { useSession } from "../session/SessionContext";
import { relative } from "./Devices";

export interface Report {
  id: string;
  name: string;
  kind: "devices" | "compliance";
  policy_id?: string;
  state?: string;
  recipients: string[];
  frequency: "daily" | "weekly";
  weekday: number;
  hour: number;
  timezone: string;
  enabled: boolean;
  next_run_at: string;
  last_sent_at?: string;
  last_error?: string;
}

interface Policy {
  id: string;
  name: string;
}

const WEEKDAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

/** describeSchedule says when a report goes out. */
export function describeSchedule(r: Pick<Report, "frequency" | "weekday" | "hour" | "timezone">): string {
  const at = `${String(r.hour).padStart(2, "0")}:00 ${r.timezone}`;
  return r.frequency === "daily" ? `Every day at ${at}` : `Every ${WEEKDAYS[r.weekday]} at ${at}`;
}

/** Reports emails the device list, or a compliance policy's results, as CSV
 * on a schedule, to people who need the numbers but not a console account. */
export default function Reports() {
  const { canWrite } = useSession();
  const { items, loading, error, reload } = useList<Report>("/reports");
  const [editing, setEditing] = useState<Report | "new" | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function sendNow(r: Report) {
    setActionError(null);
    setNotice(null);
    try {
      await api.post(`/reports/${r.id}/send`, {});
      setNotice(`Sent ${r.name} to ${r.recipients.join(", ")}.`);
    } catch (err) {
      setActionError(err);
    }
    reload();
  }

  async function remove(r: Report) {
    if (!window.confirm(`Delete ${r.name}? Its recipients stop receiving it.`)) return;
    try {
      await api.del(`/reports/${r.id}`);
      reload();
    } catch (err) {
      setActionError(err);
    }
  }

  return (
    <>
      <div className="content__head">
        <h1>Scheduled reports</h1>
        {canWrite ? (
          <Button variant="primary" onClick={() => setEditing("new")}>
            Schedule report
          </Button>
        ) : null}
      </div>
      <p className="hint" style={{ marginTop: 0 }}>
        A report emails the device list, or one compliance policy&apos;s results, as a CSV file, daily or weekly. It
        needs the server&apos;s mail relay (SMTP) to be set up.
      </p>
      <ErrorNote error={error ?? actionError} />
      {notice ? (
        <p className="note" role="status">
          {notice}
        </p>
      ) : null}
      {loading ? <Spinner /> : null}
      {!loading && items.length === 0 ? (
        <EmptyState title="No scheduled reports yet.">
          <p>Schedule one, such as the non-compliant devices every Monday morning for the security team.</p>
        </EmptyState>
      ) : null}

      {items.length > 0 ? (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>When</th>
                <th>To</th>
                <th>Last sent</th>
                {canWrite ? <th></th> : null}
              </tr>
            </thead>
            <tbody>
              {items.map((r) => (
                <tr key={r.id}>
                  <td>
                    {r.name}
                    <div className="hint">{r.kind === "devices" ? "Every device" : "Compliance results"}</div>
                  </td>
                  <td>
                    {r.enabled ? describeSchedule(r) : <StatusDot status="retired" label="paused" />}
                  </td>
                  <td>{r.recipients.join(", ")}</td>
                  <td>
                    {r.last_sent_at ? relative(r.last_sent_at) : "never"}
                    {r.last_error ? <div className="hint">Last attempt failed: {r.last_error}</div> : null}
                  </td>
                  {canWrite ? (
                    <td>
                      <div className="actions" style={{ marginTop: 0 }}>
                        <Button variant="quiet" onClick={() => void sendNow(r)}>
                          Send now
                        </Button>
                        <Button variant="quiet" onClick={() => setEditing(r)}>
                          Edit
                        </Button>
                        <Button variant="quiet" onClick={() => void remove(r)}>
                          Delete
                        </Button>
                      </div>
                    </td>
                  ) : null}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      <ReportDialog
        report={editing === "new" ? null : editing}
        open={editing !== null}
        onClose={() => setEditing(null)}
        onSaved={reload}
      />
    </>
  );
}

function ReportDialog({
  report,
  open,
  onClose,
  onSaved,
}: {
  report: Report | null;
  open: boolean;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState("");
  const [kind, setKind] = useState<Report["kind"]>("devices");
  const [policyID, setPolicyID] = useState("");
  const [state, setState] = useState("");
  const [recipients, setRecipients] = useState("");
  const [frequency, setFrequency] = useState<Report["frequency"]>("weekly");
  const [weekday, setWeekday] = useState(1);
  const [hour, setHour] = useState(7);
  const [timezone, setTimezone] = useState("UTC");
  const [enabled, setEnabled] = useState(true);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    setName(report?.name ?? "");
    setKind(report?.kind ?? "devices");
    setPolicyID(report?.policy_id ?? "");
    setState(report?.state ?? "");
    setRecipients(report?.recipients.join(", ") ?? "");
    setFrequency(report?.frequency ?? "weekly");
    setWeekday(report?.weekday ?? 1);
    setHour(report?.hour ?? 7);
    setTimezone(report?.timezone ?? (Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC"));
    setEnabled(report?.enabled ?? true);
    setError(null);
    api
      .get<{ items: Policy[] }>("/compliance-policies?limit=500")
      .then((resp) => {
        setPolicies(resp.items ?? []);
        setPolicyID((cur) => cur || (resp.items?.[0]?.id ?? ""));
      })
      .catch(() => setPolicies([]));
  }, [open, report]);

  async function save() {
    setBusy(true);
    setError(null);
    const body = {
      name,
      kind,
      policy_id: kind === "compliance" ? policyID : "",
      state: kind === "compliance" ? state : "",
      recipients: recipients
        .split(/[,;\s]+/)
        .map((s) => s.trim())
        .filter(Boolean),
      frequency,
      weekday,
      hour,
      timezone,
      enabled,
    };
    try {
      if (report) await api.post(`/reports/${report.id}`, body);
      else await api.post("/reports", body);
      onSaved();
      onClose();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog title={report ? `Edit ${report.name}` : "Schedule a report"} open={open} onClose={onClose}>
      <Field label="Name">
        <input value={name} onChange={(e) => setName(e.target.value)} />
      </Field>
      <Field label="Report">
        <select value={kind} onChange={(e) => setKind(e.target.value as Report["kind"])}>
          <option value="devices">Every device</option>
          <option value="compliance">A compliance policy&apos;s results</option>
        </select>
      </Field>
      {kind === "compliance" ? (
        <>
          <Field label="Policy">
            <select value={policyID} onChange={(e) => setPolicyID(e.target.value)}>
              {policies.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Devices">
            <select value={state} onChange={(e) => setState(e.target.value)}>
              <option value="">All of them</option>
              <option value="non_compliant">Non-compliant only</option>
              <option value="compliant">Compliant only</option>
              <option value="unknown">Unknown only</option>
            </select>
          </Field>
        </>
      ) : null}
      <Field label="Send to" hint="Email addresses, separated by commas. At most 20.">
        <input value={recipients} onChange={(e) => setRecipients(e.target.value)} />
      </Field>
      <Field label="How often">
        <select value={frequency} onChange={(e) => setFrequency(e.target.value as Report["frequency"])}>
          <option value="daily">Daily</option>
          <option value="weekly">Weekly</option>
        </select>
      </Field>
      {frequency === "weekly" ? (
        <Field label="On">
          <select value={weekday} onChange={(e) => setWeekday(Number(e.target.value))}>
            {WEEKDAYS.map((d, i) => (
              <option key={d} value={i}>
                {d}
              </option>
            ))}
          </select>
        </Field>
      ) : null}
      <Field label="At (hour)">
        <input type="number" min={0} max={23} value={hour} onChange={(e) => setHour(Number(e.target.value))} />
      </Field>
      <Field label="Time zone" hint="A name such as UTC or Europe/London.">
        <input value={timezone} onChange={(e) => setTimezone(e.target.value)} />
      </Field>
      <label style={{ display: "block", marginBottom: "var(--space-2)" }}>
        <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Send on schedule
      </label>
      <ErrorNote error={error} />
      <div className="actions">
        <Button variant="primary" onClick={() => void save()} disabled={busy || name.trim() === ""}>
          {report ? "Save report" : "Schedule report"}
        </Button>
        <Button variant="quiet" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </Dialog>
  );
}
