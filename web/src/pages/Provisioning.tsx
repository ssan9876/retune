import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { ApiError, api } from "../api/client";
import type { Group } from "../api/types";
import { StatusDot } from "../components/StatusDot";
import { Button, Dialog, EmptyState, ErrorNote, Field, Spinner } from "../components/ui";
import { useList } from "../hooks/useList";
import { useSession } from "../session/SessionContext";
import { relative } from "./Devices";

export interface Registration {
  id: string;
  serial: string;
  device_name?: string;
  group_ids: string[];
  notes?: string;
  device_id?: string;
  enrolled_at?: string;
  created_at: string;
}

interface ImportProblem {
  line: number;
  message: string;
}

/** Provisioning registers devices by serial number before they arrive: when
 * one enrolls, it joins its groups and is given its name, with nobody at the
 * console. */
export default function Provisioning() {
  const { canWrite } = useSession();
  const { items, total, loading, error, reload } = useList<Registration>("/device-registrations");
  const [groups, setGroups] = useState<Group[]>([]);
  const [adding, setAdding] = useState(false);
  const [importing, setImporting] = useState(false);
  const [actionError, setActionError] = useState<unknown>(null);

  useEffect(() => {
    api
      .get<{ items: Group[] }>("/groups")
      .then((resp) => setGroups(resp.items ?? []))
      .catch(() => setGroups([]));
  }, []);
  const groupName = (id: string) => groups.find((g) => g.id === id)?.name ?? "a deleted group";

  async function remove(r: Registration) {
    if (!window.confirm(`Remove the registration for ${r.serial}?`)) return;
    try {
      await api.del(`/device-registrations/${r.id}`);
      reload();
    } catch (err) {
      setActionError(err);
    }
  }

  return (
    <>
      <div className="content__head">
        <h1>Provisioning</h1>
        {canWrite ? (
          <div className="actions" style={{ marginTop: 0 }}>
            <Button onClick={() => setImporting(true)}>Import CSV</Button>
            <Button variant="primary" onClick={() => setAdding(true)}>
              Register device
            </Button>
          </div>
        ) : null}
      </div>
      <p className="hint" style={{ marginTop: 0 }}>
        Register devices by serial number before they arrive. When one enrolls, it joins the static groups you chose
        and, if you gave it a name, is renamed (the name takes effect when it next restarts). Pair this with an
        enrollment token set to <em>registered devices only</em>, installed with the one-line command on the
        Enrollment page, and a new laptop configures itself.
      </p>
      <ErrorNote error={error ?? actionError} />
      {loading ? <Spinner /> : null}
      {!loading && items.length === 0 ? (
        <EmptyState title="No devices registered yet.">
          <p>Register one, or import a CSV of serial numbers from your supplier.</p>
        </EmptyState>
      ) : null}
      {items.length > 0 ? (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Serial</th>
                <th>Name</th>
                <th>Groups</th>
                <th>State</th>
                {canWrite ? <th></th> : null}
              </tr>
            </thead>
            <tbody>
              {items.map((r) => (
                <tr key={r.id}>
                  <td className="mono">
                    {r.serial}
                    {r.notes ? <div className="hint">{r.notes}</div> : null}
                  </td>
                  <td>{r.device_name || <span className="hint">its own</span>}</td>
                  <td>{r.group_ids.length ? r.group_ids.map(groupName).join(", ") : <span className="hint">none</span>}</td>
                  <td>
                    {r.device_id ? (
                      <Link to={`/devices/${r.device_id}`}>
                        <StatusDot status="active" label={`enrolled ${relative(r.enrolled_at ?? r.created_at)}`} />
                      </Link>
                    ) : (
                      <StatusDot status="queued" label="waiting" />
                    )}
                  </td>
                  {canWrite ? (
                    <td>
                      <Button variant="quiet" onClick={() => void remove(r)}>
                        Remove
                      </Button>
                    </td>
                  ) : null}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {total > items.length ? <p className="hint">Showing the newest {items.length} of {total}.</p> : null}

      <RegisterDialog open={adding} groups={groups} onClose={() => setAdding(false)} onSaved={reload} />
      <ImportDialog open={importing} onClose={() => setImporting(false)} onSaved={reload} />
    </>
  );
}

function RegisterDialog({
  open,
  groups,
  onClose,
  onSaved,
}: {
  open: boolean;
  groups: Group[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const [serial, setSerial] = useState("");
  const [name, setName] = useState("");
  const [chosen, setChosen] = useState<string[]>([]);
  const [notes, setNotes] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const statics = groups.filter((g) => g.kind === "static");

  useEffect(() => {
    if (!open) return;
    setSerial("");
    setName("");
    setChosen([]);
    setNotes("");
    setError(null);
  }, [open]);

  async function save() {
    setBusy(true);
    setError(null);
    try {
      await api.post("/device-registrations", { serial, device_name: name, group_ids: chosen, notes });
      onSaved();
      onClose();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog title="Register a device" open={open} onClose={onClose}>
      <Field label="Serial number">
        <input value={serial} onChange={(e) => setSerial(e.target.value)} />
      </Field>
      <Field label="Computer name" hint="Optional. Up to 15 letters, digits and hyphens.">
        <input value={name} onChange={(e) => setName(e.target.value)} />
      </Field>
      <fieldset style={{ border: 0, padding: 0 }}>
        <legend>Groups to join</legend>
        {statics.length === 0 ? <p className="hint">There are no static groups yet.</p> : null}
        {statics.map((g) => (
          <label key={g.id} style={{ display: "block" }}>
            <input
              type="checkbox"
              checked={chosen.includes(g.id)}
              onChange={(e) =>
                setChosen((cur) => (e.target.checked ? [...cur, g.id] : cur.filter((id) => id !== g.id)))
              }
            />{" "}
            {g.name}
          </label>
        ))}
      </fieldset>
      <Field label="Notes">
        <input value={notes} onChange={(e) => setNotes(e.target.value)} />
      </Field>
      <ErrorNote error={error} />
      <div className="actions">
        <Button variant="primary" onClick={() => void save()} disabled={busy || serial.trim() === ""}>
          Register
        </Button>
        <Button variant="quiet" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </Dialog>
  );
}

function ImportDialog({ open, onClose, onSaved }: { open: boolean; onClose: () => void; onSaved: () => void }) {
  const [csv, setCsv] = useState("");
  const [problems, setProblems] = useState<ImportProblem[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    setCsv("");
    setProblems([]);
    setError(null);
  }, [open]);

  async function load(file: File | undefined) {
    if (file) setCsv(await file.text());
  }

  async function submit() {
    setBusy(true);
    setError(null);
    setProblems([]);
    try {
      await api.post("/device-registrations/import", { csv });
      onSaved();
      onClose();
    } catch (err) {
      // A file with problems lists them all; nothing was imported.
      const listed =
        err instanceof ApiError ? (err.body as { problems?: ImportProblem[] } | undefined)?.problems : undefined;
      if (listed?.length) setProblems(listed);
      else setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog title="Import devices" open={open} onClose={onClose}>
      <p className="hint">
        One device per line: <span className="mono">serial,name,groups,notes</span>. Only the serial is required;
        groups are static groups by name, separated by semicolons. A header row is fine. If any line has a problem,
        nothing is imported.
      </p>
      <Field label="CSV file">
        <input type="file" accept=".csv,text/csv" onChange={(e) => void load(e.target.files?.[0])} />
      </Field>
      <Field label="Or paste it">
        <textarea
          className="mono"
          rows={8}
          aria-label="CSV"
          value={csv}
          placeholder={"serial,name,groups\nPF3ABC12,SALES-01,Sales laptops"}
          onChange={(e) => setCsv(e.target.value)}
        />
      </Field>
      {problems.length > 0 ? (
        <div className="note" role="alert">
          Nothing was imported:
          <ul>
            {problems.map((p) => (
              <li key={p.line}>
                Line {p.line}: {p.message}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      <ErrorNote error={error} />
      <div className="actions">
        <Button variant="primary" onClick={() => void submit()} disabled={busy || csv.trim() === ""}>
          Import
        </Button>
        <Button variant="quiet" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </Dialog>
  );
}
