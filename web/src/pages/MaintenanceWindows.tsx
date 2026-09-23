import { useEffect, useState } from "react";

import { api } from "../api/client";
import type { Group } from "../api/types";
import { Button, Dialog, EmptyState, ErrorNote, Field, Spinner } from "../components/ui";
import { useList } from "../hooks/useList";
import { useSession } from "../session/SessionContext";

const ITEM_KIND = "window";
const DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"] as const;
const DAY_NAMES: Record<string, string> = {
  mon: "Mon",
  tue: "Tue",
  wed: "Wed",
  thu: "Thu",
  fri: "Fri",
  sat: "Sat",
  sun: "Sun",
};

export interface MaintenanceWindow {
  id: string;
  name: string;
  description: string;
  days: string[];
  start: string;
  duration_minutes: number;
  created_by: string;
}

interface WindowAssignment {
  id: string;
  group_name: string;
  mode: "include" | "exclude";
}

/** describeWindow says when a window is open, the way a person would. */
export function describeWindow(w: Pick<MaintenanceWindow, "days" | "start" | "duration_minutes">): string {
  const days =
    w.days.length === 0 || w.days.length === 7
      ? "Every day"
      : DAYS.filter((d) => w.days.includes(d))
          .map((d) => DAY_NAMES[d])
          .join(", ");
  const hours = Math.floor(w.duration_minutes / 60);
  const minutes = w.duration_minutes % 60;
  const length = [hours ? `${hours} h` : "", minutes ? `${minutes} min` : ""].filter(Boolean).join(" ");
  return `${days}, from ${w.start} for ${length}`;
}

/** MaintenanceWindows defines when devices may be changed. A device with a
 * window assigned runs script deployments, app installs and agent updates
 * only inside one; commands and configuration profiles are not held. */
export default function MaintenanceWindows() {
  const { canWrite } = useSession();
  const { items, loading, error, reload } = useList<MaintenanceWindow>("/maintenance-windows");
  const [editing, setEditing] = useState<MaintenanceWindow | "new" | null>(null);
  const [assigning, setAssigning] = useState<MaintenanceWindow | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [generation, setGeneration] = useState(0);

  async function remove(w: MaintenanceWindow) {
    if (!window.confirm(`Delete ${w.name}? Its assignments go with it, and its devices can be changed at any time.`)) {
      return;
    }
    try {
      await api.del(`/maintenance-windows/${w.id}`);
      reload();
    } catch (err) {
      setActionError(err);
    }
  }

  return (
    <>
      <div className="content__head">
        <h1>Maintenance windows</h1>
        {canWrite ? (
          <Button variant="primary" onClick={() => setEditing("new")}>
            Create window
          </Button>
        ) : null}
      </div>

      <p className="hint" style={{ marginTop: 0 }}>
        A device with a maintenance window assigned runs script deployments, app installs and removals, and agent
        updates only inside one of its windows, in its own local time. Commands you send and configuration profiles are
        not held back. A device with no window can be changed at any time.
      </p>

      <ErrorNote error={error ?? actionError} />
      {loading ? <Spinner /> : null}
      {!loading && items.length === 0 ? (
        <EmptyState title="No maintenance windows yet.">
          <p>Create one, such as weeknights from 22:00 for four hours, and assign it to a group.</p>
        </EmptyState>
      ) : null}

      {items.length > 0 ? (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Open</th>
                <th>Assigned to</th>
                {canWrite ? <th></th> : null}
              </tr>
            </thead>
            <tbody>
              {items.map((w) => (
                <tr key={w.id}>
                  <td>
                    {w.name}
                    {w.description ? <div className="hint">{w.description}</div> : null}
                  </td>
                  <td>{describeWindow(w)}</td>
                  <td>
                    <Assignments windowID={w.id} canWrite={canWrite} generation={generation} />
                  </td>
                  {canWrite ? (
                    <td>
                      <div className="actions" style={{ marginTop: 0 }}>
                        <Button variant="quiet" onClick={() => setAssigning(w)}>
                          Assign
                        </Button>
                        <Button variant="quiet" onClick={() => setEditing(w)}>
                          Edit
                        </Button>
                        <Button variant="quiet" onClick={() => void remove(w)}>
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

      <WindowDialog
        window={editing === "new" ? null : editing}
        open={editing !== null}
        onClose={() => setEditing(null)}
        onSaved={reload}
      />
      <AssignDialog
        window={assigning}
        open={assigning !== null}
        onClose={() => setAssigning(null)}
        onAssigned={() => setGeneration((g) => g + 1)}
      />
    </>
  );
}

function Assignments({ windowID, canWrite, generation }: { windowID: string; canWrite: boolean; generation: number }) {
  const [items, setItems] = useState<WindowAssignment[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [reloads, setReloads] = useState(0);

  useEffect(() => {
    let cancelled = false;
    api
      .get<{ items: WindowAssignment[] }>(`/assignments?item_kind=${ITEM_KIND}&item_id=${windowID}`)
      .then((resp) => !cancelled && setItems(resp.items))
      .catch((err: unknown) => !cancelled && setError(err));
    return () => {
      cancelled = true;
    };
  }, [windowID, generation, reloads]);

  async function unassign(id: string) {
    try {
      await api.del(`/assignments/${id}`);
      setReloads((n) => n + 1);
    } catch (err) {
      setError(err);
    }
  }

  if (error) return <ErrorNote error={error} />;
  if (items === null) return null;
  if (items.length === 0) return <span className="hint">Not assigned</span>;
  return (
    <ul style={{ margin: 0, paddingLeft: "1em" }}>
      {items.map((a) => (
        <li key={a.id}>
          {a.mode === "exclude" ? "Excluded: " : ""}
          {a.group_name}{" "}
          {canWrite ? (
            <Button variant="quiet" onClick={() => void unassign(a.id)} aria-label={`Unassign ${a.group_name}`}>
              ×
            </Button>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

function WindowDialog({
  window: current,
  open,
  onClose,
  onSaved,
}: {
  window: MaintenanceWindow | null;
  open: boolean;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [days, setDays] = useState<string[]>([]);
  const [start, setStart] = useState("22:00");
  const [hours, setHours] = useState(4);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    setName(current?.name ?? "");
    setDescription(current?.description ?? "");
    setDays(current?.days ?? []);
    setStart(current?.start ?? "22:00");
    setHours(current ? current.duration_minutes / 60 : 4);
    setError(null);
  }, [open, current]);

  function toggle(day: string) {
    setDays((cur) => (cur.includes(day) ? cur.filter((d) => d !== day) : [...cur, day]));
  }

  async function save() {
    setBusy(true);
    setError(null);
    const body = { name, description, days, start, duration_minutes: Math.round(hours * 60) };
    try {
      if (current) await api.post(`/maintenance-windows/${current.id}`, body);
      else await api.post("/maintenance-windows", body);
      onSaved();
      onClose();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog title={current ? `Edit ${current.name}` : "Create maintenance window"} open={open} onClose={onClose}>
      <Field label="Name">
        <input value={name} onChange={(e) => setName(e.target.value)} />
      </Field>
      <Field label="Description">
        <input value={description} onChange={(e) => setDescription(e.target.value)} />
      </Field>
      <fieldset style={{ border: 0, padding: 0 }}>
        <legend>Days (none is every day)</legend>
        {DAYS.map((d) => (
          <label key={d} style={{ marginRight: "var(--space-3)" }}>
            <input type="checkbox" checked={days.includes(d)} onChange={() => toggle(d)} /> {DAY_NAMES[d]}
          </label>
        ))}
      </fieldset>
      <Field label="Opens at" hint="The device's own local time.">
        <input type="time" value={start} onChange={(e) => setStart(e.target.value)} />
      </Field>
      <Field label="Hours open" hint="Up to 24. A window may run past midnight.">
        <input
          type="number"
          min={0.25}
          max={24}
          step={0.25}
          value={hours}
          onChange={(e) => setHours(Number(e.target.value))}
        />
      </Field>
      <p className="hint">{describeWindow({ days, start, duration_minutes: Math.round(hours * 60) })}</p>
      <ErrorNote error={error} />
      <div className="actions">
        <Button variant="primary" onClick={() => void save()} disabled={busy || name.trim() === ""}>
          {current ? "Save window" : "Create window"}
        </Button>
        <Button variant="quiet" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </Dialog>
  );
}

function AssignDialog({
  window: current,
  open,
  onClose,
  onAssigned,
}: {
  window: MaintenanceWindow | null;
  open: boolean;
  onClose: () => void;
  onAssigned: () => void;
}) {
  const [groups, setGroups] = useState<Group[]>([]);
  const [groupID, setGroupID] = useState("");
  const [mode, setMode] = useState("include");
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    if (!open) return;
    setError(null);
    api
      .get<{ items: Group[] }>("/groups")
      .then((resp) => {
        setGroups(resp.items);
        setGroupID((cur) => cur || (resp.items[0]?.id ?? ""));
      })
      .catch((err: unknown) => setError(err));
  }, [open]);

  async function assign() {
    if (!current) return;
    setError(null);
    try {
      await api.post("/assignments", { item_kind: ITEM_KIND, item_id: current.id, group_id: groupID, mode });
      onAssigned();
      onClose();
    } catch (err) {
      setError(err);
    }
  }

  return (
    <Dialog title={`Assign ${current?.name ?? ""}`} open={open} onClose={onClose}>
      <Field label="Group">
        <select value={groupID} onChange={(e) => setGroupID(e.target.value)}>
          {groups.map((g) => (
            <option key={g.id} value={g.id}>
              {g.name}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Mode" hint="An exclude always wins, whichever group it comes from.">
        <select value={mode} onChange={(e) => setMode(e.target.value)}>
          <option value="include">Include</option>
          <option value="exclude">Exclude</option>
        </select>
      </Field>
      <ErrorNote error={error} />
      <div className="actions">
        <Button onClick={() => void assign()} disabled={groupID === ""}>
          Assign to group
        </Button>
        <Button variant="quiet" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </Dialog>
  );
}
