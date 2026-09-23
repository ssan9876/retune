import { useEffect, useState } from "react";

import { api } from "../api/client";
import { useSession } from "../session/SessionContext";
import { Button, ErrorNote, Field } from "./ui";

/** Rollout phases an include in over its group. */
export interface Rollout {
  percent: number;
  step_percent?: number;
  step_hours?: number;
  current_percent?: number;
  full_at?: string;
}

interface AssignmentRow {
  id: string;
  group_name: string;
  mode: "include" | "exclude";
  rollout?: Rollout;
}

/** describeRollout says how far a phased include has got, and where it goes. */
export function describeRollout(r: Rollout): string {
  const now = `${r.current_percent ?? r.percent}% of the group`;
  if (r.full_at) return `${now}, all of it by ${new Date(r.full_at).toLocaleString()}`;
  return `${now}, until changed`;
}

/** AssignedTo lists where an item is assigned, and how far any phased
 * rollout has got. `refresh` changing re-reads it. */
export function AssignedTo({ kind, id, refresh = 0 }: { kind: string; id: string; refresh?: number }) {
  const { canWrite } = useSession();
  const [items, setItems] = useState<AssignmentRow[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [reloads, setReloads] = useState(0);

  useEffect(() => {
    let cancelled = false;
    api
      .get<{ items: AssignmentRow[] }>(`/assignments?item_kind=${kind}&item_id=${id}`)
      .then((resp) => !cancelled && setItems(resp.items ?? []))
      .catch((err: unknown) => !cancelled && setError(err));
    return () => {
      cancelled = true;
    };
  }, [kind, id, refresh, reloads]);

  async function unassign(row: AssignmentRow) {
    if (!window.confirm(`Remove this from ${row.group_name}?`)) return;
    try {
      await api.del(`/assignments/${row.id}`);
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
          {a.group_name}
          {a.rollout ? <span className="hint"> — {describeRollout(a.rollout)}</span> : null}{" "}
          {canWrite ? (
            <Button variant="quiet" onClick={() => void unassign(a)} aria-label={`Unassign ${a.group_name}`}>
              ×
            </Button>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

/** RolloutFields asks whether to phase an include in, and how. null is the
 * whole group at once. */
export function RolloutFields({ value, onChange }: { value: Rollout | null; onChange: (r: Rollout | null) => void }) {
  const phased = value !== null;
  const r = value ?? { percent: 10, step_percent: 20, step_hours: 24 };
  const set = (patch: Partial<Rollout>) => onChange({ ...r, ...patch });
  return (
    <>
      <label style={{ display: "block", marginBottom: "var(--space-2)" }}>
        <input type="checkbox" checked={phased} onChange={(e) => onChange(e.target.checked ? r : null)} /> Roll out
        in phases
      </label>
      {phased ? (
        <>
          <Field label="Start with (% of the group)" hint="The same devices stay in as it widens.">
            <input
              type="number"
              min={1}
              max={100}
              value={r.percent}
              onChange={(e) => set({ percent: Number(e.target.value) })}
            />
          </Field>
          <Field label="Then add (%)" hint="0 widens only when you change it.">
            <input
              type="number"
              min={0}
              max={100}
              value={r.step_percent ?? 0}
              onChange={(e) => {
                const step = Number(e.target.value);
                set({ step_percent: step, step_hours: step === 0 ? 0 : r.step_hours || 24 });
              }}
            />
          </Field>
          {(r.step_percent ?? 0) > 0 ? (
            <Field label="Every (hours)">
              <input
                type="number"
                min={1}
                max={720}
                value={r.step_hours ?? 24}
                onChange={(e) => set({ step_hours: Number(e.target.value) })}
              />
            </Field>
          ) : null}
        </>
      ) : null}
    </>
  );
}

/** rolloutBody is what an assignment request sends for a rollout. */
export function rolloutBody(mode: string, r: Rollout | null) {
  if (mode !== "include" || r === null) return undefined;
  return { percent: r.percent, step_percent: r.step_percent ?? 0, step_hours: r.step_hours ?? 0 };
}
