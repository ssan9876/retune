import { useCallback, useEffect, useState } from "react";

import { ApiError, api } from "../api/client";
import type { Device, Group, ListResponse } from "../api/types";
import { heldForApproval } from "../api/approvals";
import { Button, Dialog, EmptyState, ErrorNote, Field, HeldNote, Spinner } from "../components/ui";
import { useSession } from "../session/SessionContext";
import "./Groups.css";

const KIND_LABEL: Record<string, string> = {
  builtin: "Built in",
  dynamic: "Rule",
  static: "Chosen by hand",
};

/** RulePreview reports what a rule matches, or where it stops making sense. */
function RulePreview({ rule }: { rule: string }) {
  const [count, setCount] = useState<number | null>(null);
  const [sample, setSample] = useState<Device[]>([]);
  const [problem, setProblem] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);

  useEffect(() => {
    if (rule.trim() === "") {
      setCount(null);
      setProblem(null);
      return;
    }
    // Wait for a pause in typing: every keystroke would otherwise run a query.
    let cancelled = false;
    const timer = setTimeout(() => {
      setChecking(true);
      api
        .post<ListResponse<Device>>("/groups/preview", { rule })
        .then((page) => {
          if (cancelled) return;
          setCount(page.total);
          setSample(page.items.slice(0, 5));
          setProblem(null);
        })
        .catch((err: unknown) => {
          if (cancelled) return;
          setCount(null);
          setProblem(err instanceof ApiError ? err.message : String(err));
        })
        .finally(() => {
          if (!cancelled) setChecking(false);
        });
    }, 400);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [rule]);

  if (rule.trim() === "") return null;
  if (problem) {
    return (
      <p className="rule__problem" role="alert">
        {problem}
      </p>
    );
  }
  if (checking && count === null) return <Spinner label="Checking…" />;
  if (count === null) return null;
  return (
    <div className="rule__preview">
      <p>
        Matches {count} {count === 1 ? "device" : "devices"}.
      </p>
      {sample.length > 0 ? (
        <p className="rule__sample">{sample.map((d) => d.hostname).join(", ")}</p>
      ) : null}
    </div>
  );
}

export default function Groups() {
  const { canWrite } = useSession();
  const [groups, setGroups] = useState<Group[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);

  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<Group | null>(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [kind, setKind] = useState("dynamic");
  const [rule, setRule] = useState("");
  const [formError, setFormError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  // A rule change under code assigned to the group waits for a second
  // administrator; the dialog stays open to say so.
  const [held, setHeld] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    api
      .get<{ items: Group[] }>("/groups")
      .then((resp) => {
        setGroups(resp.items);
        setError(null);
      })
      .catch((err: unknown) => setError(err))
      .finally(() => setLoading(false));
  }, []);

  useEffect(load, [load]);

  function startCreate() {
    setEditing(null);
    setName("");
    setDescription("");
    setKind("dynamic");
    setRule("");
    setFormError(null);
    setHeld(false);
    setOpen(true);
  }

  function startEdit(group: Group) {
    setEditing(group);
    setName(group.name);
    setDescription(group.description);
    setKind(group.kind);
    setRule(group.rule);
    setFormError(null);
    setHeld(false);
    setOpen(true);
  }

  async function save() {
    setBusy(true);
    setFormError(null);
    try {
      const body = { name, description, kind, rule: kind === "dynamic" ? rule : "" };
      if (editing) {
        const res = await api.post(`/groups/${editing.id}`, body);
        if (heldForApproval(res)) {
          setHeld(true);
          return;
        }
      } else {
        await api.post("/groups", body);
      }
      setOpen(false);
      load();
    } catch (err) {
      setFormError(err);
    } finally {
      setBusy(false);
    }
  }

  async function remove(group: Group) {
    if (!window.confirm(`Delete ${group.name}? Anything assigned to it stops reaching its devices.`)) {
      return;
    }
    try {
      await api.del(`/groups/${group.id}`);
      load();
    } catch (err) {
      setError(err);
    }
  }

  return (
    <>
      <div className="content__head">
        <h1>Groups</h1>
        {canWrite ? <Button onClick={startCreate}>New group</Button> : null}
      </div>

      <ErrorNote error={error} />
      {loading ? <Spinner /> : null}

      {!loading && groups.length === 0 ? (
        <EmptyState title="No groups yet.">
          <p>Group devices by a rule over their inventory, or pick them by hand.</p>
        </EmptyState>
      ) : null}

      {groups.length > 0 ? (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Kind</th>
                <th>Rule</th>
                <th className="numeric">Devices</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {groups.map((group) => (
                <tr key={group.id}>
                  <td>
                    <div>{group.name}</div>
                    {group.description ? (
                      <div className="group__description">{group.description}</div>
                    ) : null}
                  </td>
                  <td>{KIND_LABEL[group.kind] ?? group.kind}</td>
                  <td className="mono group__rule">{group.rule || "—"}</td>
                  <td className="numeric">{group.member_count}</td>
                  <td className="group__actions">
                    {canWrite && group.kind !== "builtin" ? (
                      <>
                        <Button variant="quiet" onClick={() => startEdit(group)}>
                          Edit
                        </Button>
                        <Button variant="quiet" onClick={() => remove(group)}>
                          Delete
                        </Button>
                      </>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      <Dialog
        title={editing ? `Edit ${editing.name}` : "New group"}
        open={open}
        onClose={() => setOpen(false)}
      >
        <Field label="Name">
          <input value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Description">
          <input value={description} onChange={(e) => setDescription(e.target.value)} />
        </Field>
        {editing ? null : (
          <Field label="Membership">
            <select value={kind} onChange={(e) => setKind(e.target.value)}>
              <option value="dynamic">By rule</option>
              <option value="static">Chosen by hand</option>
            </select>
          </Field>
        )}
        {kind === "dynamic" ? (
          <Field
            label="Rule"
            hint="For example: ram_gb >= 16 AND hostname LIKE 'DESKTOP-%'"
          >
            <textarea
              className="mono"
              rows={3}
              value={rule}
              onChange={(e) => setRule(e.target.value)}
            />
          </Field>
        ) : null}
        {kind === "dynamic" ? <RulePreview rule={rule} /> : null}

        <ErrorNote error={formError} />
        {held ? <HeldNote /> : null}
        <div className="actions">
          <Button onClick={save} disabled={busy || name.trim() === ""}>
            {editing ? "Save changes" : "Create group"}
          </Button>
          <Button variant="quiet" onClick={() => setOpen(false)}>
            Cancel
          </Button>
        </div>
      </Dialog>
    </>
  );
}
