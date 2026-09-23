import { useCallback, useEffect, useState } from "react";

import { heldForApproval } from "../api/approvals";
import { api } from "../api/client";
import type { Group, Script, ScriptRun } from "../api/types";
import { SignatureField, parseSignature } from "../components/SignatureField";
import { AssignedTo, RolloutFields, rolloutBody } from "../components/Assignments";
import type { Rollout } from "../components/Assignments";
import { StatusDot } from "../components/StatusDot";
import { Button, Dialog, EmptyState, ErrorNote, Field, HeldNote, Spinner } from "../components/ui";
import { useList } from "../hooks/useList";
import { useSession } from "../session/SessionContext";
import { relative } from "./Devices";
import "./Scripts.css";

const ITEM_KIND = "script";

interface Rollup {
  rollup: Record<string, number>;
}

/** ScriptEditor creates or edits a script and its optional detection pair. */
function ScriptEditor({
  script,
  open,
  onClose,
  onSaved,
}: {
  script: Script | null;
  open: boolean;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [body, setBody] = useState("");
  const [detection, setDetection] = useState("");
  const [signatureText, setSignatureText] = useState("");
  const { signingRequired } = useSession();
  const signature = parseSignature(signatureText);
  // Renaming a signed script keeps its signature; changing its code needs a
  // new one.
  const codeChanged = !script || body !== (script.body ?? "") || detection !== (script.detection_body ?? "");
  const needsSignature = signingRequired && (codeChanged || !script?.signed);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    setName(script?.name ?? "");
    setDescription(script?.description ?? "");
    setBody(script?.body ?? "");
    setDetection(script?.detection_body ?? "");
    setSignatureText("");
    setError(null);
  }, [open, script]);

  async function save() {
    setBusy(true);
    setError(null);
    try {
      const payload = { name, description, body, detection_body: detection, ...(signature ? { signature } : {}) };
      if (script) {
        await api.post(`/scripts/${script.id}`, payload);
      } else {
        await api.post("/scripts", payload);
      }
      onSaved();
      onClose();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog title={script ? `Edit ${script.name}` : "New script"} open={open} onClose={onClose}>
      <Field label="Name">
        <input value={name} onChange={(e) => setName(e.target.value)} />
      </Field>
      <Field label="Description">
        <input value={description} onChange={(e) => setDescription(e.target.value)} />
      </Field>
      <Field label="PowerShell script" hint="Runs as SYSTEM. Editing this creates a new version.">
        <textarea className="mono" rows={8} value={body} spellCheck={false} onChange={(e) => setBody(e.target.value)} />
      </Field>
      <Field
        label="Detection script"
        hint="Optional. Exit 0 means there is nothing to do, so the script above is skipped. Anything else runs it, then checks again."
      >
        <textarea
          className="mono"
          rows={5}
          value={detection}
          spellCheck={false}
          onChange={(e) => setDetection(e.target.value)}
        />
      </Field>
      {needsSignature ? (
        <SignatureField
          value={signatureText}
          onChange={setSignatureText}
          valid={signature !== null}
          command={
            detection.trim()
              ? "retune-sign sign-script --key operations.key --detection detect.ps1 script.ps1"
              : "retune-sign sign-script --key operations.key script.ps1"
          }
        />
      ) : null}
      <ErrorNote error={error} />
      <div className="actions">
        <Button
          onClick={() => void save()}
          disabled={busy || name.trim() === "" || body.trim() === "" || (needsSignature && signature === null)}
        >
          {script ? "Save new version" : "Create script"}
        </Button>
        <Button variant="quiet" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </Dialog>
  );
}

/** AssignDialog gives a script to a group with its deployment options. */
function AssignDialog({
  script,
  open,
  onClose,
  onAssigned,
}: {
  script: Script | null;
  open: boolean;
  onClose: () => void;
  onAssigned: () => void;
}) {
  const [groups, setGroups] = useState<Group[]>([]);
  const [groupID, setGroupID] = useState("");
  const [mode, setMode] = useState("include");
  const [rollout, setRollout] = useState<Rollout | null>(null);
  const [frequency, setFrequency] = useState("once");
  const [intervalHours, setIntervalHours] = useState(24);
  const [runAs, setRunAs] = useState("system");
  const [timeoutSeconds, setTimeoutSeconds] = useState(600);
  const [error, setError] = useState<unknown>(null);
  const [held, setHeld] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (open) setHeld(false);
    if (!open) return;
    api
      .get<{ items: Group[] }>("/groups")
      .then((resp) => {
        setGroups(resp.items);
        setGroupID((current) => current || (resp.items[0]?.id ?? ""));
      })
      .catch((err: unknown) => setError(err));
  }, [open]);

  async function assign() {
    if (!script) return;
    setBusy(true);
    setError(null);
    try {
      const res = await api.post("/assignments", {
        item_kind: ITEM_KIND,
        item_id: script.id,
        group_id: groupID,
        mode,
        options:
          mode === "include"
            ? {
                frequency,
                interval_hours: intervalHours,
                run_as: runAs,
                timeout_seconds: timeoutSeconds,
              }
            : undefined,
        rollout: rolloutBody(mode, rollout),
      });
      onAssigned();
      if (heldForApproval(res)) {
        setHeld(true);
        return;
      }
      onClose();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog title={`Assign ${script?.name ?? ""}`} open={open} onClose={onClose}>
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

      {mode === "include" ? (
        <>
          <Field label="How often">
            <select value={frequency} onChange={(e) => setFrequency(e.target.value)}>
              <option value="once">Once per version</option>
              <option value="recurring">Repeatedly</option>
            </select>
          </Field>
          {frequency === "recurring" ? (
            <Field label="Every (hours)">
              <input
                type="number"
                min={1}
                value={intervalHours}
                onChange={(e) => setIntervalHours(Number(e.target.value))}
              />
            </Field>
          ) : null}
          <Field
            label="Run as"
            hint={
              runAs === "logged_in_user"
                ? "Runs in the signed-in user's session. A device with nobody signed in reports this as pending until somebody does."
                : undefined
            }
          >
            <select value={runAs} onChange={(e) => setRunAs(e.target.value)}>
              <option value="system">The system account</option>
              <option value="logged_in_user">The signed-in user</option>
            </select>
          </Field>
          <Field label="Timeout in seconds">
            <input
              type="number"
              min={1}
              max={86400}
              value={timeoutSeconds}
              onChange={(e) => setTimeoutSeconds(Number(e.target.value))}
            />
          </Field>
        </>
      ) : null}

      {mode === "include" ? <RolloutFields value={rollout} onChange={setRollout} /> : null}
      <ErrorNote error={error} />
      {held ? <HeldNote /> : null}
      <div className="actions">
        <Button onClick={() => void assign()} disabled={busy || groupID === ""}>
          Assign to group
        </Button>
        <Button variant="quiet" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </Dialog>
  );
}

/** ScriptDetail shows how a script is faring and its recent runs. */
function ScriptDetail({ script }: { script: Script }) {
  const [rollup, setRollup] = useState<Record<string, number>>({});
  const { items: runs, loading, error } = useList<ScriptRun>(`/scripts/${script.id}/runs`);

  useEffect(() => {
    api
      .get<Rollup>(`/items/${ITEM_KIND}/${script.id}/status`)
      .then((resp) => setRollup(resp.rollup))
      .catch(() => setRollup({}));
  }, [script.id]);

  const counts = Object.entries(rollup);
  return (
    <section className="script__detail">
      <h2>{script.name}</h2>
      <AssignedTo kind={ITEM_KIND} id={script.id} />
      {counts.length > 0 ? (
        <p className="script__rollup">
          {counts.map(([status, count]) => (
            <span key={status}>
              <StatusDot status={status} /> {count}
            </span>
          ))}
        </p>
      ) : (
        <p className="script__none">No device has reported on this script yet.</p>
      )}

      <ErrorNote error={error} />
      {loading ? <Spinner /> : null}
      {runs.length > 0 ? (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Device</th>
                <th>Version</th>
                <th>Status</th>
                <th>Decided by</th>
                <th>Exit</th>
                <th>When</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((run) => (
                <tr key={run.id}>
                  <td>{run.hostname}</td>
                  <td className="numeric">{run.version}</td>
                  <td>
                    <StatusDot status={run.status} />
                  </td>
                  <td>
                    {run.phase}
                    {run.remediated ? " (remediated)" : ""}
                  </td>
                  <td className="numeric">{run.exit_code}</td>
                  <td>{relative(run.started_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {runs[0]?.stdout ? (
        <pre className="mono script__output">{runs[0].stdout}</pre>
      ) : null}
      {runs[0]?.stderr ? (
        <pre className="mono script__output script__output--error">{runs[0].stderr}</pre>
      ) : null}
    </section>
  );
}

export default function Scripts() {
  const { canWrite } = useSession();
  const { items, total, loading, error, offset, setOffset, reload } = useList<Script>("/scripts");
  const [editing, setEditing] = useState<Script | null>(null);
  const [editorOpen, setEditorOpen] = useState(false);
  const [assigning, setAssigning] = useState<Script | null>(null);
  const [selected, setSelected] = useState<Script | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);

  const openEditor = useCallback(async (script: Script | null) => {
    setActionError(null);
    if (script) {
      try {
        // The listing omits the body; the editor needs it.
        setEditing(await api.get<Script>(`/scripts/${script.id}`));
      } catch (err) {
        setActionError(err);
        return;
      }
    } else {
      setEditing(null);
    }
    setEditorOpen(true);
  }, []);

  async function remove(script: Script) {
    if (!window.confirm(`Delete ${script.name}? Its assignments go with it; its run history stays.`)) {
      return;
    }
    try {
      await api.del(`/scripts/${script.id}`);
      if (selected?.id === script.id) setSelected(null);
      reload();
    } catch (err) {
      setActionError(err);
    }
  }

  return (
    <>
      <div className="content__head">
        <h1>Scripts</h1>
        {canWrite ? <Button onClick={() => void openEditor(null)}>New script</Button> : null}
      </div>

      <ErrorNote error={error} />
      <ErrorNote error={actionError} />
      {loading ? <Spinner /> : null}

      {!loading && items.length === 0 ? (
        <EmptyState title="No scripts yet.">
          <p>A script here is deployed to groups and keeps applying, unlike a one-off command.</p>
        </EmptyState>
      ) : null}

      {items.length > 0 ? (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th className="numeric">Version</th>
                <th>Updated</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {items.map((script) => (
                <tr key={script.id}>
                  <td>
                    <button className="linklike" onClick={() => setSelected(script)}>
                      {script.name}
                    </button>
                    {script.description ? <div className="script__description">{script.description}</div> : null}
                  </td>
                  <td className="numeric">{script.current_version}</td>
                  <td>{relative(script.updated_at)}</td>
                  <td className="script__actions">
                    {canWrite ? (
                      <>
                        <Button variant="quiet" onClick={() => void openEditor(script)}>
                          Edit
                        </Button>
                        <Button variant="quiet" onClick={() => setAssigning(script)}>
                          Assign
                        </Button>
                        <Button variant="quiet" onClick={() => void remove(script)}>
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

      {selected ? <ScriptDetail script={selected} /> : null}

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

      <ScriptEditor script={editing} open={editorOpen} onClose={() => setEditorOpen(false)} onSaved={reload} />
      <AssignDialog
        script={assigning}
        open={assigning !== null}
        onClose={() => setAssigning(null)}
        onAssigned={reload}
      />
    </>
  );
}
