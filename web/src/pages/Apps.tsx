import { useCallback, useEffect, useState } from "react";

import { api } from "../api/client";
import type { App, AppInstall, Group } from "../api/types";
import { StatusDot } from "../components/StatusDot";
import { Button, Dialog, EmptyState, ErrorNote, Field, Spinner } from "../components/ui";
import { useList } from "../hooks/useList";
import { useSession } from "../session/SessionContext";
import { relative } from "./Devices";
import "./Apps.css";

const ITEM_KIND = "app";

interface Rollup {
  rollup: Record<string, number>;
}

/** AppEditor creates or edits an app and the package it installs. */
function AppEditor({
  app,
  open,
  onClose,
  onSaved,
}: {
  app: App | null;
  open: boolean;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [packageID, setPackageID] = useState("");
  const [pinnedVersion, setPinnedVersion] = useState("");
  const [installArgs, setInstallArgs] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    setName(app?.name ?? "");
    setDescription(app?.description ?? "");
    setPackageID(app?.package_id ?? "");
    setPinnedVersion(app?.pinned_version ?? "");
    setInstallArgs(app?.install_args ?? "");
    setError(null);
  }, [open, app]);

  async function save() {
    setBusy(true);
    setError(null);
    try {
      const payload = {
        name,
        description,
        package_id: packageID,
        pinned_version: pinnedVersion,
        install_args: installArgs,
      };
      if (app) {
        await api.post(`/apps/${app.id}`, payload);
      } else {
        await api.post("/apps", payload);
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
    <Dialog title={app ? `Edit ${app.name}` : "New app"} open={open} onClose={onClose}>
      <Field label="Name">
        <input value={name} onChange={(e) => setName(e.target.value)} />
      </Field>
      <Field label="Description">
        <input value={description} onChange={(e) => setDescription(e.target.value)} />
      </Field>
      <Field label="Package ID" hint="The winget package identifier, such as 7zip.7zip.">
        <input className="mono" value={packageID} onChange={(e) => setPackageID(e.target.value)} />
      </Field>
      <Field
        label="Pinned version"
        hint="Leave blank to install whatever is current when a device first installs it. Retune does not chase later releases on its own; set a version here to hold to one."
      >
        <input className="mono" value={pinnedVersion} onChange={(e) => setPinnedVersion(e.target.value)} />
      </Field>
      <Field
        label="Extra install arguments"
        hint="Optional. Arguments are separated by spaces; a value containing spaces of its own is not supported."
      >
        <input className="mono" value={installArgs} onChange={(e) => setInstallArgs(e.target.value)} />
      </Field>
      <ErrorNote error={error} />
      <div className="actions">
        <Button onClick={() => void save()} disabled={busy || name.trim() === "" || packageID.trim() === ""}>
          {app ? "Save changes" : "Create app"}
        </Button>
        <Button variant="quiet" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </Dialog>
  );
}

/** AssignDialog gives an app to a group, deciding whether it installs or uninstalls. */
function AssignDialog({
  app,
  open,
  onClose,
  onAssigned,
}: {
  app: App | null;
  open: boolean;
  onClose: () => void;
  onAssigned: () => void;
}) {
  const [groups, setGroups] = useState<Group[]>([]);
  const [groupID, setGroupID] = useState("");
  const [mode, setMode] = useState("include");
  const [intent, setIntent] = useState("install");
  const [timeoutSeconds, setTimeoutSeconds] = useState(900);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
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
    if (!app) return;
    setBusy(true);
    setError(null);
    try {
      await api.post("/assignments", {
        item_kind: ITEM_KIND,
        item_id: app.id,
        group_id: groupID,
        mode,
        options: mode === "include" ? { intent, timeout_seconds: timeoutSeconds } : undefined,
      });
      onAssigned();
      onClose();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog title={`Assign ${app?.name ?? ""}`} open={open} onClose={onClose}>
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
          <Field
            label="What to do"
            hint={
              intent === "uninstall"
                ? "This removes it from every device in the group. Leaving the group does not."
                : undefined
            }
          >
            <select value={intent} onChange={(e) => setIntent(e.target.value)}>
              <option value="install">Install</option>
              <option value="uninstall">Uninstall</option>
            </select>
          </Field>
          <Field label="Timeout in seconds" hint="Installs are far slower than scripts: 60 to 14400 seconds.">
            <input
              type="number"
              min={60}
              max={14400}
              value={timeoutSeconds}
              onChange={(e) => setTimeoutSeconds(Number(e.target.value))}
            />
          </Field>
        </>
      ) : null}

      <ErrorNote error={error} />
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

/** AppDetail shows how an app's rollout is faring and its recent installs. */
function AppDetail({ app }: { app: App }) {
  const [rollup, setRollup] = useState<Record<string, number>>({});
  const { items: installs, loading, error } = useList<AppInstall>(`/apps/${app.id}/installs`);

  useEffect(() => {
    api
      .get<Rollup>(`/items/${ITEM_KIND}/${app.id}/status`)
      .then((resp) => setRollup(resp.rollup))
      .catch(() => setRollup({}));
  }, [app.id]);

  const counts = Object.entries(rollup);
  return (
    <section className="app__detail">
      <h2>{app.name}</h2>
      {counts.length > 0 ? (
        <p className="app__rollup">
          {counts.map(([status, count]) => (
            <span key={status}>
              <StatusDot status={status} /> {count}
            </span>
          ))}
        </p>
      ) : (
        <p className="app__none">No device has reported on this app yet.</p>
      )}

      <ErrorNote error={error} />
      {loading ? <Spinner /> : null}
      {installs.length > 0 ? (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Device</th>
                <th>Intent</th>
                <th>Status</th>
                <th className="numeric">Version</th>
                <th>Installed version</th>
                <th>Exit</th>
                <th>When</th>
              </tr>
            </thead>
            <tbody>
              {installs.map((install) => (
                <tr key={install.id}>
                  <td>{install.hostname}</td>
                  <td>{install.intent}</td>
                  <td>
                    <StatusDot status={install.status} />
                  </td>
                  <td className="numeric">{install.version}</td>
                  <td>{install.installed_version}</td>
                  <td className="numeric">{install.exit_code}</td>
                  <td>{relative(install.started_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {installs[0]?.detail ? <pre className="mono app__output">{installs[0].detail}</pre> : null}
      {installs[0]?.error ? <pre className="mono app__output app__output--error">{installs[0].error}</pre> : null}
      {installs[0]?.stdout ? <pre className="mono app__output">{installs[0].stdout}</pre> : null}
      {installs[0]?.stderr ? (
        <pre className="mono app__output app__output--error">{installs[0].stderr}</pre>
      ) : null}
    </section>
  );
}

export default function Apps() {
  const { canWrite } = useSession();
  const { items, total, loading, error, offset, setOffset, reload } = useList<App>("/apps");
  const [editing, setEditing] = useState<App | null>(null);
  const [editorOpen, setEditorOpen] = useState(false);
  const [assigning, setAssigning] = useState<App | null>(null);
  const [selected, setSelected] = useState<App | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);

  const openEditor = useCallback(async (app: App | null) => {
    setActionError(null);
    if (app) {
      try {
        setEditing(await api.get<App>(`/apps/${app.id}`));
      } catch (err) {
        setActionError(err);
        return;
      }
    } else {
      setEditing(null);
    }
    setEditorOpen(true);
  }, []);

  async function remove(app: App) {
    if (!window.confirm(`Delete ${app.name}? Its assignments go with it; its install history stays.`)) {
      return;
    }
    try {
      await api.del(`/apps/${app.id}`);
      if (selected?.id === app.id) setSelected(null);
      reload();
    } catch (err) {
      setActionError(err);
    }
  }

  return (
    <>
      <div className="content__head">
        <h1>Apps</h1>
        {canWrite ? <Button onClick={() => void openEditor(null)}>New app</Button> : null}
      </div>

      <ErrorNote error={error} />
      <ErrorNote error={actionError} />
      {loading ? <Spinner /> : null}

      {!loading && items.length === 0 ? (
        <EmptyState title="No apps yet.">
          <p>An app here installs a package on every device in a group, and keeps it present.</p>
        </EmptyState>
      ) : null}

      {items.length > 0 ? (
        <div className="table-scroll">
          <table className="apps-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Package</th>
                <th className="numeric">Version</th>
                <th>Updated</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {items.map((app) => (
                <tr key={app.id}>
                  <td>
                    <button className="linklike" onClick={() => setSelected(app)}>
                      {app.name}
                    </button>
                    {app.description ? <div className="app__description">{app.description}</div> : null}
                  </td>
                  <td className="mono">{app.package_id}</td>
                  <td className="numeric">{app.current_version}</td>
                  <td>{relative(app.updated_at)}</td>
                  <td className="app__actions">
                    {canWrite ? (
                      <>
                        <Button variant="quiet" onClick={() => void openEditor(app)}>
                          Edit
                        </Button>
                        <Button variant="quiet" onClick={() => setAssigning(app)}>
                          Assign
                        </Button>
                        <Button variant="quiet" onClick={() => void remove(app)}>
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

      {selected ? <AppDetail app={selected} /> : null}

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

      <AppEditor app={editing} open={editorOpen} onClose={() => setEditorOpen(false)} onSaved={reload} />
      <AssignDialog app={assigning} open={assigning !== null} onClose={() => setAssigning(null)} onAssigned={reload} />
    </>
  );
}
