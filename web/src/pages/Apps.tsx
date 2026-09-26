import { useCallback, useEffect, useState } from "react";

import { heldForApproval } from "../api/approvals";
import { api } from "../api/client";
import type { App, AppInstall, DetectionRule, Group } from "../api/types";
import { AssignedTo, RolloutFields, rolloutBody } from "../components/Assignments";
import { SignatureField, SignedSubject, parseSignature } from "../components/SignatureField";
import type { Rollout } from "../components/Assignments";
import { StatusDot } from "../components/StatusDot";
import { Button, Dialog, EmptyState, ErrorNote, Field, HeldNote, Spinner } from "../components/ui";
import { useList } from "../hooks/useList";
import { useSession } from "../session/SessionContext";
import { relative } from "./Devices";
import "./Apps.css";

const ITEM_KIND = "app";

interface Rollup {
  rollup: Record<string, number>;
}

/** parseExitCodes reads "0, 3010, 1641" into numbers, or null if any isn't one. */
export function parseExitCodes(text: string): number[] | null {
  const parts = text
    .split(/[\s,]+/)
    .map((p) => p.trim())
    .filter(Boolean);
  const codes = parts.map((p) => Number(p));
  return codes.every((c) => Number.isInteger(c)) ? codes : null;
}

/** installerTypeOf is "msi" or "exe" from a file name, or "" for anything else. */
export function installerTypeOf(fileName: string): "msi" | "exe" | "" {
  const lower = fileName.toLowerCase();
  if (lower.endsWith(".msi")) return "msi";
  if (lower.endsWith(".exe")) return "exe";
  return "";
}

const DEFAULT_EXIT_CODES = "0, 3010, 1641";

/** AppEditor creates or edits an app: a winget package, or an uploaded installer. */
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
  const [source, setSource] = useState<"winget" | "package">("winget");
  const [packageID, setPackageID] = useState("");
  const [pinnedVersion, setPinnedVersion] = useState("");
  const [installArgs, setInstallArgs] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [uninstallCommand, setUninstallCommand] = useState("");
  const [exitCodes, setExitCodes] = useState(DEFAULT_EXIT_CODES);
  const [detection, setDetection] = useState<DetectionRule>({ type: "msi_product_code" });
  const [uninstallPrevious, setUninstallPrevious] = useState(false);
  const [signatureText, setSignatureText] = useState("");
  const { signingRequired } = useSession();
  const signature = parseSignature(signatureText);
  // An edit to something already sent to many devices can be held for a
  // second administrator; the dialog stays open to say so.
  const [held, setHeld] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    setName(app?.name ?? "");
    setDescription(app?.description ?? "");
    setSource(app?.source === "package" ? "package" : "winget");
    setPackageID(app?.package_id ?? "");
    setPinnedVersion(app?.pinned_version ?? "");
    setInstallArgs(app?.install_args ?? "");
    setFile(null);
    setUninstallCommand(app?.uninstall_command ?? "");
    setExitCodes(app?.success_exit_codes?.length ? app.success_exit_codes.join(", ") : DEFAULT_EXIT_CODES);
    setDetection(app?.detection ?? { type: "msi_product_code" });
    setUninstallPrevious(app?.uninstall_previous ?? false);
    setSignatureText("");
    setError(null);
    setHeld(false);
  }, [open, app]);

  const fileName = file?.name ?? (app?.source === "package" ? (app.file_name ?? "") : "");
  const installerType = installerTypeOf(fileName);
  const codes = parseExitCodes(exitCodes);
  const packageReady = fileName !== "" && installerType !== "" && codes !== null;
  const ready = name.trim() !== "" && (source === "winget" ? packageID.trim() !== "" : packageReady);

  // What an operations signature covers: everything but the name and
  // description. A package's hash comes from the file when one is chosen,
  // which retune-sign --file reads for itself.
  const definition: Record<string, unknown> =
    source === "winget"
      ? { package_id: packageID, pinned_version: pinnedVersion, install_args: installArgs }
      : {
          source: "package",
          installer_type: installerType,
          file_name: fileName,
          ...(file ? {} : { file_sha256: app?.file_sha256 ?? "" }),
          install_args: installArgs,
          uninstall_command: uninstallCommand,
          success_exit_codes: codes ?? [],
          detection: cleanRule(detection),
          uninstall_previous: uninstallPrevious,
        };
  // Renaming a signed app keeps its signature; changing what it installs
  // needs a new one.
  const definitionChanged = !app || file !== null || JSON.stringify(definition) !== JSON.stringify(definitionOf(app));
  const needsSignature = signingRequired && (definitionChanged || !app?.signed);

  function setRule(patch: Partial<DetectionRule>) {
    setDetection((d) => ({ ...d, ...patch }));
  }

  async function save() {
    setBusy(true);
    setError(null);
    try {
      let payload: Record<string, unknown>;
      if (source === "winget") {
        payload = {
          name,
          description,
          package_id: packageID,
          pinned_version: pinnedVersion,
          install_args: installArgs,
        };
      } else {
        let sha = app?.source === "package" ? (app.file_sha256 ?? "") : "";
        if (file) {
          const uploaded = await api.postBinary<{ file_sha256: string }>(
            `/app-packages?file_name=${encodeURIComponent(file.name)}`,
            file,
          );
          sha = uploaded.file_sha256;
        }
        payload = {
          name,
          description,
          source: "package",
          installer_type: installerType,
          file_sha256: sha,
          file_name: fileName,
          install_args: installArgs,
          uninstall_command: uninstallCommand,
          success_exit_codes: codes ?? [],
          detection: cleanRule(detection),
          uninstall_previous: uninstallPrevious,
        };
      }
      if (signature) payload.signature = signature;
      if (app) {
        const res = await api.post(`/apps/${app.id}`, payload);
        if (heldForApproval(res)) {
          onSaved();
          setHeld(true);
          return;
        }
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
      <fieldset className="apps__source">
        <legend>Installs from</legend>
        <label>
          <input
            type="radio"
            name="source"
            checked={source === "winget"}
            onChange={() => setSource("winget")}
          />
          A winget package
        </label>
        <label>
          <input
            type="radio"
            name="source"
            checked={source === "package"}
            onChange={() => setSource("package")}
          />
          An installer I upload (MSI or EXE)
        </label>
      </fieldset>

      {source === "winget" ? (
        <>
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
        </>
      ) : (
        <>
          <Field
            label="Installer"
            hint={
              fileName
                ? `${fileName}${file ? "" : " (choose a file to replace it)"}. Up to 2 GiB.`
                : "An .msi or .exe file, up to 2 GiB."
            }
          >
            <input
              type="file"
              accept=".msi,.exe"
              aria-label="Installer file"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            />
          </Field>
          {fileName && installerType === "" ? (
            <p className="note">The installer must be an .msi or .exe file.</p>
          ) : null}
          <Field
            label={installerType === "exe" ? "Install arguments" : "Extra msiexec arguments"}
            hint={
              installerType === "exe"
                ? "The switches that make this setup program silent, such as /S or /quiet /norestart. Passed exactly as written."
                : "Optional, after msiexec /i <file> /qn /norestart — such as properties: ALLUSERS=1."
            }
          >
            <input className="mono" value={installArgs} onChange={(e) => setInstallArgs(e.target.value)} />
          </Field>
          <Field
            label="Uninstall command"
            hint={
              installerType === "msi"
                ? "Optional. Left blank, an MSI detected by its product code is removed with msiexec /x."
                : 'The whole command line, such as "%ProgramFiles%\\Contoso\\uninstall.exe" /S. Needed to uninstall.'
            }
          >
            <input className="mono" value={uninstallCommand} onChange={(e) => setUninstallCommand(e.target.value)} />
          </Field>
          <Field
            label="Success exit codes"
            hint="Comma-separated. 3010 and 1641 also mean a restart is needed to finish; Retune never restarts on its own."
          >
            <input className="mono" value={exitCodes} onChange={(e) => setExitCodes(e.target.value)} />
          </Field>
          {codes === null ? <p className="note">Exit codes must be whole numbers.</p> : null}

          <fieldset className="apps__detection">
            <legend>Detection</legend>
            <p className="apps__hint">How a device tells whether this app is installed, before and after installing.</p>
            <Field label="Detect by">
              <select
                aria-label="Detect by"
                value={detection.type}
                onChange={(e) => setDetection({ type: e.target.value as DetectionRule["type"] })}
              >
                <option value="msi_product_code">MSI product code</option>
                <option value="registry">Registry key or value</option>
                <option value="file">File</option>
              </select>
            </Field>
            {detection.type === "msi_product_code" ? (
              <Field
                label="Product code"
                hint="The MSI's ProductCode, braces included. Once installed on a test machine it appears under HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall."
              >
                <input
                  className="mono"
                  placeholder="{00000000-0000-0000-0000-000000000000}"
                  value={detection.product_code ?? ""}
                  onChange={(e) => setRule({ product_code: e.target.value.trim() })}
                />
              </Field>
            ) : null}
            {detection.type === "registry" ? (
              <>
                <Field label="Key" hint="Under HKEY_LOCAL_MACHINE; both 64- and 32-bit views are checked.">
                  <input
                    className="mono"
                    placeholder="SOFTWARE\Contoso\App"
                    value={detection.key ?? ""}
                    onChange={(e) => setRule({ key: e.target.value })}
                  />
                </Field>
                <Field label="Value" hint="Optional. Blank means the key existing is enough.">
                  <input
                    className="mono"
                    value={detection.value ?? ""}
                    onChange={(e) => setRule({ value: e.target.value })}
                  />
                </Field>
                {detection.value ? (
                  <Field label="Equals" hint="Optional. The value must be exactly this.">
                    <input
                      className="mono"
                      value={detection.equals ?? ""}
                      onChange={(e) => setRule({ equals: e.target.value })}
                    />
                  </Field>
                ) : null}
              </>
            ) : null}
            {detection.type === "file" ? (
              <Field label="Path" hint="Environment variables such as %ProgramFiles% are expanded.">
                <input
                  className="mono"
                  placeholder="%ProgramFiles%\Contoso\app.exe"
                  value={detection.path ?? ""}
                  onChange={(e) => setRule({ path: e.target.value })}
                />
              </Field>
            ) : null}
            {detection.type !== "registry" || (detection.value && !detection.equals) ? (
              <Field label="At least version" hint="Optional, such as 2.1 — older counts as not installed.">
                <input
                  className="mono"
                  value={detection.version_at_least ?? ""}
                  onChange={(e) => setRule({ version_at_least: e.target.value.trim() })}
                />
              </Field>
            ) : null}
          </fieldset>

          {app ? (
            <label className="apps__check">
              <input
                type="checkbox"
                checked={uninstallPrevious}
                onChange={(e) => setUninstallPrevious(e.target.checked)}
              />
              Remove the previous version first, for installers that can't upgrade in place
            </label>
          ) : null}
        </>
      )}
      {needsSignature ? (
        <>
          <SignedSubject fileName="app.json" value={definition} />
          <SignatureField
            value={signatureText}
            onChange={setSignatureText}
            valid={signature !== null}
            command={
              source === "package" && file
                ? `retune-sign sign-app --key operations.key --file ${file.name} app.json`
                : "retune-sign sign-app --key operations.key app.json"
            }
          />
        </>
      ) : null}
      <ErrorNote error={error} />
      {held ? <HeldNote /> : null}
      <div className="actions">
        <Button onClick={() => void save()} disabled={busy || !ready || (needsSignature && signature === null)}>
          {busy && file ? "Uploading…" : app ? "Save changes" : "Create app"}
        </Button>
        <Button variant="quiet" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </Dialog>
  );
}

/** definitionOf is what the editor would sign for an app as it is saved now. */
function definitionOf(app: App): Record<string, unknown> {
  if (app.source !== "package") {
    return { package_id: app.package_id, pinned_version: app.pinned_version ?? "", install_args: app.install_args ?? "" };
  }
  return {
    source: "package",
    installer_type: app.installer_type ?? "",
    file_name: app.file_name ?? "",
    file_sha256: app.file_sha256 ?? "",
    install_args: app.install_args ?? "",
    uninstall_command: app.uninstall_command ?? "",
    success_exit_codes: app.success_exit_codes ?? [],
    detection: cleanRule(app.detection ?? { type: "msi_product_code" }),
    uninstall_previous: app.uninstall_previous ?? false,
  };
}

/** cleanRule drops the fields a rule's type doesn't use, which the server refuses. */
export function cleanRule(rule: DetectionRule): DetectionRule {
  const keep: Record<DetectionRule["type"], (keyof DetectionRule)[]> = {
    msi_product_code: ["product_code", "version_at_least"],
    registry: ["key", "value", "equals", "version_at_least"],
    file: ["path", "version_at_least"],
  };
  const out: DetectionRule = { type: rule.type };
  for (const field of keep[rule.type]) {
    const value = rule[field];
    if (value) (out as unknown as Record<string, string>)[field] = value;
  }
  if (out.equals) delete out.version_at_least;
  return out;
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
  const [rollout, setRollout] = useState<Rollout | null>(null);
  const [intent, setIntent] = useState("install");
  const [timeoutSeconds, setTimeoutSeconds] = useState(900);
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
    if (!app) return;
    setBusy(true);
    setError(null);
    try {
      const res = await api.post("/assignments", {
        item_kind: ITEM_KIND,
        item_id: app.id,
        group_id: groupID,
        mode,
        options: mode === "include" ? { intent, timeout_seconds: timeoutSeconds } : undefined,
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
      <AssignedTo kind={ITEM_KIND} id={app.id} />
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
                  <td className="mono">{app.source === "package" ? app.file_name : app.package_id}</td>
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
