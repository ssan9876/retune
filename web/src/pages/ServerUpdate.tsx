import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";

import { heldForApproval } from "../api/approvals";
import { api } from "../api/client";
import { updateDone } from "../api/serverupdate";
import type { ServerInfo, UpdateState } from "../api/serverupdate";
import { Button, ErrorNote, HeldNote, Spinner } from "../components/ui";
import { useSession } from "../session/SessionContext";
import { relative } from "./Devices";
import "./ServerUpdate.css";

/** The steps an update goes through, in order, as the page names them. */
const STEPS: { phase: UpdateState["phase"]; label: string }[] = [
  { phase: "verifying", label: "Verify the signed release" },
  { phase: "backing_up", label: "Back up the database" },
  { phase: "pulling", label: "Fetch the new version" },
  { phase: "restarting", label: "Restart on the new version" },
  { phase: "healthy", label: "Ready" },
];

const OUTCOME: Partial<Record<UpdateState["phase"], string>> = {
  healthy: "Updated",
  rolled_back: "Rolled back",
  failed: "Failed",
};

function modeLabel(mode: ServerInfo["mode"]): string {
  return mode === "docker" ? "the updater service (Docker Compose)" : mode === "binary" ? "systemd (binary install)" : "";
}

function Progress({ state }: { state: UpdateState }) {
  const done = updateDone(state);
  const reached = STEPS.findIndex((s) => s.phase === state.phase);
  return (
    <div className="server-update__progress" aria-label="Update progress">
      <p>
        <strong>
          {done ? OUTCOME[state.phase] : "Updating"} {state.from_version ? `${state.from_version} → ` : ""}
          {state.version}
        </strong>
        {state.requested_by ? <> · asked for by {state.requested_by}</> : null} · {relative(state.updated_at)}
      </p>
      {state.phase === "healthy" || !done ? (
        <ol className="server-update__steps">
          {STEPS.map((s, i) => (
            <li
              key={s.phase}
              className={
                state.phase === "healthy" || i < reached ? "is-done" : i === reached ? "is-current" : undefined
              }
            >
              {s.label}
            </li>
          ))}
        </ol>
      ) : null}
      {state.detail ? <p className="hint">{state.detail}</p> : null}
      {state.error ? <p className="server-update__error">{state.error}</p> : null}
      {state.backup ? (
        <p className="hint">
          Database backup: <span className="mono">{state.backup}</span>
        </p>
      ) : null}
    </div>
  );
}

/** ServerUpdate shows the running version and the newest verified release,
 * and lets an administrator update to it. The updater verifies the release
 * itself, backs the database up, and puts the old version back if the new one
 * does not become ready. */
export default function ServerUpdate() {
  const { admin, canWrite } = useSession();
  const [info, setInfo] = useState<ServerInfo | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [unreachable, setUnreachable] = useState(false);
  const [busy, setBusy] = useState(false);
  const [held, setHeld] = useState(false);
  const loaded = useRef(false);

  const load = useCallback(() => {
    api
      .get<ServerInfo>("/server")
      .then((next) => {
        loaded.current = true;
        setInfo(next);
        setUnreachable(false);
      })
      .catch((err: unknown) => {
        // While the server restarts it does not answer; that is expected once
        // the page has loaded, and an error only before.
        if (loaded.current) setUnreachable(true);
        else setError(err);
      });
  }, []);
  useEffect(load, [load]);

  const running = (info?.state && !updateDone(info.state)) || unreachable;
  useEffect(() => {
    if (!running) return;
    const t = window.setInterval(load, 3000);
    return () => window.clearInterval(t);
  }, [running, load]);

  const mayUpdate = canWrite && admin?.role === "admin" && admin?.scope == null;

  async function update() {
    if (!info?.latest) return;
    const question =
      `Update Retune from ${info.version} to ${info.latest.version}?\n\n` +
      "The database is backed up first, then the server restarts on the new version: expect a minute or two when " +
      "the console and agents cannot reach it. If the new version does not become ready, the previous one is put " +
      "back automatically.\n\n" +
      "Database migrations run when the new version starts. If it is rolled back after migrating, restoring the " +
      "backup is what brings the data back, so keep it.";
    if (!window.confirm(question)) return;
    setBusy(true);
    setError(null);
    setHeld(false);
    try {
      const res = await api.post<unknown>("/server/update", { version: info.latest.version });
      if (heldForApproval(res)) setHeld(true);
      load();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  if (!info) {
    return (
      <>
        <div className="content__head">
          <h1>Server update</h1>
        </div>
        <ErrorNote error={error} />
        {!error ? <Spinner /> : null}
      </>
    );
  }

  const canApply = info.mode !== "none" && !info.mode_note;
  return (
    <>
      <div className="content__head">
        <h1>Server update</h1>
      </div>

      <section className="server-update" aria-label="Versions">
        <dl className="server-update__versions">
          <dt>Running</dt>
          <dd>
            <span className="mono">{info.version}</span>
            {!info.stamped ? <span className="hint"> (a development build: every release is newer)</span> : null}
          </dd>
          <dt>Newest release</dt>
          <dd>
            {info.latest ? (
              <>
                <span className="mono">{info.latest.version}</span>
                {info.latest.prerelease ? <span className="server-update__tag">prerelease</span> : null}
                <span className="hint"> published {relative(info.latest.published_at)}</span>
              </>
            ) : (
              <span className="hint">
                {info.latest_error
                  ? `Releases cannot be read: ${info.latest_error}`
                  : "None found yet. The release feed looks for them; see Agent versions."}
              </span>
            )}
          </dd>
        </dl>

        {info.latest && !info.update_available ? <p className="server-update__ok">This server is up to date.</p> : null}

        {unreachable && info.state ? <p className="hint">The server is restarting; this page will catch up.</p> : null}
        {info.state ? <Progress state={info.state} /> : null}

        {info.update_available && info.latest ? (
          <div className="server-update__available">
            <h2>Retune {info.latest.version} is available</h2>
            {info.latest.notes ? <pre className="server-update__notes">{info.latest.notes}</pre> : null}
            {canApply ? (
              <p className="hint">
                Applied by {modeLabel(info.mode)}. It verifies the release against the release keys itself, backs the
                database up, restarts the server on the new version, and rolls back if it does not become ready.
                Migrations run on start, so a rollback after one relies on that backup.
              </p>
            ) : (
              <p className="server-update__error">{info.mode_note}</p>
            )}
            {info.pending_approval_id ? (
              <p className="hint">
                An update is waiting for a second administrator on <Link to="/approvals">Approvals</Link>.
              </p>
            ) : null}
            {held ? <HeldNote /> : null}
            {mayUpdate && canApply && !running && !info.pending_approval_id ? (
              <Button onClick={() => void update()} disabled={busy}>
                {busy ? "Starting…" : info.approvals_required ? `Request update to ${info.latest.version}` : `Update to ${info.latest.version}`}
              </Button>
            ) : null}
          </div>
        ) : null}
        <ErrorNote error={error} />
      </section>
    </>
  );
}
