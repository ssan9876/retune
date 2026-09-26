import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { api } from "../api/client";
import type { AgentRollout, AgentRolloutResponse, Group, Release, ReleasesResponse } from "../api/types";
import { Button, ErrorNote, Field } from "../components/ui";
import { relative } from "./Devices";

const STATE_LABELS: Record<AgentRollout["state"], string> = {
  pilot: "Piloting",
  promoting: "Waiting for approval",
  promoted: "On every device",
  halted: "Halted",
  superseded: "Replaced",
};

function when(value?: string): string {
  return value ? new Date(value).toLocaleString() : "";
}

/** ReleasesPanel shows what the server's release feed has found. Every
 * release listed has had its signed manifest verified; its Windows agent is
 * imported as a build, ready to assign or roll out. */
export function ReleasesPanel({ canWrite, onImported }: { canWrite: boolean; onImported: () => void }) {
  const [data, setData] = useState<ReleasesResponse | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api
      .get<ReleasesResponse>("/releases")
      .then(setData)
      .catch((err: unknown) => setError(err));
  }, []);
  useEffect(load, [load]);

  async function checkNow() {
    setBusy(true);
    setError(null);
    try {
      setData(await api.post<ReleasesResponse>("/releases/check"));
      onImported();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  const feed = data?.feed;
  const releases: Release[] = data?.items ?? [];
  return (
    <section className="agent-updates" aria-label="Releases">
      <div className="agent-updates__head">
        <h2>Releases</h2>
        {canWrite && feed?.enabled ? (
          <Button variant="quiet" onClick={() => void checkNow()} disabled={busy}>
            {busy ? "Checking…" : "Check now"}
          </Button>
        ) : null}
      </div>
      {feed ? (
        feed.enabled ? (
          <p className="agent-updates__meta">
            Looks for new releases every {feed.interval_hours} hours
            {feed.prereleases ? ", release candidates included" : ""}. Last checked {relative(feed.checked_at)}.
          </p>
        ) : (
          <p className="agent-updates__meta">
            This server does not look for releases. Upload builds by hand, or set RELEASE_FEED_ENABLED.
          </p>
        )
      ) : null}
      {feed?.error ? <p className="agent-updates__error">The last check failed: {feed.error}</p> : null}
      <ErrorNote error={error} />
      {releases.length > 0 ? (
        <ul className="agent-updates__releases">
          {releases.slice(0, 5).map((r) => (
            <li key={r.version}>
              <span className="mono">{r.version}</span>
              {r.prerelease ? <span className="agent-updates__tag">prerelease</span> : null}
              <span className="agent-updates__meta"> published {relative(r.published_at)}</span>
              {r.agent_version_id ? (
                <span className="agent-updates__ok"> · agent imported</span>
              ) : r.import_error ? (
                <span className="agent-updates__error"> · agent not imported: {r.import_error}</span>
              ) : null}
              {r.notes ? (
                <details>
                  <summary>Release notes</summary>
                  <pre className="agent-updates__notes">{r.notes}</pre>
                </details>
              ) : null}
            </li>
          ))}
        </ul>
      ) : feed?.enabled ? (
        <p className="agent-updates__meta">No release found yet.</p>
      ) : null}
    </section>
  );
}

/** AutoRolloutPanel is the staged rollout of imported agent builds: the pilot
 * group first, everyone after the delay if no pilot device rolled back. */
export function AutoRolloutPanel({ canWrite }: { canWrite: boolean }) {
  const [data, setData] = useState<AgentRolloutResponse | null>(null);
  const [groups, setGroups] = useState<Group[]>([]);
  const [editing, setEditing] = useState(false);
  const [enabled, setEnabled] = useState(false);
  const [pilot, setPilot] = useState("");
  const [delay, setDelay] = useState(24);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api
      .get<AgentRolloutResponse>("/agent-rollout")
      .then(setData)
      .catch((err: unknown) => setError(err));
  }, []);
  useEffect(load, [load]);

  function startEditing() {
    const p = data?.policy;
    setEnabled(p?.enabled ?? false);
    setPilot(p?.pilot_group_id ?? "");
    setDelay(p?.delay_hours || 24);
    setError(null);
    setEditing(true);
    api
      .get<{ items: Group[] }>("/groups")
      .then((resp) => setGroups(resp.items.filter((g) => g.kind !== "builtin")))
      .catch((err: unknown) => setError(err));
  }

  async function save() {
    setBusy(true);
    setError(null);
    try {
      setData(
        await api.post<AgentRolloutResponse>("/agent-rollout/policy", {
          enabled,
          pilot_group_id: pilot || undefined,
          delay_hours: delay,
        }),
      );
      setEditing(false);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  async function resume(r: AgentRollout) {
    setError(null);
    try {
      setData(await api.post<AgentRolloutResponse>(`/agent-rollouts/${r.id}/resume`));
    } catch (err) {
      setError(err);
    }
  }

  const policy = data?.policy;
  const rollouts = (data?.rollouts ?? []).filter((r) => r.state !== "superseded").slice(0, 5);
  return (
    <section className="agent-updates" aria-label="Automatic rollout">
      <div className="agent-updates__head">
        <h2>Automatic rollout</h2>
        {canWrite && !editing ? (
          <Button variant="quiet" onClick={startEditing}>
            Change
          </Button>
        ) : null}
      </div>
      {policy && !editing ? (
        <p className="agent-updates__meta">
          {policy.enabled
            ? `On: each new release's agent goes to ${policy.pilot_group_name || "the pilot group"} first, and to every device ${policy.delay_hours} hours later if no pilot device rolled back.`
            : "Off: imported builds wait here for you to assign them."}
        </p>
      ) : null}

      {editing ? (
        <div className="agent-updates__form">
          <label className="agent-updates__check">
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Roll out new
            releases automatically
          </label>
          <Field label="Pilot group" hint="A few machines that get each release first.">
            <select value={pilot} onChange={(e) => setPilot(e.target.value)}>
              <option value="">Choose a group</option>
              {groups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Hours before everyone gets it" hint="1 to 720. Maintenance windows still hold updates back.">
            <input type="number" min={1} max={720} value={delay} onChange={(e) => setDelay(Number(e.target.value))} />
          </Field>
          <div className="actions">
            <Button onClick={() => void save()} disabled={busy || (enabled && pilot === "")}>
              Save
            </Button>
            <Button variant="quiet" onClick={() => setEditing(false)}>
              Cancel
            </Button>
          </div>
        </div>
      ) : null}
      <ErrorNote error={error} />

      {rollouts.length > 0 ? (
        <table className="agent-updates__rollouts">
          <thead>
            <tr>
              <th>Build</th>
              <th>State</th>
              <th>Detail</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rollouts.map((r) => (
              <tr key={r.id} className={`agent-updates__rollout--${r.state}`}>
                <td className="mono">{r.version}</td>
                <td>{STATE_LABELS[r.state] ?? r.state}</td>
                <td>
                  {r.detail}
                  {r.state === "pilot" && r.promote_after && !r.detail ? `Everyone after ${when(r.promote_after)}` : ""}
                  {r.state === "promoted" && r.promoted_at ? `Since ${when(r.promoted_at)}` : ""}
                  {r.approval_id ? (
                    <>
                      {" "}
                      <Link to="/approvals">Review it under Approvals</Link>
                    </>
                  ) : null}
                </td>
                <td>
                  {canWrite && r.state === "halted" ? (
                    <Button variant="quiet" onClick={() => void resume(r)}>
                      Resume
                    </Button>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </section>
  );
}
