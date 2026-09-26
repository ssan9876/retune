import { useEffect, useRef, useState } from "react";

import { heldForApproval } from "../api/approvals";
import { api } from "../api/client";
import type { AgentVersion, Group } from "../api/types";
import { AssignedTo, RolloutFields, rolloutBody } from "../components/Assignments";
import type { Rollout } from "../components/Assignments";
import { StatusDot } from "../components/StatusDot";
import { Button, Dialog, EmptyState, ErrorNote, Field, HeldNote, Spinner } from "../components/ui";
import { useList } from "../hooks/useList";
import { useSession } from "../session/SessionContext";
import { AutoRolloutPanel, ReleasesPanel } from "./AgentUpdates";
import { relative } from "./Devices";
import "./AgentVersions.css";

const ITEM_KIND = "agent";
const DEFAULT_DEADLINE_SECONDS = 600;

interface Rollup {
  rollup: Record<string, number>;
}

/** formatSize renders a byte count the way a person reads a file size. */
function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(1)} ${units[unit]}`;
}

/** PLATFORMS are the builds a version can have, and how they are named. */
export const PLATFORMS: { value: string; label: string }[] = [
  { value: "windows-amd64", label: "Windows (x64)" },
  { value: "darwin-universal", label: "macOS (Apple silicon and Intel)" },
  { value: "darwin-arm64", label: "macOS (Apple silicon)" },
  { value: "darwin-amd64", label: "macOS (Intel)" },
  { value: "linux-amd64", label: "Linux (x64)" },
  { value: "linux-arm64", label: "Linux (ARM64)" },
];

function platformLabel(platform: string): string {
  return PLATFORMS.find((p) => p.value === platform)?.label ?? platform;
}

/** platformFromFilename guesses a build's platform from the name a release
 * gives it -- retune-agent-darwin-universal, retune-agent-linux-arm64 -- and
 * a .exe is Windows. "" when the name says nothing. */
export function platformFromFilename(name: string): string {
  const lower = name.toLowerCase();
  if (lower.endsWith(".exe")) return "windows-amd64";
  const known = PLATFORMS.map((p) => p.value).find((p) => lower.includes(p));
  return known ?? "";
}

/** versionFromFilename guesses a version from a build's file name, so the
 * uploader rarely has to type one out by hand. */
function versionFromFilename(name: string): string {
  const match = /(\d+\.\d+\.\d+(?:\.\d+)?)/.exec(name);
  return match ? match[1] : "";
}

/** UploadDialog sends a build's bytes as a raw body, not JSON, because
 * base64 would inflate a multi-megabyte binary by a third for nothing. */
function UploadDialog({ open, onClose, onUploaded }: { open: boolean; onClose: () => void; onUploaded: () => void }) {
  const [version, setVersion] = useState("");
  const [platform, setPlatform] = useState("windows-amd64");
  const [notes, setNotes] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [sig, setSig] = useState<File | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const sigInput = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!open) return;
    setVersion("");
    setPlatform("windows-amd64");
    setNotes("");
    setFile(null);
    setSig(null);
    setError(null);
    if (fileInput.current) fileInput.current.value = "";
    if (sigInput.current) sigInput.current.value = "";
  }, [open]);

  function pickFile(picked: File | null) {
    setFile(picked);
    const guessedPlatform = picked ? platformFromFilename(picked.name) : "";
    if (guessedPlatform) setPlatform(guessedPlatform);
    if (picked && version.trim() === "") {
      const guessed = versionFromFilename(picked.name);
      if (guessed) setVersion(guessed);
    }
  }

  async function upload() {
    if (!file || !sig) return;
    setBusy(true);
    setError(null);
    try {
      const sigText = await sig.text();
      const params = new URLSearchParams({ version: version.trim(), platform, notes });
      await api.postBinary(`/agent-versions?${params.toString()}`, file, {
        "X-Retune-Signature": btoa(sigText),
      });
      onUploaded();
      onClose();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog title="Upload a build" open={open} onClose={onClose}>
      <p className="agent-versions__notice">
        Uploading a build only makes it available to assign. Nothing changes on a device until you assign it to a
        group. Builds must be signed with the release key; the server refuses anything else. Upload each
        platform's build under the same version: every device is handed the one it can run.
      </p>
      <Field label="Build file">
        <input
          ref={fileInput}
          type="file"
          onChange={(e) => pickFile(e.target.files?.[0] ?? null)}
        />
      </Field>
      <Field label="Signature file" hint="The .sig written by retune-sign beside the build.">
        <input
          ref={sigInput}
          type="file"
          accept=".sig"
          onChange={(e) => setSig(e.target.files?.[0] ?? null)}
        />
      </Field>
      <Field label="Platform" hint="Filled in from the file name when it says; a .exe is Windows.">
        <select value={platform} onChange={(e) => setPlatform(e.target.value)}>
          {PLATFORMS.map((p) => (
            <option key={p.value} value={p.value}>
              {p.label}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Version" hint="Filled in from the file name when it carries one; check it before uploading.">
        <input className="mono" value={version} onChange={(e) => setVersion(e.target.value)} />
      </Field>
      <Field label="Notes">
        <input value={notes} onChange={(e) => setNotes(e.target.value)} />
      </Field>
      <ErrorNote error={error} />
      <div className="actions">
        <Button onClick={() => void upload()} disabled={busy || !file || !sig || version.trim() === ""}>
          Upload
        </Button>
        <Button variant="quiet" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </Dialog>
  );
}

/** AssignDialog gives a build to a group. Every device in that group is
 * updated to run it. */
function AssignDialog({
  build,
  open,
  onClose,
  onAssigned,
}: {
  build: AgentVersion | null;
  open: boolean;
  onClose: () => void;
  onAssigned: () => void;
}) {
  const [groups, setGroups] = useState<Group[]>([]);
  const [groupID, setGroupID] = useState("");
  const [mode, setMode] = useState("include");
  const [rollout, setRollout] = useState<Rollout | null>(null);
  const [deadlineSeconds, setDeadlineSeconds] = useState(DEFAULT_DEADLINE_SECONDS);
  const [error, setError] = useState<unknown>(null);
  const [held, setHeld] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (open) setHeld(false);
    if (!open) return;
    setMode("include");
    setDeadlineSeconds(DEFAULT_DEADLINE_SECONDS);
    api
      .get<{ items: Group[] }>("/groups")
      .then((resp) => {
        setGroups(resp.items);
        setGroupID((current) => current || (resp.items[0]?.id ?? ""));
      })
      .catch((err: unknown) => setError(err));
  }, [open]);

  async function assign() {
    if (!build) return;
    setBusy(true);
    setError(null);
    try {
      const res = await api.post("/assignments", {
        item_kind: ITEM_KIND,
        item_id: build.id,
        group_id: groupID,
        mode,
        options: mode === "include" ? { deadline_seconds: deadlineSeconds } : undefined,
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
    <Dialog title={`Assign ${build?.version ?? ""}`} open={open} onClose={onClose}>
      <p className="agent-versions__notice">
        Assigning this build replaces the agent on every device in the group. A device that cannot check in
        afterwards goes back to what it was running by itself.
      </p>
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
        <Field
          label="Rollback deadline in seconds"
          hint="If the new agent has not checked in by then, the previous build is put back. 60 to 3600 seconds."
        >
          <input
            type="number"
            min={60}
            max={3600}
            value={deadlineSeconds}
            onChange={(e) => setDeadlineSeconds(Number(e.target.value))}
          />
        </Field>
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

/** AgentVersionDetail shows how a build's rollout is faring, so a pilot
 * group can report back before a wider one is assigned. */
function AgentVersionDetail({ build }: { build: AgentVersion }) {
  const [rollup, setRollup] = useState<Record<string, number>>({});

  useEffect(() => {
    api
      .get<Rollup>(`/items/${ITEM_KIND}/${build.id}/status`)
      .then((resp) => setRollup(resp.rollup))
      .catch(() => setRollup({}));
  }, [build.id]);

  const counts = Object.entries(rollup);
  return (
    <section className="agent-versions__detail">
      <h2>{build.version}</h2>
      <AssignedTo kind={ITEM_KIND} id={build.id} />
      {(build.builds ?? []).length > 0 ? (
        <ul className="agent-versions__builds">
          {(build.builds ?? []).map((b) => (
            <li key={b.platform}>
              <strong>{platformLabel(b.platform)}</strong> <span className="mono">{formatSize(b.size_bytes)}</span>
              <div className="agent-versions__sha mono">{b.sha256}</div>
            </li>
          ))}
        </ul>
      ) : (
        <p className="agent-versions__sha mono">{build.sha256}</p>
      )}
      {build.notes ? <p>{build.notes}</p> : null}
      {counts.length > 0 ? (
        <p className="agent-versions__rollup">
          {counts.map(([status, count]) => (
            <span key={status}>
              <StatusDot status={status} /> {count}
            </span>
          ))}
        </p>
      ) : (
        <p className="agent-versions__none">No device has reported on this build yet.</p>
      )}
    </section>
  );
}

export default function AgentVersions() {
  const { canWrite } = useSession();
  const { items, total, loading, error, offset, setOffset, reload } = useList<AgentVersion>("/agent-versions");
  const [uploadOpen, setUploadOpen] = useState(false);
  const [assigning, setAssigning] = useState<AgentVersion | null>(null);
  const [selected, setSelected] = useState<AgentVersion | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);

  async function remove(build: AgentVersion) {
    if (!window.confirm(`Delete build ${build.version}? Its assignments go with it.`)) {
      return;
    }
    try {
      await api.del(`/agent-versions/${build.id}`);
      if (selected?.id === build.id) setSelected(null);
      reload();
    } catch (err) {
      setActionError(err);
    }
  }

  return (
    <>
      <div className="content__head">
        <h1>Agent versions</h1>
        {canWrite ? <Button onClick={() => setUploadOpen(true)}>Upload build</Button> : null}
      </div>

      <div className="agent-updates__panels">
        <ReleasesPanel canWrite={canWrite} onImported={reload} />
        <AutoRolloutPanel canWrite={canWrite} />
      </div>

      <ErrorNote error={error} />
      <ErrorNote error={actionError} />
      {loading ? <Spinner /> : null}

      {!loading && items.length === 0 ? (
        <EmptyState title="No builds yet.">
          <p>
            New releases appear here by themselves when this server watches for them. Or upload a build, then
            assign it to a group. Assigning replaces the agent on every device in that group; a device that cannot
            check in afterwards goes back to its previous build by itself.
          </p>
        </EmptyState>
      ) : null}

      {items.length > 0 ? (
        <div className="table-scroll">
          <table className="agent-versions-table">
            <thead>
              <tr>
                <th>Version</th>
                <th>Platforms</th>
                <th>Key</th>
                <th>Source</th>
                <th>Uploaded by</th>
                <th>Uploaded</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {items.map((build) => (
                <tr key={build.id}>
                  <td>
                    <button className="linklike" onClick={() => setSelected(build)}>
                      {build.version}
                    </button>
                    {build.notes ? <div className="agent-versions__notes">{build.notes}</div> : null}
                  </td>
                  <td>
                    {(build.builds ?? []).length > 0
                      ? (build.builds ?? []).map((b) => (
                          <span key={b.platform} className="agent-versions__platform" title={formatSize(b.size_bytes)}>
                            {platformLabel(b.platform)}
                          </span>
                        ))
                      : formatSize(build.size_bytes)}
                  </td>
                  <td>
                    <span className="mono">{build.key_id}</span>
                  </td>
                  <td>{build.source === "release_feed" ? "Release" : "Upload"}</td>
                  <td>{build.created_by}</td>
                  <td>{relative(build.created_at)}</td>
                  <td className="agent-versions__actions">
                    {canWrite ? (
                      <>
                        <Button variant="quiet" onClick={() => setAssigning(build)}>
                          Assign
                        </Button>
                        <Button variant="quiet" onClick={() => void remove(build)}>
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

      {selected ? <AgentVersionDetail build={selected} /> : null}

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

      <UploadDialog open={uploadOpen} onClose={() => setUploadOpen(false)} onUploaded={reload} />
      <AssignDialog
        build={assigning}
        open={assigning !== null}
        onClose={() => setAssigning(null)}
        onAssigned={reload}
      />
    </>
  );
}
