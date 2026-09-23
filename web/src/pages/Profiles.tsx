import { useEffect, useState } from "react";

import { api } from "../api/client";
import type { Group, Profile, Setting, SettingStatus } from "../api/types";
import { StatusDot } from "../components/StatusDot";
import { Button, Dialog, EmptyState, ErrorNote, Field, Spinner } from "../components/ui";
import { useList } from "../hooks/useList";
import { useSession } from "../session/SessionContext";
import { relative } from "./Devices";
import "./Profiles.css";

const ITEM_KIND = "profile";

const KINDS = [
  { value: "registry", label: "Registry value" },
  { value: "service", label: "Service" },
  { value: "local_group_members", label: "Local group members" },
  { value: "file", label: "File" },
  { value: "firewall_profile", label: "Firewall profile" },
  { value: "firewall_rule", label: "Firewall rule" },
  { value: "windows_update", label: "Windows Update" },
  { value: "bitlocker", label: "BitLocker" },
  { value: "defender", label: "Microsoft Defender" },
];

/** The Defender preferences a setting can name, with the words the server
 * accepts for each (internal/protocol/profile.go, DefenderPreferences). */
type DefenderChoice = {
  field: "cloud_protection" | "sample_submission" | "pua_protection" | "cloud_block_level";
  label: string;
  options: [string, string][];
};

const DEFENDER_CHOICES: DefenderChoice[] = [
  {
    field: "cloud_protection",
    label: "Cloud-delivered protection",
    options: [["off", "Off"], ["basic", "Basic"], ["advanced", "Advanced"]],
  },
  {
    field: "sample_submission",
    label: "Sample submission",
    options: [["prompt", "Always ask"], ["safe", "Safe samples"], ["never", "Never send"], ["all", "Send all samples"]],
  },
  {
    field: "pua_protection",
    label: "Potentially unwanted apps",
    options: [["off", "Off"], ["on", "Block"], ["audit", "Audit only"]],
  },
  {
    field: "cloud_block_level",
    label: "Cloud block level",
    options: [
      ["default", "Default"],
      ["moderate", "Moderate"],
      ["high", "High"],
      ["high_plus", "High+"],
      ["zero_tolerance", "Zero tolerance"],
    ],
  },
];

function blankSetting(kind: string): Setting {
  switch (kind) {
    case "service":
      return { kind, name: "", startup: "automatic", state: "running" };
    case "local_group_members":
      return { kind, group: "", members: [], mode: "additive" };
    case "file":
      return { kind, path: "", content_base64: "", ensure: "present" };
    case "firewall_profile":
      return { kind, profile: "public", state: "on" };
    case "firewall_rule":
      return { kind, name: "", direction: "inbound", action: "allow", protocol: "tcp", local_port: "", ensure: "present" };
    case "windows_update":
      return { kind, quality_deferral_days: 7 };
    case "bitlocker":
      return { kind, require_encryption: true, method: "XtsAes256", escrow_recovery_key: true };
    case "defender":
      return { kind, realtime_monitoring: true };
    default:
      return { kind: "registry", hive: "HKLM", key: "", name: "", type: "REG_SZ", data: "" };
  }
}

/** describe summarises a setting for the list, in the words of what it does. */
function describe(s: Setting): string {
  switch (s.kind) {
    case "registry":
      return s.ensure === "absent"
        ? `Remove ${s.hive}\\${s.key}\\${s.name}`
        : `${s.hive}\\${s.key}\\${s.name} = ${s.data} (${s.type})`;
    case "service":
      return [
        s.name,
        s.startup ? `starts ${s.startup}` : "",
        s.state ? `should be ${s.state}` : "",
      ]
        .filter(Boolean)
        .join(", ");
    case "local_group_members":
      return `${s.group}: ${s.mode === "exact" ? "exactly" : "at least"} ${(s.members ?? []).join(", ") || "nobody"}`;
    case "file":
      return s.ensure === "absent" ? `Remove ${s.path}` : `Write ${s.path}`;
    case "firewall_profile":
      return `Turn the ${s.profile} firewall ${s.state}`;
    case "firewall_rule":
      return s.ensure === "absent"
        ? `Remove the rule ${s.name}`
        : `${s.action === "block" ? "Block" : "Allow"} ${s.direction} ${s.protocol} ${s.local_port || "any port"}`;
    case "windows_update":
      return "Windows Update policy";
    case "bitlocker":
      return s.require_encryption ? "Require BitLocker on the system drive" : "BitLocker";
    case "defender":
      return "Microsoft Defender preferences";
    default:
      return s.kind;
  }
}

/** today is the local date as YYYY-MM-DD, what a pause starts from. */
export function today(now = new Date()): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`;
}

/** pauseEnds is when Windows lifts a pause that started on from: 35 days later. */
export function pauseEnds(from: string): string {
  const [y, m, d] = from.split("-").map(Number);
  const end = new Date(y, m - 1, d + 35);
  return today(end);
}

/** PauseField pauses one kind of update from a date, and says when it lapses. */
function PauseField({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string | undefined;
  onChange: (value: string | undefined) => void;
}) {
  const lapsed = value !== undefined && pauseEnds(value) < today();
  return (
    <Field
      label={label}
      hint={
        value
          ? lapsed
            ? `This pause ended on ${pauseEnds(value)}. Remove it, or pause again.`
            : `Paused until ${pauseEnds(value)}; Windows lifts a pause after 35 days on its own.`
          : "Stops these updates for 35 days, for when one is causing trouble."
      }
    >
      {value ? (
        <div className="inline-field">
          <input type="date" value={value} onChange={(e) => onChange(e.target.value || undefined)} />
          <Button variant="quiet" onClick={() => onChange(undefined)}>
            Remove pause
          </Button>
        </div>
      ) : (
        <Button variant="quiet" onClick={() => onChange(today())}>
          Pause from today
        </Button>
      )}
    </Field>
  );
}

/** SettingFields renders the fields the chosen kind needs, and nothing else. */
function SettingFields({
  setting,
  onChange,
}: {
  setting: Setting;
  onChange: (next: Setting) => void;
}) {
  const set = (patch: Partial<Setting>) => onChange({ ...setting, ...patch });

  if (setting.kind === "registry") {
    return (
      <>
        <Field
          label="Hive"
          hint={
            setting.hive === "HKCU"
              ? "The signed-in user's hive. A device with nobody signed in reports that and changes nothing."
              : undefined
          }
        >
          <select value={setting.hive ?? "HKLM"} onChange={(e) => set({ hive: e.target.value })}>
            <option value="HKLM">The machine (HKEY_LOCAL_MACHINE)</option>
            <option value="HKCU">The signed-in user (HKEY_CURRENT_USER)</option>
          </select>
        </Field>
        <Field label="Key" hint="Under the hive chosen above.">
          <input value={setting.key ?? ""} onChange={(e) => set({ key: e.target.value })} />
        </Field>
        <Field label="Value name">
          <input value={setting.name ?? ""} onChange={(e) => set({ name: e.target.value })} />
        </Field>
        <Field label="Should it exist?">
          <select value={setting.ensure || "present"} onChange={(e) => set({ ensure: e.target.value })}>
            <option value="present">Set this value</option>
            <option value="absent">Remove this value</option>
          </select>
        </Field>
        {setting.ensure !== "absent" ? (
          <>
            <Field label="Type">
              <select value={setting.type ?? "REG_SZ"} onChange={(e) => set({ type: e.target.value })}>
                {["REG_SZ", "REG_EXPAND_SZ", "REG_DWORD", "REG_QWORD", "REG_MULTI_SZ"].map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </Field>
            <Field
              label="Data"
              hint={setting.type === "REG_MULTI_SZ" ? "One string per line." : undefined}
            >
              <input value={setting.data ?? ""} onChange={(e) => set({ data: e.target.value })} />
            </Field>
          </>
        ) : null}
      </>
    );
  }

  if (setting.kind === "service") {
    return (
      <>
        <Field label="Service name">
          <input value={setting.name ?? ""} onChange={(e) => set({ name: e.target.value })} />
        </Field>
        <Field label="Startup type">
          <select value={setting.startup ?? ""} onChange={(e) => set({ startup: e.target.value })}>
            <option value="">Leave alone</option>
            <option value="automatic">Automatic</option>
            <option value="manual">Manual</option>
            <option value="disabled">Disabled</option>
          </select>
        </Field>
        <Field label="It should be">
          <select value={setting.state ?? ""} onChange={(e) => set({ state: e.target.value })}>
            <option value="">Leave alone</option>
            <option value="running">Running</option>
            <option value="stopped">Stopped</option>
          </select>
        </Field>
      </>
    );
  }

  if (setting.kind === "local_group_members") {
    return (
      <>
        <Field label="Group">
          <input value={setting.group ?? ""} onChange={(e) => set({ group: e.target.value })} />
        </Field>
        <Field label="Members" hint="One per line.">
          <textarea
            className="mono"
            rows={3}
            value={(setting.members ?? []).join("\n")}
            onChange={(e) =>
              set({ members: e.target.value.split("\n").map((m) => m.trim()).filter(Boolean) })
            }
          />
        </Field>
        <Field
          label="Mode"
          hint={
            setting.mode === "exact"
              ? "Anyone else is removed, except the built-in Administrator, which is never removed."
              : "Adds these members and leaves everyone else alone."
          }
        >
          <select value={setting.mode ?? "additive"} onChange={(e) => set({ mode: e.target.value })}>
            <option value="additive">At least these members</option>
            <option value="exact">Exactly these members</option>
          </select>
        </Field>
      </>
    );
  }

  if (setting.kind === "firewall_profile") {
    return (
      <>
        <Field label="Firewall profile">
          <select value={setting.profile ?? "public"} onChange={(e) => set({ profile: e.target.value })}>
            <option value="domain">Domain</option>
            <option value="private">Private</option>
            <option value="public">Public</option>
          </select>
        </Field>
        <Field label="It should be">
          <select value={setting.state ?? "on"} onChange={(e) => set({ state: e.target.value })}>
            <option value="on">On</option>
            <option value="off">Off</option>
          </select>
        </Field>
      </>
    );
  }

  if (setting.kind === "firewall_rule") {
    return (
      <>
        <Field label="Rule name" hint="Rules Retune creates are tagged, so they can be found and removed later.">
          <input value={setting.name ?? ""} onChange={(e) => set({ name: e.target.value })} />
        </Field>
        <Field label="Should it exist?">
          <select value={setting.ensure || "present"} onChange={(e) => set({ ensure: e.target.value })}>
            <option value="present">Create this rule</option>
            <option value="absent">Remove this rule</option>
          </select>
        </Field>
        {setting.ensure !== "absent" ? (
          <>
            <Field label="Direction">
              <select value={setting.direction ?? "inbound"} onChange={(e) => set({ direction: e.target.value })}>
                <option value="inbound">Inbound</option>
                <option value="outbound">Outbound</option>
              </select>
            </Field>
            <Field label="Action">
              <select value={setting.action ?? "allow"} onChange={(e) => set({ action: e.target.value })}>
                <option value="allow">Allow</option>
                <option value="block">Block</option>
              </select>
            </Field>
            <Field label="Protocol">
              <select value={setting.protocol ?? "tcp"} onChange={(e) => set({ protocol: e.target.value })}>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="any">Any</option>
              </select>
            </Field>
            {setting.protocol !== "any" ? (
              <Field label="Port" hint="A port, or a range such as 5000-5010. Leave empty for any.">
                <input value={setting.local_port ?? ""} onChange={(e) => set({ local_port: e.target.value })} />
              </Field>
            ) : null}
            <Field label="Program" hint="Optional path the rule applies to.">
              <input value={setting.program ?? ""} onChange={(e) => set({ program: e.target.value })} />
            </Field>
          </>
        ) : null}
      </>
    );
  }

  if (setting.kind === "windows_update") {
    return (
      <>
        <Field label="Hold quality updates for (days)" hint="Leave empty to leave this alone.">
          <input
            type="number"
            min={0}
            max={30}
            value={setting.quality_deferral_days ?? ""}
            onChange={(e) => set({ quality_deferral_days: numberOrUndefined(e.target.value) })}
          />
        </Field>
        <Field label="Hold feature updates for (days)">
          <input
            type="number"
            min={0}
            max={365}
            value={setting.feature_deferral_days ?? ""}
            onChange={(e) => set({ feature_deferral_days: numberOrUndefined(e.target.value) })}
          />
        </Field>
        <Field label="Active hours start">
          <input
            type="number"
            min={0}
            max={23}
            value={setting.active_hours_start ?? ""}
            onChange={(e) => set({ active_hours_start: numberOrUndefined(e.target.value) })}
          />
        </Field>
        <Field label="Active hours end">
          <input
            type="number"
            min={0}
            max={23}
            value={setting.active_hours_end ?? ""}
            onChange={(e) => set({ active_hours_end: numberOrUndefined(e.target.value) })}
          />
        </Field>
        <Field label="Restart while someone is signed in">
          <select
            value={setting.auto_restart === undefined ? "" : String(setting.auto_restart)}
            onChange={(e) =>
              set({ auto_restart: e.target.value === "" ? undefined : e.target.value === "true" })
            }
          >
            <option value="">Leave alone</option>
            <option value="false">Never</option>
            <option value="true">Allowed</option>
          </select>
        </Field>

        <h4 className="settings__subhead">Deadlines</h4>
        <Field
          label="Install quality updates within (days)"
          hint="Once an update is offered, it installs — and the machine restarts — by this many days, whatever the user does. Empty leaves it alone."
        >
          <input
            type="number"
            min={0}
            max={30}
            value={setting.quality_deadline_days ?? ""}
            onChange={(e) => set({ quality_deadline_days: numberOrUndefined(e.target.value) })}
          />
        </Field>
        <Field label="Install feature updates within (days)">
          <input
            type="number"
            min={0}
            max={30}
            value={setting.feature_deadline_days ?? ""}
            onChange={(e) => set({ feature_deadline_days: numberOrUndefined(e.target.value) })}
          />
        </Field>
        {setting.quality_deadline_days !== undefined || setting.feature_deadline_days !== undefined ? (
          <Field
            label="Grace period (days)"
            hint="Extra days for a machine that was off when the deadline passed, so it isn't restarted the moment it comes back."
          >
            <input
              type="number"
              min={0}
              max={7}
              value={setting.deadline_grace_days ?? ""}
              onChange={(e) => set({ deadline_grace_days: numberOrUndefined(e.target.value) })}
            />
          </Field>
        ) : null}

        <h4 className="settings__subhead">Pause</h4>
        <PauseField
          label="Pause quality updates"
          value={setting.pause_quality_from}
          onChange={(v) => set({ pause_quality_from: v })}
        />
        <PauseField
          label="Pause feature updates"
          value={setting.pause_feature_from}
          onChange={(v) => set({ pause_feature_from: v })}
        />

        <h4 className="settings__subhead">Feature release</h4>
        <Field
          label="Stay on"
          hint="Holds machines on one Windows release — they still get its monthly updates — until you choose another. Empty leaves it alone."
        >
          <div className="inline-field">
            <select
              aria-label="Target product"
              value={setting.target_product ?? ""}
              onChange={(e) =>
                set(
                  e.target.value === ""
                    ? { target_product: undefined, target_version: undefined }
                    : { target_product: e.target.value },
                )
              }
            >
              <option value="">Leave alone</option>
              <option value="Windows 11">Windows 11</option>
              <option value="Windows 10">Windows 10</option>
            </select>
            {setting.target_product ? (
              <input
                aria-label="Target version"
                className="mono"
                placeholder="24H2"
                value={setting.target_version ?? ""}
                onChange={(e) => set({ target_version: e.target.value.trim().toUpperCase() || undefined })}
              />
            ) : null}
          </div>
        </Field>
      </>
    );
  }

  if (setting.kind === "defender") {
    return (
      <>
        <p className="hint">
          Only what you choose is enforced; everything left alone stays as it is on each machine. Where
          Tamper Protection is on, Defender refuses these changes and the device says so.
        </p>
        <Field label="Real-time protection">
          <select
            value={setting.realtime_monitoring === undefined ? "" : String(setting.realtime_monitoring)}
            onChange={(e) =>
              set({ realtime_monitoring: e.target.value === "" ? undefined : e.target.value === "true" })
            }
          >
            <option value="">Leave alone</option>
            <option value="true">On</option>
            <option value="false">Off</option>
          </select>
        </Field>
        {DEFENDER_CHOICES.map((c) => (
          <Field key={c.field} label={c.label}>
            <select value={setting[c.field] ?? ""} onChange={(e) => set({ [c.field]: e.target.value || undefined })}>
              <option value="">Leave alone</option>
              {c.options.map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </Field>
        ))}
      </>
    );
  }

  if (setting.kind === "bitlocker") {
    return (
      <>
        <Field
          label="The system drive"
          hint="Retune never decrypts a drive, and never re-encrypts one already encrypted another way."
        >
          <select
            value={setting.require_encryption ? "required" : "ignored"}
            onChange={(e) => set({ require_encryption: e.target.value === "required" })}
          >
            <option value="required">Must be encrypted</option>
            <option value="ignored">Leave alone</option>
          </select>
        </Field>
        {setting.require_encryption ? (
          <>
            <Field label="Encryption method">
              <select value={setting.method ?? "XtsAes256"} onChange={(e) => set({ method: e.target.value })}>
                <option value="XtsAes256">XTS-AES 256</option>
                <option value="XtsAes128">XTS-AES 128</option>
              </select>
            </Field>
            <Field
              label="Recovery key"
              hint="Escrowed keys are stored encrypted, and every time one is revealed it is recorded."
            >
              <select
                value={setting.escrow_recovery_key ? "escrow" : "no"}
                onChange={(e) => set({ escrow_recovery_key: e.target.value === "escrow" })}
              >
                <option value="escrow">Send it to the server</option>
                <option value="no">Leave it on the device</option>
              </select>
            </Field>
          </>
        ) : null}
      </>
    );
  }

  return (
    <>
      <Field label="Path">
        <input value={setting.path ?? ""} onChange={(e) => set({ path: e.target.value })} />
      </Field>
      <Field label="Should it exist?">
        <select value={setting.ensure || "present"} onChange={(e) => set({ ensure: e.target.value })}>
          <option value="present">Write this file</option>
          <option value="absent">Remove this file</option>
        </select>
      </Field>
      {setting.ensure !== "absent" ? (
        <Field label="Contents">
          <textarea
            className="mono"
            rows={4}
            value={decodeContent(setting.content_base64 ?? "")}
            onChange={(e) => set({ content_base64: encodeContent(e.target.value) })}
          />
        </Field>
      ) : null}
    </>
  );
}

function numberOrUndefined(value: string): number | undefined {
  return value === "" ? undefined : Number(value);
}

function encodeContent(text: string): string {
  return btoa(String.fromCharCode(...new TextEncoder().encode(text)));
}

function decodeContent(encoded: string): string {
  try {
    return new TextDecoder().decode(Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0)));
  } catch {
    return "";
  }
}

function ProfileEditor({
  profile,
  open,
  onClose,
  onSaved,
}: {
  profile: Profile | null;
  open: boolean;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [settings, setSettings] = useState<Setting[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    setName(profile?.name ?? "");
    setDescription(profile?.description ?? "");
    setSettings(profile?.settings ?? []);
    setError(null);
  }, [open, profile]);

  async function save() {
    setBusy(true);
    setError(null);
    try {
      const payload = { name, description, settings };
      if (profile) {
        await api.post(`/profiles/${profile.id}`, payload);
      } else {
        await api.post("/profiles", payload);
      }
      onSaved();
      onClose();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  function update(index: number, next: Setting) {
    setSettings(settings.map((s, i) => (i === index ? next : s)));
  }

  return (
    <Dialog title={profile ? `Edit ${profile.name}` : "New profile"} open={open} onClose={onClose}>
      <Field label="Name">
        <input value={name} onChange={(e) => setName(e.target.value)} />
      </Field>
      <Field label="Description">
        <input value={description} onChange={(e) => setDescription(e.target.value)} />
      </Field>

      {settings.map((setting, index) => (
        <fieldset key={index} className="setting">
          <legend>
            <select
              value={setting.kind}
              onChange={(e) => update(index, blankSetting(e.target.value))}
              aria-label={`Setting ${index + 1} kind`}
            >
              {KINDS.map((k) => (
                <option key={k.value} value={k.value}>
                  {k.label}
                </option>
              ))}
            </select>
            <Button
              variant="quiet"
              onClick={() => setSettings(settings.filter((_, i) => i !== index))}
            >
              Remove
            </Button>
          </legend>
          <SettingFields setting={setting} onChange={(next) => update(index, next)} />
        </fieldset>
      ))}

      <div className="actions">
        <Button variant="quiet" onClick={() => setSettings([...settings, blankSetting("registry")])}>
          Add a setting
        </Button>
      </div>

      <ErrorNote error={error} />
      <div className="actions">
        <Button onClick={() => void save()} disabled={busy || name.trim() === "" || settings.length === 0}>
          {profile ? "Save new version" : "Create profile"}
        </Button>
        <Button variant="quiet" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </Dialog>
  );
}

function AssignDialog({
  profile,
  open,
  onClose,
  onAssigned,
}: {
  profile: Profile | null;
  open: boolean;
  onClose: () => void;
  onAssigned: () => void;
}) {
  const [groups, setGroups] = useState<Group[]>([]);
  const [groupID, setGroupID] = useState("");
  const [mode, setMode] = useState("include");
  const [revert, setRevert] = useState(false);
  const [error, setError] = useState<unknown>(null);

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
    if (!profile) return;
    setError(null);
    try {
      await api.post("/assignments", {
        item_kind: ITEM_KIND,
        item_id: profile.id,
        group_id: groupID,
        mode,
        options: mode === "include" ? { revert_on_removal: revert } : undefined,
      });
      onAssigned();
      onClose();
    } catch (err) {
      setError(err);
    }
  }

  return (
    <Dialog title={`Assign ${profile?.name ?? ""}`} open={open} onClose={onClose}>
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
          label="When it stops applying"
          hint="Restores what was there before this profile first changed it."
        >
          <select value={revert ? "revert" : "leave"} onChange={(e) => setRevert(e.target.value === "revert")}>
            <option value="leave">Leave the settings as they are</option>
            <option value="revert">Put the previous values back</option>
          </select>
        </Field>
      ) : null}
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

/** ProfileDetail answers the question an administrator actually has: which
 * setting is failing, and where. */
function ProfileDetail({ profile }: { profile: Profile }) {
  const [rollup, setRollup] = useState<Record<string, number>>({});
  const { items, loading, error } = useList<SettingStatus>(`/profiles/${profile.id}/settings`);

  useEffect(() => {
    api
      .get<{ rollup: Record<string, number> }>(`/profiles/${profile.id}/settings`)
      .then((resp) => setRollup(resp.rollup))
      .catch(() => setRollup({}));
  }, [profile.id]);

  const counts = Object.entries(rollup);
  return (
    <section className="profile__detail">
      <h2>{profile.name}</h2>
      {counts.length > 0 ? (
        <p className="profile__rollup">
          {counts.map(([status, count]) => (
            <span key={status}>
              <StatusDot status={status} /> {count}
            </span>
          ))}
        </p>
      ) : (
        <p className="profile__none">No device has reported on this profile yet.</p>
      )}

      <ErrorNote error={error} />
      {loading ? <Spinner /> : null}
      {items.length > 0 ? (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Device</th>
                <th>Setting</th>
                <th>Status</th>
                <th>Detail</th>
                <th>When</th>
              </tr>
            </thead>
            <tbody>
              {items.map((row) => (
                <tr key={row.device_id + row.identity}>
                  <td>{row.hostname}</td>
                  <td className="mono">{row.identity}</td>
                  <td>
                    <StatusDot status={row.status} />
                  </td>
                  <td>{row.detail}</td>
                  <td>{relative(row.updated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  );
}

export default function Profiles() {
  const { canWrite } = useSession();
  const { items, total, loading, error, offset, setOffset, reload } = useList<Profile>("/profiles");
  const [editing, setEditing] = useState<Profile | null>(null);
  const [editorOpen, setEditorOpen] = useState(false);
  const [assigning, setAssigning] = useState<Profile | null>(null);
  const [selected, setSelected] = useState<Profile | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);

  async function openEditor(profile: Profile | null) {
    setActionError(null);
    if (profile) {
      try {
        // The listing omits the settings; the editor needs them.
        setEditing(await api.get<Profile>(`/profiles/${profile.id}`));
      } catch (err) {
        setActionError(err);
        return;
      }
    } else {
      setEditing(null);
    }
    setEditorOpen(true);
  }

  async function remove(profile: Profile) {
    if (!window.confirm(`Delete ${profile.name}? Its assignments go with it.`)) return;
    try {
      await api.del(`/profiles/${profile.id}`);
      if (selected?.id === profile.id) setSelected(null);
      reload();
    } catch (err) {
      setActionError(err);
    }
  }

  return (
    <>
      <div className="content__head">
        <h1>Profiles</h1>
        {canWrite ? <Button onClick={() => void openEditor(null)}>New profile</Button> : null}
      </div>

      <ErrorNote error={error} />
      <ErrorNote error={actionError} />
      {loading ? <Spinner /> : null}

      {!loading && items.length === 0 ? (
        <EmptyState title="No profiles yet.">
          <p>A profile states how a machine should be, and the agent keeps it that way.</p>
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
              {items.map((profile) => (
                <tr key={profile.id}>
                  <td>
                    <button className="linklike" onClick={() => setSelected(profile)}>
                      {profile.name}
                    </button>
                    {profile.description ? (
                      <div className="profile__description">{profile.description}</div>
                    ) : null}
                  </td>
                  <td className="numeric">{profile.current_version}</td>
                  <td>{relative(profile.updated_at)}</td>
                  <td className="profile__actions">
                    {canWrite ? (
                      <>
                        <Button variant="quiet" onClick={() => void openEditor(profile)}>
                          Edit
                        </Button>
                        <Button variant="quiet" onClick={() => setAssigning(profile)}>
                          Assign
                        </Button>
                        <Button variant="quiet" onClick={() => void remove(profile)}>
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

      {selected ? <ProfileDetail profile={selected} /> : null}

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

      <ProfileEditor profile={editing} open={editorOpen} onClose={() => setEditorOpen(false)} onSaved={reload} />
      <AssignDialog
        profile={assigning}
        open={assigning !== null}
        onClose={() => setAssigning(null)}
        onAssigned={reload}
      />
    </>
  );
}

export { describe as describeSetting };
