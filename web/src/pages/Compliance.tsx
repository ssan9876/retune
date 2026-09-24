import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { api } from "../api/client";
import type { CompliancePolicy, ComplianceRule, Group, ListResponse, PolicyDeviceCompliance, Profile } from "../api/types";
import { StatusDot } from "../components/StatusDot";
import { Button, Dialog, EmptyState, ErrorNote, Field, Spinner } from "../components/ui";
import { useList } from "../hooks/useList";
import { useSession } from "../session/SessionContext";
import { relative } from "./Devices";
import "./Compliance.css";

const ITEM_KIND = "compliance";

// Digits, optionally dotted - matches the server's dottedNumeric exactly
// (internal/server/compliance/rules.go), so a value the editor accepts is
// never rejected by ParseRules.
const DOTTED = /^\d+(\.\d+)*$/;

const RULE_TYPES = [
  { value: "os_build_min", label: "Minimum OS build" },
  { value: "os_build_min_per_release", label: "Patched to at least, per release" },
  { value: "agent_version_min", label: "Minimum agent version" },
  { value: "bitlocker", label: "BitLocker" },
  { value: "tpm", label: "TPM present" },
  { value: "checked_in_within", label: "Checked in within" },
  { value: "inventory_within", label: "Inventory received within" },
  { value: "updates_within", label: "Updates installed within" },
  { value: "no_pending_reboot", label: "No pending reboot" },
  { value: "max_local_admins", label: "Maximum local admins" },
  { value: "forbidden_software", label: "Forbidden software" },
  { value: "required_software", label: "Required software" },
  { value: "profile_applied", label: "Profile applied" },
  { value: "defender_realtime", label: "Defender real-time protection on" },
  { value: "defender_signatures_within", label: "Defender signatures updated within" },
  { value: "firewall_enabled", label: "Firewall on" },
  { value: "max_missing_security_updates", label: "Maximum missing security updates" },
];

const FIREWALL_PROFILES = ["domain", "private", "public"];

function blankRule(type: string): ComplianceRule {
  switch (type) {
    case "os_build_min":
      return { type, build: "" };
    case "os_build_min_per_release":
      return { type, minimums: {} };
    case "agent_version_min":
      return { type, version: "" };
    case "bitlocker":
      return { type, volumes: "system" };
    case "tpm":
      return { type, min_version: "" };
    case "checked_in_within":
      return { type, hours: 24 };
    case "inventory_within":
      return { type, hours: 24 };
    case "updates_within":
      return { type, days: 30 };
    case "no_pending_reboot":
      return { type };
    case "max_local_admins":
      return { type, count: 1 };
    case "forbidden_software":
      return { type, name: "" };
    case "required_software":
      return { type, name: "" };
    case "profile_applied":
      return { type, profile_id: "" };
    case "defender_realtime":
      return { type };
    case "defender_signatures_within":
      return { type, days: 3 };
    case "firewall_enabled":
      return { type };
    case "max_missing_security_updates":
      return { type, count: 0 };
    default:
      return { type: "os_build_min", build: "" };
  }
}

/** ruleError reports what is wrong with a rule's parameters, matching the
 * bounds ParseRules enforces exactly, so the editor never accepts something
 * the server would reject. undefined means the rule is valid. */
function ruleError(rule: ComplianceRule): string | undefined {
  switch (rule.type) {
    case "os_build_min":
      return DOTTED.test(rule.build ?? "") ? undefined : "Digits only, optionally dotted (e.g. 26100 or 22631.1).";
    case "os_build_min_per_release": {
      const entries = Object.entries(rule.minimums ?? {});
      if (entries.length === 0) return "Add at least one build, such as 26100.2605.";
      if (entries.length > 20) return "At most 20 releases.";
      return entries.every(([base, min]) => /^\d+$/.test(base) && new RegExp(`^${base}\\.\\d+$`).test(min))
        ? undefined
        : "One build per line, a release and its patch level, such as 26100.2605.";
    }
    case "agent_version_min":
      return DOTTED.test(rule.version ?? "") ? undefined : "A dotted numeric version, e.g. 1.4.0.";
    case "bitlocker":
      return rule.volumes === "system" || rule.volumes === "all" ? undefined : "Choose which volumes.";
    case "tpm": {
      const v = rule.min_version ?? "";
      return v === "" || DOTTED.test(v) ? undefined : "A dotted numeric version, e.g. 2.0, or leave empty.";
    }
    case "checked_in_within":
    case "inventory_within": {
      const h = rule.hours;
      return h !== undefined && Number.isInteger(h) && h >= 1 && h <= 8760
        ? undefined
        : "Between 1 and 8760 hours.";
    }
    case "updates_within": {
      const d = rule.days;
      return d !== undefined && Number.isInteger(d) && d >= 1 && d <= 365 ? undefined : "Between 1 and 365 days.";
    }
    case "no_pending_reboot":
      return undefined;
    case "max_local_admins":
    case "max_missing_security_updates": {
      const c = rule.count;
      return c !== undefined && Number.isInteger(c) && c >= 0 && c <= 100 ? undefined : "Between 0 and 100.";
    }
    case "forbidden_software":
    case "required_software": {
      const n = (rule.name ?? "").length;
      return n >= 1 && n <= 200 ? undefined : "Between 1 and 200 characters.";
    }
    case "profile_applied":
      return rule.profile_id ? undefined : "Choose a profile.";
    case "defender_realtime":
      return undefined;
    case "defender_signatures_within": {
      const d = rule.days;
      return d !== undefined && Number.isInteger(d) && d >= 1 && d <= 30 ? undefined : "Between 1 and 30 days.";
    }
    case "firewall_enabled":
      // Absent means all three; a list, when given, must name at least one.
      return rule.profiles === undefined || rule.profiles.length > 0 ? undefined : "Choose at least one profile.";
    default:
      return "Unsupported rule type.";
  }
}

/** parseMinimums reads one patched build per line, such as 26100.2605, into
 * the per-release map the rule stores. A line that isn't one is kept with an
 * empty minimum, so ruleError flags it rather than it silently vanishing. */
export function parseMinimums(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const m = /^(\d+)\.\d+$/.exec(line);
    if (m) out[m[1]] = line;
    else out[line] = "";
  }
  return out;
}

/** MinimumsField edits os_build_min_per_release's table as lines of text. */
function MinimumsField({
  minimums,
  error,
  onChange,
}: {
  minimums: Record<string, string>;
  error?: string;
  onChange: (next: Record<string, string>) => void;
}) {
  const [text, setText] = useState(() => Object.values(minimums).join("\n"));
  return (
    <Field
      label="Minimum patched builds"
      hint="One per line, for each Windows release in the fleet: e.g. 26100.2605 for 24H2 and 22631.4751 for 23H2. A device on a release not listed is reported unknown. Keeping this current each month is up to you."
      error={error}
    >
      <textarea
        className="mono"
        rows={4}
        value={text}
        onChange={(e) => {
          setText(e.target.value);
          onChange(parseMinimums(e.target.value));
        }}
      />
    </Field>
  );
}

/** RuleFields renders the typed inputs one rule type needs, and nothing
 * else, the same idiom Profiles' SettingFields uses for setting kinds. */
function RuleFields({
  rule,
  profiles,
  onChange,
}: {
  rule: ComplianceRule;
  profiles: Profile[];
  onChange: (next: ComplianceRule) => void;
}) {
  const set = (patch: Partial<ComplianceRule>) => onChange({ ...rule, ...patch });
  const err = ruleError(rule);

  switch (rule.type) {
    case "os_build_min_per_release":
      return <MinimumsField minimums={rule.minimums ?? {}} error={err} onChange={(minimums) => set({ minimums })} />;
    case "os_build_min":
      return (
        <Field label="Minimum OS build" hint="Digits, optionally dotted, e.g. 26100 or 22631.1." error={err}>
          <input value={rule.build ?? ""} onChange={(e) => set({ build: e.target.value })} />
        </Field>
      );
    case "agent_version_min":
      return (
        <Field label="Minimum agent version" hint="Dotted numeric, e.g. 1.4.0." error={err}>
          <input value={rule.version ?? ""} onChange={(e) => set({ version: e.target.value })} />
        </Field>
      );
    case "bitlocker":
      return (
        <Field label="Volumes" error={err}>
          <select value={rule.volumes ?? "system"} onChange={(e) => set({ volumes: e.target.value })}>
            <option value="system">System volume (C:)</option>
            <option value="all">All fixed volumes</option>
          </select>
        </Field>
      );
    case "tpm":
      return (
        <Field
          label="Minimum TPM version"
          hint="Optional. Leave empty to only require a TPM be present."
          error={err}
        >
          <input value={rule.min_version ?? ""} onChange={(e) => set({ min_version: e.target.value })} />
        </Field>
      );
    case "checked_in_within":
      return (
        <Field label="Checked in within (hours)" error={err}>
          <input
            type="number"
            min={1}
            max={8760}
            value={rule.hours ?? ""}
            onChange={(e) => set({ hours: e.target.value === "" ? undefined : Number(e.target.value) })}
          />
        </Field>
      );
    case "inventory_within":
      return (
        <Field label="Inventory received within (hours)" error={err}>
          <input
            type="number"
            min={1}
            max={8760}
            value={rule.hours ?? ""}
            onChange={(e) => set({ hours: e.target.value === "" ? undefined : Number(e.target.value) })}
          />
        </Field>
      );
    case "updates_within":
      return (
        <Field label="Updates installed within (days)" error={err}>
          <input
            type="number"
            min={1}
            max={365}
            value={rule.days ?? ""}
            onChange={(e) => set({ days: e.target.value === "" ? undefined : Number(e.target.value) })}
          />
        </Field>
      );
    case "no_pending_reboot":
      return <p className="hint">No parameters: the device must not have a reboot pending.</p>;
    case "max_missing_security_updates":
      return (
        <Field
          label="Security updates that may be missing"
          hint="Counted from the device's own daily Windows Update search. No search yet, a failed one or one over a week old is unknown."
          error={err}
        >
          <input
            type="number"
            min={0}
            max={100}
            value={rule.count ?? ""}
            onChange={(e) => set({ count: e.target.value === "" ? undefined : Number(e.target.value) })}
          />
        </Field>
      );
    case "max_local_admins":
      return (
        <Field label="Maximum local admins" error={err}>
          <input
            type="number"
            min={0}
            max={100}
            value={rule.count ?? ""}
            onChange={(e) => set({ count: e.target.value === "" ? undefined : Number(e.target.value) })}
          />
        </Field>
      );
    case "forbidden_software":
      return (
        <Field
          label="Forbidden software name"
          hint="Matches any installed package whose name contains this, case-insensitively."
          error={err}
        >
          <input value={rule.name ?? ""} maxLength={200} onChange={(e) => set({ name: e.target.value })} />
        </Field>
      );
    case "required_software":
      return (
        <Field
          label="Required software name"
          hint="Matches any installed package whose name contains this, case-insensitively."
          error={err}
        >
          <input value={rule.name ?? ""} maxLength={200} onChange={(e) => set({ name: e.target.value })} />
        </Field>
      );
    case "profile_applied":
      return (
        <Field
          label="Profile"
          hint={profiles.length === 0 ? "No profiles exist yet." : undefined}
          error={err}
        >
          <select value={rule.profile_id ?? ""} onChange={(e) => set({ profile_id: e.target.value })}>
            <option value="">Choose a profile…</option>
            {profiles.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </Field>
      );
    case "defender_realtime":
      return (
        <p className="hint">
          No parameters: Defender must be on with real-time protection. A device where another antivirus is primary
          reports unknown, not non-compliant.
        </p>
      );
    case "defender_signatures_within":
      return (
        <Field label="Signatures updated within (days)" error={err}>
          <input
            type="number"
            min={1}
            max={30}
            value={rule.days ?? ""}
            onChange={(e) => set({ days: e.target.value === "" ? undefined : Number(e.target.value) })}
          />
        </Field>
      );
    case "firewall_enabled": {
      // No list stored means "all three", so every box starts ticked; a
      // list is only written once somebody unticks one.
      const chosen = rule.profiles ?? FIREWALL_PROFILES;
      const toggle = (name: string, on: boolean) => {
        const next = FIREWALL_PROFILES.filter((p) => (p === name ? on : chosen.includes(p)));
        set({ profiles: next.length === FIREWALL_PROFILES.length ? undefined : next });
      };
      // A fieldset rather than Field: Field wraps its content in a <label>,
      // and a label cannot hold three more.
      return (
        <fieldset className="field check-group">
          <legend>Profiles that must be on</legend>
          {FIREWALL_PROFILES.map((name) => (
            <label key={name}>
              <input type="checkbox" checked={chosen.includes(name)} onChange={(e) => toggle(name, e.target.checked)} />
              {name}
            </label>
          ))}
          {err ? <p className="error">{err}</p> : null}
        </fieldset>
      );
    }
    default:
      return null;
  }
}

function PolicyEditor({
  policy,
  open,
  onClose,
  onSaved,
}: {
  policy: CompliancePolicy | null;
  open: boolean;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [rules, setRules] = useState<ComplianceRule[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [warning, setWarning] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    setName(policy?.name ?? "");
    setDescription(policy?.description ?? "");
    setRules(policy?.rules ?? []);
    setError(null);
    setWarning("");
    api
      .get<ListResponse<Profile>>("/profiles?limit=200")
      .then((resp) => setProfiles(resp.items))
      .catch(() => setProfiles([]));
  }, [open, policy]);

  function update(index: number, next: ComplianceRule) {
    setRules(rules.map((r, i) => (i === index ? next : r)));
  }

  const hasRuleErrors = rules.some((r) => ruleError(r) !== undefined);
  const canSave = name.trim() !== "" && rules.length >= 1 && rules.length <= 50 && !hasRuleErrors;

  async function save() {
    setBusy(true);
    setError(null);
    setWarning("");
    try {
      const payload = { name, description, rules };
      if (!policy) {
        await api.post("/compliance-policies", payload);
      } else {
        await api.post(`/compliance-policies/${policy.id}`, payload);
        // Spec §2: a policy is edited in place and re-evaluated. Without
        // this, every verdict on the list, the Devices compliance column and
        // each device page reflects the rules as they were until the next
        // sweep, up to fifteen minutes later, with nothing marking them
        // stale. It is a second request rather than part of the update
        // because re-scoring walks the whole fleet, which has no business
        // inside an edit. The server runs the pass after answering, so this
        // returns as soon as the work is accepted, not when it is finished.
        try {
          await api.post(`/compliance-policies/${policy.id}/evaluate`);
        } catch {
          // The edit is already committed, so this is a warning on a save
          // that worked, not a failed save: reload the list and say what did
          // not happen, leaving the dialog open so it is read.
          setWarning("Saved, but re-evaluating devices failed. They will be re-scored at the next sweep.");
          onSaved();
          return;
        }
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
    <Dialog title={policy ? `Edit ${policy.name}` : "New compliance policy"} open={open} onClose={onClose}>
      <Field label="Name">
        <input value={name} onChange={(e) => setName(e.target.value)} />
      </Field>
      <Field label="Description">
        <input value={description} onChange={(e) => setDescription(e.target.value)} />
      </Field>

      {rules.map((rule, index) => (
        <fieldset key={index} className="rule">
          <legend>
            <select
              value={rule.type}
              onChange={(e) => update(index, blankRule(e.target.value))}
              aria-label={`Rule ${index + 1} type`}
            >
              {RULE_TYPES.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </select>
            <Button variant="quiet" onClick={() => setRules(rules.filter((_, i) => i !== index))}>
              Remove
            </Button>
          </legend>
          <RuleFields rule={rule} profiles={profiles} onChange={(next) => update(index, next)} />
        </fieldset>
      ))}

      <div className="actions">
        <Button
          variant="quiet"
          onClick={() => setRules([...rules, blankRule("os_build_min")])}
          disabled={rules.length >= 50}
        >
          Add a rule
        </Button>
      </div>
      {rules.length === 0 ? <p className="hint">A policy needs between 1 and 50 rules.</p> : null}

      <ErrorNote error={error} />
      {warning ? <p className="hint">{warning}</p> : null}
      <div className="actions">
        <Button onClick={() => void save()} disabled={busy || !canSave}>
          {policy ? "Save policy" : "Create policy"}
        </Button>
        <Button variant="quiet" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </Dialog>
  );
}

function AssignDialog({
  policy,
  open,
  onClose,
  onAssigned,
}: {
  policy: CompliancePolicy | null;
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
    api
      .get<{ items: Group[] }>("/groups")
      .then((resp) => {
        setGroups(resp.items);
        setGroupID((current) => current || (resp.items[0]?.id ?? ""));
      })
      .catch((err: unknown) => setError(err));
  }, [open]);

  async function assign() {
    if (!policy) return;
    setError(null);
    try {
      // A compliance policy takes no assignment options at all (spec §5,
      // internal/server/adminapi/itemkinds.go): the same policy always
      // evaluates the same way, so there is nothing per-assignment to send.
      await api.post("/assignments", {
        item_kind: ITEM_KIND,
        item_id: policy.id,
        group_id: groupID,
        mode,
      });
      onAssigned();
      onClose();
    } catch (err) {
      setError(err);
    }
  }

  return (
    <Dialog title={`Assign ${policy?.name ?? ""}`} open={open} onClose={onClose}>
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

/** PolicyRollup renders a policy's device-state counts, which the list
 * endpoint now batches for the whole page in one query (device_counts on
 * each item) rather than this component fetching them itself. */
function PolicyRollup({ counts }: { counts?: Record<string, number> }) {
  if (!counts) return null;
  return (
    <span className="policy__rollup">
      <StatusDot status="compliant" /> {counts.compliant ?? 0} <StatusDot status="non_compliant" />{" "}
      {counts.non_compliant ?? 0} <StatusDot status="unknown" /> {counts.unknown ?? 0}
    </span>
  );
}

/** PolicyDetail answers the question an administrator actually has: which
 * devices are failing this policy, and why. */
function PolicyDetail({ policy, canWrite }: { policy: CompliancePolicy; canWrite: boolean }) {
  const [state, setState] = useState("");
  const [evaluating, setEvaluating] = useState(false);
  const [evaluateNote, setEvaluateNote] = useState<string | null>(null);
  const [evalError, setEvalError] = useState<unknown>(null);
  const { items, total, loading, error, offset, setOffset, reload } = useList<PolicyDeviceCompliance>(
    `/compliance-policies/${policy.id}/devices`,
    { state },
  );

  // The pass runs on the server after the response, so there is nothing to
  // reload yet: the reply says how many devices it covers, and Refresh is how
  // an administrator picks up the verdicts once it has run. Its outcome is
  // also written to the audit log, which is where to look if a device's
  // result never changes.
  async function evaluateNow() {
    setEvaluating(true);
    setEvalError(null);
    setEvaluateNote(null);
    try {
      const resp = await api.post<{ device_count: number; started: boolean }>(
        `/compliance-policies/${policy.id}/evaluate`,
      );
      setEvaluateNote(
        resp.started
          ? `Re-evaluating ${resp.device_count} device${resp.device_count === 1 ? "" : "s"} in the background.`
          : "A re-evaluation of this policy is already running.",
      );
    } catch (err) {
      setEvalError(err);
    } finally {
      setEvaluating(false);
    }
  }

  const exportHref = `/api/admin/v1/compliance-policies/${policy.id}/devices/export.csv${
    state ? `?state=${state}` : ""
  }`;

  return (
    <section className="policy__detail">
      <div className="content__head">
        <h2>{policy.name}</h2>
        <div className="policy__detail-actions">
          {canWrite ? (
            <Button onClick={() => void evaluateNow()} disabled={evaluating}>
              {evaluating ? "Starting…" : "Evaluate now"}
            </Button>
          ) : null}
          <Button variant="quiet" onClick={reload} disabled={loading}>
            Refresh
          </Button>
          <a className="button" href={exportHref}>
            Export CSV
          </a>
        </div>
      </div>

      {evaluateNote ? <p className="hint">{evaluateNote}</p> : null}
      <ErrorNote error={evalError} />

      <Field label="State">
        <select
          value={state}
          onChange={(e) => {
            setOffset(0);
            setState(e.target.value);
          }}
        >
          <option value="">All</option>
          <option value="compliant">Compliant</option>
          <option value="non_compliant">Non-compliant</option>
          <option value="unknown">Unknown</option>
        </select>
      </Field>

      <ErrorNote error={error} />
      {loading ? <Spinner /> : null}
      {!loading && items.length === 0 ? <p className="policy__none">No devices to show.</p> : null}

      {items.length > 0 ? (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Device</th>
                <th>State</th>
                <th>Failures</th>
                <th>Evaluated</th>
              </tr>
            </thead>
            <tbody>
              {items.map((row) => (
                <tr key={row.device_id}>
                  <td>
                    <Link to={`/devices/${row.device_id}`}>{row.hostname}</Link>
                  </td>
                  <td>
                    <StatusDot status={row.state} />
                  </td>
                  <td>{row.failures.map((f) => f.detail).join("; ")}</td>
                  <td>{relative(row.evaluated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

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
    </section>
  );
}

export default function Compliance() {
  const { canWrite } = useSession();
  const { items, total, loading, error, offset, setOffset, reload } = useList<CompliancePolicy>(
    "/compliance-policies",
  );
  const [editing, setEditing] = useState<CompliancePolicy | null>(null);
  const [editorOpen, setEditorOpen] = useState(false);
  const [assigning, setAssigning] = useState<CompliancePolicy | null>(null);
  // The open detail is remembered by id, not by holding the policy object the
  // row was rendered from: that object is a snapshot, so after an edit the
  // detail kept showing the name and rules the policy had before it was saved.
  // Deriving it from the current page means the detail follows the list.
  const [selectedID, setSelectedID] = useState<string | null>(null);
  const selected = items.find((p) => p.id === selectedID) ?? null;
  const [actionError, setActionError] = useState<unknown>(null);

  async function remove(policy: CompliancePolicy) {
    if (!window.confirm(`Delete ${policy.name}? Its assignments and results go with it.`)) return;
    try {
      await api.del(`/compliance-policies/${policy.id}`);
      if (selectedID === policy.id) setSelectedID(null);
      reload();
    } catch (err) {
      setActionError(err);
    }
  }

  return (
    <>
      <div className="content__head">
        <h1>Compliance</h1>
        {canWrite ? (
          <Button
            onClick={() => {
              setEditing(null);
              setEditorOpen(true);
            }}
          >
            New policy
          </Button>
        ) : null}
      </div>

      <ErrorNote error={error} />
      <ErrorNote error={actionError} />
      {loading ? <Spinner /> : null}

      {!loading && items.length === 0 ? (
        <EmptyState title="No compliance policies yet.">
          <p>A policy states what a healthy device looks like, and is assigned to groups the same way a profile is.</p>
        </EmptyState>
      ) : null}

      {items.length > 0 ? (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th className="numeric">Rule count</th>
                <th>Devices</th>
                <th>Updated</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {items.map((policy) => (
                <tr key={policy.id}>
                  <td>
                    <button className="linklike" onClick={() => setSelectedID(policy.id)}>
                      {policy.name}
                    </button>
                    {policy.description ? <div className="policy__description">{policy.description}</div> : null}
                  </td>
                  <td className="numeric">{policy.rules.length}</td>
                  <td>
                    <PolicyRollup counts={policy.device_counts} />
                  </td>
                  <td>{relative(policy.updated_at)}</td>
                  <td className="policy__actions">
                    {canWrite ? (
                      <>
                        <Button
                          variant="quiet"
                          onClick={() => {
                            setEditing(policy);
                            setEditorOpen(true);
                          }}
                        >
                          Edit
                        </Button>
                        <Button variant="quiet" onClick={() => setAssigning(policy)}>
                          Assign
                        </Button>
                        <Button variant="quiet" onClick={() => void remove(policy)}>
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

      {selected ? <PolicyDetail policy={selected} canWrite={canWrite} /> : null}

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

      <PolicyEditor policy={editing} open={editorOpen} onClose={() => setEditorOpen(false)} onSaved={reload} />
      <AssignDialog
        policy={assigning}
        open={assigning !== null}
        onClose={() => setAssigning(null)}
        onAssigned={reload}
      />
    </>
  );
}
