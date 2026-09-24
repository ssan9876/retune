import { useEffect, useState } from "react";

import { heldForApproval } from "../api/approvals";
import { api } from "../api/client";
import { useSession } from "../session/SessionContext";
import { SignatureField, parseSignedOrder } from "./SignatureField";
import { Button, Dialog, ErrorNote, Field, HeldNote } from "./ui";
import "./RemoteActionDialogs.css";

/** CollectLogsDialog asks a device for its agent and event logs. */
export function CollectLogsDialog({
  deviceId,
  open,
  onClose,
  onQueued,
}: {
  deviceId: string;
  open: boolean;
  onClose: () => void;
  onQueued: () => void;
}) {
  const [hours, setHours] = useState(24);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (open) {
      setHours(24);
      setError(null);
    }
  }, [open]);

  async function queue() {
    setBusy(true);
    setError(null);
    try {
      await api.post("/commands", { device_ids: [deviceId], type: "collect_logs", hours });
      onQueued();
      onClose();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  const valid = Number.isInteger(hours) && hours >= 1 && hours <= 168;
  return (
    <Dialog title="Collect logs" open={open} onClose={onClose}>
      <p className="hint">
        The device zips the Retune agent&apos;s logs and its System and Application event logs, up to 50 MiB, and
        uploads them at its next check-in. The archive appears on the Commands page for 30 days.
      </p>
      <Field label="Event logs from the last (hours)" hint="1 to 168." error={valid ? undefined : "Between 1 and 168."}>
        <input
          type="number"
          min={1}
          max={168}
          value={Number.isNaN(hours) ? "" : hours}
          onChange={(e) => setHours(e.target.valueAsNumber)}
        />
      </Field>
      <ErrorNote error={error} />
      <div className="actions">
        <Button variant="primary" disabled={busy || !valid} onClick={() => void queue()}>
          Collect logs
        </Button>
        <Button variant="quiet" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </Dialog>
  );
}

/** InstallUpdatesDialog installs what Windows Update is offering the device
 * now. */
export function InstallUpdatesDialog({
  deviceId,
  hostname,
  open,
  onClose,
  onQueued,
}: {
  deviceId: string;
  hostname: string;
  open: boolean;
  onClose: () => void;
  onQueued: () => void;
}) {
  const [scope, setScope] = useState("security");
  const [restart, setRestart] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (open) {
      setScope("security");
      setRestart(false);
      setError(null);
    }
  }, [open]);

  async function install() {
    setBusy(true);
    setError(null);
    try {
      await api.post("/commands", {
        device_ids: [deviceId],
        type: "install_updates",
        scope,
        restart_policy: restart ? "if_required" : "never",
      });
      onQueued();
      onClose();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog title={`Install updates on ${hostname}`} open={open} onClose={onClose}>
      <Field label="Install">
        <select value={scope} onChange={(e) => setScope(e.target.value)}>
          <option value="security">Security and critical updates</option>
          <option value="all">Everything Windows Update offers, drivers included</option>
        </select>
      </Field>
      <label style={{ display: "block", marginBottom: "var(--space-2)" }}>
        <input type="checkbox" checked={restart} onChange={(e) => setRestart(e.target.checked)} /> Restart five
        minutes later if an update needs it
      </label>
      <p className="hint">
        Downloading and installing can take a while. The result shows on the Commands page, and the device reports its
        updates afresh when it is done.
      </p>
      <ErrorNote error={error} />
      <div className="actions">
        <Button variant="primary" onClick={() => void install()} disabled={busy}>
          Install updates
        </Button>
        <Button variant="quiet" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </Dialog>
  );
}

/** validComputerName matches the server's check on a computer name. */
export function validComputerName(name: string): boolean {
  return /^[A-Za-z0-9-]{1,15}$/.test(name) && !/^\d+$/.test(name) && !name.startsWith("-") && !name.endsWith("-");
}

/** RenameDialog gives a device a new computer name. */
export function RenameDialog({
  deviceId,
  hostname,
  open,
  onClose,
  onQueued,
}: {
  deviceId: string;
  hostname: string;
  open: boolean;
  onClose: () => void;
  onQueued: () => void;
}) {
  const [name, setName] = useState("");
  const [restart, setRestart] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (open) {
      setName("");
      setRestart(false);
      setError(null);
    }
  }, [open]);

  async function rename() {
    setBusy(true);
    setError(null);
    try {
      await api.post("/commands", { device_ids: [deviceId], type: "rename_computer", name: name.trim(), restart });
      onQueued();
      onClose();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  const valid = validComputerName(name.trim());
  return (
    <Dialog title={`Rename ${hostname}`} open={open} onClose={onClose}>
      <Field
        label="New computer name"
        error={name.trim() && !valid ? "Up to 15 letters, digits and hyphens, not all digits." : undefined}
      >
        <input value={name} onChange={(e) => setName(e.target.value)} />
      </Field>
      <label style={{ display: "block", marginBottom: "var(--space-2)" }}>
        <input type="checkbox" checked={restart} onChange={(e) => setRestart(e.target.checked)} /> Restart a minute
        later, so the name takes effect now
      </label>
      <p className="hint">Without a restart, the new name takes effect the next time the device restarts.</p>
      <ErrorNote error={error} />
      <div className="actions">
        <Button variant="primary" onClick={() => void rename()} disabled={busy || !valid}>
          Rename
        </Button>
        <Button variant="quiet" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </Dialog>
  );
}

/** WipeDialog resets a device to factory settings, once the administrator has
 * typed its hostname and said why. */
export function WipeDialog({
  deviceId,
  hostname,
  open,
  onClose,
  onQueued,
}: {
  deviceId: string;
  hostname: string;
  open: boolean;
  onClose: () => void;
  onQueued: () => void;
}) {
  const [confirm, setConfirm] = useState("");
  const [reason, setReason] = useState("");
  const [protectedWipe, setProtectedWipe] = useState(false);
  const [orderText, setOrderText] = useState("");
  const { signingRequired } = useSession();
  const [error, setError] = useState<unknown>(null);
  const [held, setHeld] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (open) setHeld(false);
    if (open) {
      setConfirm("");
      setReason("");
      setProtectedWipe(false);
      setOrderText("");
      setError(null);
    }
  }, [open]);

  const order = parseSignedOrder(orderText);
  // A signed order says for itself whether the wipe is protected.
  const effectiveProtected = order?.protected ?? protectedWipe;
  const orderFits = !signingRequired || (order !== null && (order.device ?? deviceId).toLowerCase() === deviceId.toLowerCase());
  const matches = confirm.trim().toLowerCase() === hostname.toLowerCase();
  const ready = matches && reason.trim() !== "" && orderFits;

  async function wipe() {
    setBusy(true);
    setError(null);
    try {
      const res = await api.post("/commands", {
        device_ids: [deviceId],
        type: "wipe",
        protected: effectiveProtected,
        confirm_hostname: confirm.trim(),
        reason: reason.trim(),
        ...(order ? { expires: order.expires, signature: { key_id: order.key_id, signature: order.signature } } : {}),
      });
      onQueued();
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
    <Dialog title={`Wipe ${hostname}`} open={open} onClose={onClose}>
      <p className="note" role="alert">
        This resets {hostname} to factory settings: every app, file and account on it is removed, and it stops being
        managed until it is enrolled again. It can&apos;t be undone. The order lapses if the device doesn&apos;t check
        in within 24 hours.
      </p>
      <Field label={`Type ${hostname} to confirm`}>
        <input
          aria-label="Confirm hostname"
          className="mono"
          autoComplete="off"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
        />
      </Field>
      <Field label="Reason" hint="Recorded in the audit log, e.g. a ticket number.">
        <input aria-label="Reason" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={500} />
      </Field>
      {signingRequired ? (
        <SignatureField
          label="Signed wipe order"
          value={orderText}
          onChange={setOrderText}
          valid={order !== null && orderFits}
          command={`retune-sign sign-wipe --key operations.key --device ${deviceId} [--protected] --valid-for 4h`}
        />
      ) : (
        <label className="remote-actions__check">
          <input type="checkbox" checked={protectedWipe} onChange={(e) => setProtectedWipe(e.target.checked)} />
          Also remove what a reset keeps for recovery (a protected wipe; the device may need reinstalling)
        </label>
      )}
      <ErrorNote error={error} />
      {held ? <HeldNote /> : null}
      <div className="actions">
        <Button variant="danger" disabled={busy || !ready} onClick={() => void wipe()}>
          Wipe {hostname}
        </Button>
        <Button variant="quiet" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </Dialog>
  );
}
