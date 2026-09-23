import { useEffect, useState } from "react";

import { api } from "../api/client";
import { useSession } from "../session/SessionContext";
import { SignatureField, parseSignedOrder } from "./SignatureField";
import { Button, Dialog, ErrorNote, Field } from "./ui";
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
  const [busy, setBusy] = useState(false);

  useEffect(() => {
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
      await api.post("/commands", {
        device_ids: [deviceId],
        type: "wipe",
        protected: effectiveProtected,
        confirm_hostname: confirm.trim(),
        reason: reason.trim(),
        ...(order ? { expires: order.expires, signature: { key_id: order.key_id, signature: order.signature } } : {}),
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
