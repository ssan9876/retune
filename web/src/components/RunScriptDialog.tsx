import { useState } from "react";

import { api } from "../api/client";
import { useSession } from "../session/SessionContext";
import { SignatureField, parseSignature } from "./SignatureField";
import { Button, Dialog, ErrorNote, Field } from "./ui";

/** RunScriptDialog queues one PowerShell script on one or more devices. */
export function RunScriptDialog({
  deviceIds,
  open,
  onClose,
  onQueued,
}: {
  deviceIds: string[];
  open: boolean;
  onClose: () => void;
  onQueued: () => void;
}) {
  const [script, setScript] = useState("");
  const [timeoutSeconds, setTimeoutSeconds] = useState(600);
  const { signingRequired } = useSession();
  const [signatureText, setSignatureText] = useState("");
  const signature = parseSignature(signatureText);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  async function queue() {
    setBusy(true);
    setError(null);
    try {
      await api.post("/commands", {
        device_ids: deviceIds,
        type: "run_powershell",
        script,
        timeout_seconds: timeoutSeconds,
        ...(signature ? { signature } : {}),
      });
      setScript("");
      setSignatureText("");
      onQueued();
      onClose();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog title="Run a PowerShell script" open={open} onClose={onClose}>
      <Field
        label="PowerShell script"
        hint={`Runs as SYSTEM on ${deviceIds.length} ${deviceIds.length === 1 ? "device" : "devices"}.`}
      >
        <textarea value={script} onChange={(event) => setScript(event.target.value)} spellCheck={false} />
      </Field>
      <Field label="Timeout in seconds">
        <input
          type="number"
          min={1}
          max={86400}
          value={timeoutSeconds}
          onChange={(event) => setTimeoutSeconds(Number(event.target.value))}
        />
      </Field>
      {signingRequired ? (
        <SignatureField
          value={signatureText}
          onChange={setSignatureText}
          valid={signature !== null}
          command="retune-sign sign-script --key operations.key script.ps1"
        />
      ) : null}
      <ErrorNote error={error} />
      <div className="actions">
        <Button
          variant="primary"
          disabled={busy || script.trim() === "" || (signingRequired && signature === null)}
          onClick={() => void queue()}
        >
          {busy ? "Queueing…" : "Queue script"}
        </Button>
        <Button variant="quiet" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </Dialog>
  );
}
