import { useCallback, useEffect, useState } from "react";

import { api } from "../api/client";
import type { BitLockerKey } from "../api/types";
import { useSession } from "../session/SessionContext";
import { Button, ErrorNote, Field } from "./ui";

interface Revealed extends BitLockerKey {
  recovery_password: string;
}

/**
 * RecoveryKeys shows which of a device's volumes have an escrowed BitLocker
 * key, and reveals one on request. The key is never part of the listing: it is
 * fetched only when someone deliberately asks, and every reveal is recorded.
 */
export function RecoveryKeys({ deviceId }: { deviceId: string }) {
  const { canOperate } = useSession();
  const [keys, setKeys] = useState<BitLockerKey[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [revealing, setRevealing] = useState<BitLockerKey | null>(null);
  const [reason, setReason] = useState("");
  const [revealed, setRevealed] = useState<Revealed | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api
      .get<{ items: BitLockerKey[] }>(`/devices/${deviceId}/bitlocker-keys`)
      .then((resp) => {
        setKeys(resp.items ?? []);
        setError(null);
      })
      .catch((err: unknown) => setError(err));
  }, [deviceId]);

  useEffect(load, [load]);

  async function reveal() {
    if (!revealing) return;
    setBusy(true);
    setError(null);
    try {
      setRevealed(
        await api.post<Revealed>(`/bitlocker-keys/${revealing.id}/reveal`, { reason }),
      );
      setRevealing(null);
      setReason("");
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  if (keys.length === 0) {
    return null;
  }

  return (
    <section className="recovery">
      <h2>BitLocker recovery keys</h2>
      <ErrorNote error={error} />
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Volume</th>
              <th>Method</th>
              <th>Escrowed</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {keys.map((key) => (
              <tr key={key.id}>
                <td className="mono">{key.volume_id}</td>
                <td>{key.method}</td>
                <td>{new Date(key.updated_at).toLocaleDateString()}</td>
                <td style={{ textAlign: "right" }}>
                  {canOperate ? (
                    <Button
                      variant="quiet"
                      onClick={() => {
                        setRevealed(null);
                        setRevealing(key);
                      }}
                    >
                      Show the key
                    </Button>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {revealing ? (
        <div className="recovery__confirm">
          <p>
            Showing the recovery key for {revealing.volume_id} is recorded against your account.
          </p>
          <Field label="Why do you need it?" hint="Recorded with the entry. Optional.">
            <input value={reason} onChange={(e) => setReason(e.target.value)} />
          </Field>
          <div className="actions">
            <Button onClick={() => void reveal()} disabled={busy}>
              Show the key
            </Button>
            <Button variant="quiet" onClick={() => setRevealing(null)}>
              Cancel
            </Button>
          </div>
        </div>
      ) : null}

      {revealed ? (
        <div className="recovery__key">
          <p>
            Recovery key for {revealed.volume_id} on {revealed.hostname}:
          </p>
          <pre className="mono">{revealed.recovery_password}</pre>
          <Button variant="quiet" onClick={() => setRevealed(null)}>
            Hide it
          </Button>
        </div>
      ) : null}
    </section>
  );
}
