import { useCallback, useEffect, useState } from "react";

import { api } from "../api/client";
import type { AdminPassword } from "../api/types";
import { useSession } from "../session/SessionContext";
import { Button, ErrorNote, Field } from "./ui";

const STATE_LABELS: Record<AdminPassword["state"], string> = {
  active: "In use",
  pending: "Being set",
  superseded: "Replaced",
  abandoned: "Rotation failed; may not be in use",
};

/**
 * AdminPasswords lists a device's escrowed local administrator passwords and
 * reveals one, with a reason, on request. The listing never carries a
 * password; every reveal is recorded against whoever asked.
 */
export function AdminPasswords({ deviceId, reloadToken = 0 }: { deviceId: string; reloadToken?: number }) {
  const { canWrite } = useSession();
  const [items, setItems] = useState<AdminPassword[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [revealing, setRevealing] = useState<AdminPassword | null>(null);
  const [reason, setReason] = useState("");
  const [revealed, setRevealed] = useState<{ password: string; admin_password: AdminPassword } | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api
      .get<{ items: AdminPassword[] }>(`/devices/${deviceId}/admin-passwords`)
      .then((resp) => {
        setItems(resp.items ?? []);
        setError(null);
      })
      .catch((err: unknown) => setError(err));
  }, [deviceId]);

  useEffect(load, [load, reloadToken]);

  async function reveal() {
    if (!revealing) return;
    setBusy(true);
    setError(null);
    try {
      setRevealed(
        await api.post<{ password: string; admin_password: AdminPassword }>(
          `/admin-passwords/${revealing.id}/reveal`,
          { reason },
        ),
      );
      setRevealing(null);
      setReason("");
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  if (items.length === 0) {
    return null;
  }

  return (
    <section className="recovery">
      <h2>Local administrator passwords</h2>
      <ErrorNote error={error} />
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Account</th>
              <th>State</th>
              <th>Set</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={item.id}>
                <td className="mono">{item.account}</td>
                <td>{STATE_LABELS[item.state] ?? item.state}</td>
                <td>{new Date(item.activated_at ?? item.created_at).toLocaleString()}</td>
                <td style={{ textAlign: "right" }}>
                  {canWrite ? (
                    <Button
                      variant="quiet"
                      onClick={() => {
                        setRevealed(null);
                        setRevealing(item);
                      }}
                    >
                      Show the password
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
          <p>Showing the password for {revealing.account} is recorded against your account, with your reason.</p>
          <Field label="Why do you need it?" hint="Required, e.g. a ticket number.">
            <input aria-label="Reason" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={500} />
          </Field>
          <div className="actions">
            <Button onClick={() => void reveal()} disabled={busy || reason.trim() === ""}>
              Show the password
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
            Password for {revealed.admin_password.account} on {revealed.admin_password.hostname}
            {revealed.admin_password.state === "active" ? "" : ` (${STATE_LABELS[revealed.admin_password.state]})`}:
          </p>
          <pre className="mono">{revealed.password}</pre>
          <p className="hint">Rotate it again once you&apos;re done, so this one stops working.</p>
          <Button variant="quiet" onClick={() => setRevealed(null)}>
            Hide it
          </Button>
        </div>
      ) : null}
    </section>
  );
}
