import { useState } from "react";

import { api } from "../api/client";
import type { Admin } from "../api/types";
import { StatusDot } from "../components/StatusDot";
import { Button, Dialog, ErrorNote, Field, Spinner } from "../components/ui";
import { useList } from "../hooks/useList";
import { useSession } from "../session/SessionContext";

export default function Admins() {
  const { canWrite } = useSession();
  const { items, loading, error, reload } = useList<Admin>("/admins");
  const [addOpen, setAddOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("admin");
  const [formError, setFormError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [otpauth, setOtpauth] = useState<string | null>(null);

  async function add() {
    setBusy(true);
    setFormError(null);
    try {
      await api.post("/admins", { email, password, role });
      setAddOpen(false);
      setEmail("");
      setPassword("");
      reload();
    } catch (err) {
      setFormError(err);
    } finally {
      setBusy(false);
    }
  }

  async function changePassword(admin: Admin) {
    const next = window.prompt(`New password for ${admin.email} (at least 12 characters)`);
    if (!next) return;
    try {
      await api.post(`/admins/${admin.id}/password`, { password: next });
      setFormError(null);
    } catch (err) {
      setFormError(err);
    }
  }

  async function toggleTOTP(admin: Admin) {
    try {
      if (admin.totp_enabled) {
        await api.post(`/admins/${admin.id}/totp`, { enabled: false });
        setOtpauth(null);
      } else {
        const result = await api.post<{ otpauth_url: string }>(`/admins/${admin.id}/totp`, {
          enabled: true,
        });
        setOtpauth(result.otpauth_url);
      }
      reload();
    } catch (err) {
      setFormError(err);
    }
  }

  async function toggleDisabled(admin: Admin) {
    const action = admin.disabled ? "Enable" : "Disable";
    if (!window.confirm(`${action} ${admin.email}?`)) return;
    try {
      await api.post(`/admins/${admin.id}/disabled`, { disabled: !admin.disabled });
      reload();
    } catch (err) {
      setFormError(err);
    }
  }

  return (
    <>
      <div className="content__head">
        <h1>Admins</h1>
        {canWrite ? (
          <Button variant="primary" onClick={() => setAddOpen(true)}>
            Add admin
          </Button>
        ) : null}
      </div>

      <ErrorNote error={error ?? formError} />

      {otpauth ? (
        <section
          style={{
            border: "1px solid var(--rule)",
            borderRadius: "var(--radius)",
            padding: "var(--space-4)",
            marginBottom: "var(--space-6)",
            background: "var(--surface)",
          }}
        >
          <h2>Authenticator set up</h2>
          <p style={{ fontSize: "var(--text-sm)", color: "var(--ink-muted)" }}>
            Add this to an authenticator app now. It is shown only once.
          </p>
          <p className="mono" style={{ wordBreak: "break-all" }}>
            {otpauth}
          </p>
          <div className="actions">
            <Button onClick={() => void navigator.clipboard?.writeText(otpauth)}>Copy setup URL</Button>
            <Button variant="quiet" onClick={() => setOtpauth(null)}>
              Done
            </Button>
          </div>
        </section>
      ) : null}

      {loading ? <Spinner /> : null}

      {items.length > 0 ? (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Email</th>
                <th>Role</th>
                <th>Authenticator</th>
                <th>Account</th>
                <th>Last sign-in</th>
                {canWrite ? <th></th> : null}
              </tr>
            </thead>
            <tbody>
              {items.map((admin) => (
                <tr key={admin.id}>
                  <td>{admin.email}</td>
                  <td>{admin.role === "admin" ? "Admin" : "Read-only"}</td>
                  <td>{admin.totp_enabled ? "On" : "Off"}</td>
                  <td>
                    <StatusDot
                      status={admin.disabled ? "retired" : "active"}
                      label={admin.disabled ? "disabled" : "enabled"}
                    />
                  </td>
                  <td>{admin.last_login_at ? new Date(admin.last_login_at).toLocaleString() : "never"}</td>
                  {canWrite ? (
                    <td>
                      <div className="actions" style={{ marginTop: 0 }}>
                        <Button variant="quiet" onClick={() => void changePassword(admin)}>
                          Change password
                        </Button>
                        <Button variant="quiet" onClick={() => void toggleTOTP(admin)}>
                          {admin.totp_enabled ? "Turn off authenticator" : "Set up authenticator"}
                        </Button>
                        <Button variant="quiet" onClick={() => void toggleDisabled(admin)}>
                          {admin.disabled ? "Enable account" : "Disable account"}
                        </Button>
                      </div>
                    </td>
                  ) : null}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      <Dialog title="Add an admin" open={addOpen} onClose={() => setAddOpen(false)}>
        <Field label="Email">
          <input type="email" value={email} onChange={(event) => setEmail(event.target.value)} />
        </Field>
        <Field label="Password" hint="At least 12 characters.">
          <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} />
        </Field>
        <Field label="Role">
          <select value={role} onChange={(event) => setRole(event.target.value)}>
            <option value="admin">Admin — can read and change everything</option>
            <option value="read_only">Read-only — can look, not change</option>
          </select>
        </Field>
        <ErrorNote error={formError} />
        <div className="actions">
          <Button variant="primary" disabled={busy} onClick={() => void add()}>
            {busy ? "Adding…" : "Add admin"}
          </Button>
          <Button variant="quiet" onClick={() => setAddOpen(false)}>
            Cancel
          </Button>
        </div>
      </Dialog>
    </>
  );
}
