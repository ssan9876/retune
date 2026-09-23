import { useState } from "react";

import { api } from "../api/client";
import type { ApiToken } from "../api/types";
import { StatusDot } from "../components/StatusDot";
import { Button, Dialog, EmptyState, ErrorNote, Field, Spinner } from "../components/ui";
import { useList } from "../hooks/useList";
import { useSession } from "../session/SessionContext";
import { relative } from "./Devices";

interface CreatedToken {
  token: string;
  api_token: ApiToken;
}

function tokenState(token: ApiToken): "active" | "revoked" | "expired" {
  if (token.revoked_at) return "revoked";
  if (new Date(token.expires_at) <= new Date()) return "expired";
  return "active";
}

export default function ApiTokens() {
  const { canWrite } = useSession();
  const { items, loading, error, reload } = useList<ApiToken>("/api-tokens");
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [role, setRole] = useState("read_only");
  const [days, setDays] = useState("90");
  const [created, setCreated] = useState<CreatedToken | null>(null);
  const [formError, setFormError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  async function create() {
    setBusy(true);
    setFormError(null);
    try {
      setCreated(
        await api.post<CreatedToken>("/api-tokens", { name, role, expires_in_days: Number(days) || undefined }),
      );
      setOpen(false);
      setName("");
      reload();
    } catch (err) {
      setFormError(err);
    } finally {
      setBusy(false);
    }
  }

  async function revoke(token: ApiToken) {
    if (!window.confirm(`Revoke "${token.name}"? Anything using it stops working at once.`)) return;
    try {
      await api.post(`/api-tokens/${token.id}/revoke`);
      reload();
    } catch (err) {
      setFormError(err);
    }
  }

  return (
    <>
      <div className="content__head">
        <h1>API tokens</h1>
        {canWrite ? (
          <Button variant="primary" onClick={() => setOpen(true)}>
            Create token
          </Button>
        ) : null}
      </div>

      <p className="hint" style={{ marginTop: 0 }}>
        A token lets a script or another system call the admin API: send it as{" "}
        <span className="mono">Authorization: Bearer …</span>. It stops working when it expires, when it is revoked, or
        when the admin who made it is disabled. Tokens cannot manage admins or tokens, or reveal recovery keys.
      </p>

      <ErrorNote error={error ?? formError} />

      {created ? (
        <section
          style={{
            border: "1px solid var(--rule)",
            borderRadius: "var(--radius)",
            padding: "var(--space-4)",
            marginBottom: "var(--space-6)",
            background: "var(--surface)",
          }}
        >
          <h2>Token for {created.api_token.name}</h2>
          <p className="hint">Copy it now. Only a hash of it is kept, so it cannot be shown again.</p>
          <p className="mono" style={{ wordBreak: "break-all" }}>
            {created.token}
          </p>
          <div className="actions">
            <Button onClick={() => void navigator.clipboard?.writeText(created.token)}>Copy token</Button>
            <Button variant="quiet" onClick={() => setCreated(null)}>
              Done
            </Button>
          </div>
        </section>
      ) : null}

      {loading ? <Spinner /> : null}
      {!loading && items.length === 0 ? (
        <EmptyState title="No API tokens yet.">
          <p>Create one for each script or system that needs to call Retune, so each can be revoked on its own.</p>
        </EmptyState>
      ) : null}

      {items.length > 0 ? (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Access</th>
                <th>State</th>
                <th>Last used</th>
                <th>Expires</th>
                <th>Created by</th>
                {canWrite ? <th></th> : null}
              </tr>
            </thead>
            <tbody>
              {items.map((token) => {
                const state = tokenState(token);
                return (
                  <tr key={token.id}>
                    <td>{token.name}</td>
                    <td>{token.role === "admin" ? "Admin" : "Read-only"}</td>
                    <td>
                      <StatusDot status={state === "active" ? "active" : "retired"} label={state} />
                    </td>
                    <td>{token.last_used_at ? relative(token.last_used_at) : "never"}</td>
                    <td>{new Date(token.expires_at).toLocaleDateString()}</td>
                    <td>{token.created_by}</td>
                    {canWrite ? (
                      <td>
                        {state !== "revoked" ? (
                          <Button variant="quiet" onClick={() => void revoke(token)}>
                            Revoke
                          </Button>
                        ) : null}
                      </td>
                    ) : null}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : null}

      <Dialog title="Create an API token" open={open} onClose={() => setOpen(false)}>
        <Field label="Name" hint="What will use it, e.g. ServiceNow or the nightly report.">
          <input value={name} maxLength={100} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Access">
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="read_only">Read-only</option>
            <option value="helpdesk">Helpdesk: device actions, no code or policy</option>
            <option value="admin">Admin: can change things</option>
          </select>
        </Field>
        <Field label="Expires in (days)" hint="1 to 365.">
          <input type="number" min={1} max={365} value={days} onChange={(e) => setDays(e.target.value)} />
        </Field>
        <ErrorNote error={formError} />
        <div className="actions">
          <Button variant="primary" disabled={busy || name.trim() === ""} onClick={() => void create()}>
            Create token
          </Button>
          <Button variant="quiet" onClick={() => setOpen(false)}>
            Cancel
          </Button>
        </div>
      </Dialog>
    </>
  );
}
