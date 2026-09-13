import { useState } from "react";

import { api } from "../api/client";
import type { Token } from "../api/types";
import { StatusDot } from "../components/StatusDot";
import { Button, Dialog, EmptyState, ErrorNote, Field, Spinner } from "../components/ui";
import { useList } from "../hooks/useList";
import { useSession } from "../session/SessionContext";

interface CreatedToken {
  id: string;
  token: string;
  label: string;
}

function tokenState(token: Token): string {
  if (token.revoked_at) return "revoked";
  if (token.expires_at && new Date(token.expires_at) <= new Date()) return "expired";
  if (token.max_uses !== undefined && token.use_count >= token.max_uses) return "used up";
  return "active";
}

export default function Tokens() {
  const { canWrite } = useSession();
  const { items, loading, error, reload } = useList<Token>("/tokens");
  const [open, setOpen] = useState(false);
  const [label, setLabel] = useState("");
  const [maxUses, setMaxUses] = useState("");
  const [expiresIn, setExpiresIn] = useState("168");
  const [created, setCreated] = useState<CreatedToken | null>(null);
  const [formError, setFormError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  async function create() {
    setBusy(true);
    setFormError(null);
    try {
      const body: Record<string, unknown> = { label };
      if (maxUses !== "") body.max_uses = Number(maxUses);
      if (expiresIn !== "") body.expires_in_hours = Number(expiresIn);
      setCreated(await api.post<CreatedToken>("/tokens", body));
      setOpen(false);
      setLabel("");
      reload();
    } catch (err) {
      setFormError(err);
    } finally {
      setBusy(false);
    }
  }

  async function revoke(id: string) {
    if (!window.confirm("Revoke this token? Machines cannot enroll with it afterwards.")) return;
    try {
      await api.post(`/tokens/${id}/revoke`);
      reload();
    } catch (err) {
      setFormError(err);
    }
  }

  const installLine = created
    ? `msiexec /i retune-agent.msi SERVER_URL=${window.location.origin} ENROLL_TOKEN=${created.token} /qn`
    : "";

  return (
    <>
      <div className="content__head">
        <h1>Enrollment</h1>
        {canWrite ? (
          <Button variant="primary" onClick={() => setOpen(true)}>
            Create token
          </Button>
        ) : null}
      </div>

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
          <h2>Token for {created.label || "this batch"}</h2>
          <p style={{ fontSize: "var(--text-sm)", color: "var(--ink-muted)" }}>
            Copy it now. It is not stored and cannot be shown again.
          </p>
          <p className="mono" style={{ wordBreak: "break-all" }}>
            {created.token}
          </p>
          <p className="mono" style={{ wordBreak: "break-all", color: "var(--ink-muted)" }}>
            {installLine}
          </p>
          <div className="actions">
            <Button onClick={() => void navigator.clipboard?.writeText(created.token)}>Copy token</Button>
            <Button onClick={() => void navigator.clipboard?.writeText(installLine)}>
              Copy install command
            </Button>
            <Button variant="quiet" onClick={() => setCreated(null)}>
              Done
            </Button>
          </div>
        </section>
      ) : null}

      {loading ? <Spinner /> : null}
      {!loading && items.length === 0 ? (
        <EmptyState title="No enrollment tokens yet.">
          <p>A token lets one or more machines enroll. Create one, then install the agent with it.</p>
        </EmptyState>
      ) : null}

      {items.length > 0 ? (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Label</th>
                <th>State</th>
                <th>Uses</th>
                <th>Expires</th>
                <th>Created by</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {items.map((token) => (
                <tr key={token.id}>
                  <td>{token.label || "—"}</td>
                  <td>
                    <StatusDot
                      status={tokenState(token) === "active" ? "active" : "retired"}
                      label={tokenState(token)}
                    />
                  </td>
                  <td>
                    {token.max_uses === undefined
                      ? `${token.use_count} of unlimited`
                      : `${token.use_count} of ${token.max_uses}`}
                  </td>
                  <td>{token.expires_at ? new Date(token.expires_at).toLocaleString() : "never"}</td>
                  <td>{token.created_by}</td>
                  <td>
                    {canWrite && !token.revoked_at ? (
                      <Button variant="quiet" onClick={() => void revoke(token.id)}>
                        Revoke
                      </Button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      <Dialog title="Create an enrollment token" open={open} onClose={() => setOpen(false)}>
        <Field label="Label" hint="Shown in this list, for example “Office laptops”.">
          <input value={label} onChange={(event) => setLabel(event.target.value)} />
        </Field>
        <Field label="Maximum uses" hint="Leave empty for unlimited.">
          <input
            type="number"
            min={1}
            value={maxUses}
            onChange={(event) => setMaxUses(event.target.value)}
          />
        </Field>
        <Field label="Expires in hours" hint="Leave empty for no expiry.">
          <input
            type="number"
            min={1}
            value={expiresIn}
            onChange={(event) => setExpiresIn(event.target.value)}
          />
        </Field>
        <ErrorNote error={formError} />
        <div className="actions">
          <Button variant="primary" disabled={busy} onClick={() => void create()}>
            {busy ? "Creating…" : "Create"}
          </Button>
          <Button variant="quiet" onClick={() => setOpen(false)}>
            Cancel
          </Button>
        </div>
      </Dialog>
    </>
  );
}
