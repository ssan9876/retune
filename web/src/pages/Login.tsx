import { useState } from "react";
import type { FormEvent } from "react";

import { ApiError } from "../api/client";
import { Button, ErrorNote, Field } from "../components/ui";
import { useSession } from "../session/SessionContext";
import "./Login.css";

export default function Login() {
  const { signIn, needsSetup } = useSession();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [needsCode, setNeedsCode] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await signIn(email, password, code);
    } catch (err) {
      if (err instanceof ApiError && err.code === "totp_required") {
        setNeedsCode(true);
      } else {
        setError(err);
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login">
      <div className="login__panel">
        <h1 className="login__mark">Retune</h1>
        <p className="login__lede">Manage the machines you have enrolled.</p>

        <form onSubmit={submit} noValidate>
          <Field label="Email">
            <input
              type="email"
              autoComplete="username"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </Field>
          <Field label="Password">
            <input
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </Field>
          {needsCode ? (
            <Field label="Authenticator code" hint="Six digits from your authenticator app.">
              <input
                inputMode="numeric"
                autoComplete="one-time-code"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                autoFocus
              />
            </Field>
          ) : null}
          <ErrorNote error={error} />
          <Button
            type="submit"
            variant="primary"
            disabled={busy}
            style={{ marginTop: "var(--space-4)" }}
          >
            {busy ? "Signing in…" : "Sign in"}
          </Button>
        </form>

        {needsSetup ? (
          <div className="login__setup">
            No account exists yet. Create the first one on the server:
            <code>retune-server bootstrap-admin --email you@example.com</code>
          </div>
        ) : null}
      </div>
    </main>
  );
}
