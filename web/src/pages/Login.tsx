import { useState } from "react";
import type { FormEvent } from "react";

import { ApiError } from "../api/client";
import { Icon } from "../components/Icon";
import { Button, ErrorNote, Field } from "../components/ui";
import { useSession } from "../session/SessionContext";
import "./Login.css";

/** SSO_ERRORS turns the code the server puts in ?sso_error= into a sentence.
 * The server never puts the detail in the URL; that is in its log. */
const SSO_ERRORS: Record<string, string> = {
  unauthorized: "Your account is not in a group that may use Retune. Ask an administrator to add you.",
  email_taken:
    "A Retune account with a password already uses your email address, so single sign-on cannot take it " +
    "over. Ask an administrator to change or remove that account.",
  disabled: "Your Retune account is disabled.",
  email_unverified: "Your identity provider says your email address is not verified. Verify it there, then try again.",
  no_email:
    "The identity provider did not say who you are. Ask an administrator to check that it sends an email claim.",
  state: "That sign-in took too long or was started in another window. Try again.",
  provider_error: "The identity provider did not sign you in.",
};

function ssoErrorMessage(code: string): string {
  return SSO_ERRORS[code] ?? "Single sign-on failed. Try again, or ask an administrator to check the server's log.";
}

/** takeSsoError reads ?sso_error= once and removes it from the address bar,
 * so a reload does not show a failure that is already over. */
function takeSsoError(): string | null {
  const params = new URLSearchParams(window.location.search);
  const code = params.get("sso_error");
  if (code === null) return null;
  params.delete("sso_error");
  const rest = params.toString();
  window.history.replaceState(null, "", window.location.pathname + (rest ? `?${rest}` : "") + window.location.hash);
  return code;
}

export default function Login() {
  const { signIn, needsSetup, sso, localLogin } = useSession();
  const [ssoError] = useState(takeSsoError);
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
        <h1 className="login__mark">
          <Icon name="mark" />
          Retune
        </h1>
        <p className="login__lede">Manage the machines you have enrolled.</p>

        <ErrorNote error={ssoError !== null ? ssoErrorMessage(ssoError) : null} />

        {sso !== null ? (
          // A link rather than a fetch: the sign-in is a sequence of full-page
          // redirects through the identity provider and back.
          <a className="button button--primary login__sso" href="/api/admin/v1/oidc/start">
            {sso}
          </a>
        ) : null}

        {sso !== null && localLogin ? <p className="login__or">or sign in with a password</p> : null}

        {localLogin ? (
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
        ) : null}

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
