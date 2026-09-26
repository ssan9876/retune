import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

import { ApiError, api, onUnauthenticated, setCsrfToken } from "../api/client";
import type { Admin, SessionResponse, Setup } from "../api/types";

interface SessionValue {
  admin: Admin | null;
  loading: boolean;
  needsSetup: boolean;
  /** sso is the SSO button's text, or null when single sign-on is off. */
  sso: string | null;
  /** localLogin is false when only SSO may sign in. */
  localLogin: boolean;
  canWrite: boolean;
  /** canOperate: admin or helpdesk - lock, restart, collect logs, reveal keys. */
  canOperate: boolean;
  /** signingRequired: scripts and wipes need an operations signature. */
  signingRequired: boolean;
  /** agentDownloadUrl: where the agent installers are published. */
  agentDownloadUrl: string | null;
  startupError: unknown;
  retryStartup: () => void;
  signIn: (email: string, password: string, totpCode?: string) => Promise<void>;
  signOut: () => Promise<void>;
}

const SessionContext = createContext<SessionValue | null>(null);

/** SessionProvider holds the signed-in admin and the CSRF token. */
export function SessionProvider({ children }: { children: ReactNode }) {
  const [admin, setAdmin] = useState<Admin | null>(null);
  const [loading, setLoading] = useState(true);
  const [needsSetup, setNeedsSetup] = useState(false);
  const [sso, setSso] = useState<string | null>(null);
  const [localLogin, setLocalLogin] = useState(true);
  const [signingRequired, setSigningRequired] = useState(false);
  const [agentDownloadUrl, setAgentDownloadUrl] = useState<string | null>(null);
  const [startupError, setStartupError] = useState<unknown>(null);
  const [retryToken, setRetryToken] = useState(0);

  const clear = useCallback(() => {
    setAdmin(null);
    setCsrfToken(null);
  }, []);

  useEffect(() => {
    onUnauthenticated(clear);
    return () => onUnauthenticated(null);
  }, [clear]);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const session = await api.get<SessionResponse>("/session");
        if (cancelled) return;
        setCsrfToken(session.csrf_token);
        setAdmin(session.admin);
        setSigningRequired(session.signing_required ?? false);
        setAgentDownloadUrl(session.agent_download_url ?? null);
        setStartupError(null);
      } catch (error) {
        if (!cancelled) {
          clear();
          if (error instanceof ApiError && error.status === 401) setStartupError(null);
          else setStartupError(error);
        }
      }
      try {
        const setup = await api.get<Setup>("/setup");
        if (!cancelled) {
          setNeedsSetup(setup.needs_setup);
          setSso(setup.sso?.enabled ? (setup.sso.display_name ?? "Sign in with SSO") : null);
          setLocalLogin(setup.local_login ?? true);
        }
      } catch {
        // The setup hint is optional; ignore a failure here.
      }
      if (!cancelled) setLoading(false);
    })();
    return () => {
      cancelled = true;
    };
  }, [clear, retryToken]);

  const retryStartup = useCallback(() => {
    setLoading(true);
    setRetryToken((token) => token + 1);
  }, []);

  const signIn = useCallback(async (email: string, password: string, totpCode?: string) => {
    const session = await api.post<SessionResponse>("/session", {
      email,
      password,
      totp_code: totpCode ?? "",
    });
    setCsrfToken(session.csrf_token);
    setAdmin(session.admin);
    setSigningRequired(session.signing_required ?? false);
    setAgentDownloadUrl(session.agent_download_url ?? null);
    setNeedsSetup(false);
  }, []);

  const signOut = useCallback(async () => {
    try {
      await api.del("/session");
    } catch (error) {
      // An expired session is already signed out.
      if (!(error instanceof ApiError) || error.status !== 401) throw error;
    }
    clear();
  }, [clear]);

  const value = useMemo<SessionValue>(
    () => ({
      admin,
      loading,
      needsSetup,
      sso,
      localLogin,
      canWrite: admin?.role === "admin",
      canOperate: admin?.role === "admin" || admin?.role === "helpdesk",
      signingRequired,
      agentDownloadUrl,
      startupError,
      retryStartup,
      signIn,
      signOut,
    }),
    [
      admin,
      loading,
      needsSetup,
      sso,
      localLogin,
      signingRequired,
      agentDownloadUrl,
      startupError,
      retryStartup,
      signIn,
      signOut,
    ],
  );

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

/** useSession reads the session; it throws outside a SessionProvider. */
export function useSession(): SessionValue {
  const value = useContext(SessionContext);
  if (!value) throw new Error("useSession must be used inside a SessionProvider");
  return value;
}
