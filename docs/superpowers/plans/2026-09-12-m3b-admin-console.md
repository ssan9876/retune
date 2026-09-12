# M3b: Admin Console Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An administrator opens the server in a browser, signs in, and manages devices, commands, enrollment tokens, admins and the audit log from a single console the server itself serves.

**Architecture:** A Vite + React + TypeScript app in `web/`, built to `web/dist` and embedded in the server binary with `go:embed`. The server serves it at `/` with SPA fallback, keeping `/api/...` for the APIs. The app talks to the M3a admin API with cookies plus the `X-CSRF-Token` header, and keeps the signed-in admin in one session context.

**Tech Stack:** React 19, TypeScript, Vite, react-router, Vitest + Testing Library (jsdom), `@fontsource/ibm-plex-sans` and `@fontsource/ibm-plex-mono`, Go `embed`.

**Spec:** `docs/superpowers/specs/2026-09-12-core-platform-design.md` §12 (console screens); API from `docs/superpowers/plans/2026-09-12-m3a-admin-api-auth.md`.

## Design direction

The console is for administrators running a Windows fleet: the work is identifying machines, acting on them, and proving what happened. The visual language follows that, not a generic dashboard kit.

- **Color.** Paper `#F7F8FA`, ink `#1B1F24`, rule `#D8DCE2`, primary `#5B5BD6`. Status colors carry meaning and are used nowhere else: active `#12876F`, stale `#B4690E`, retired/failed `#C4403A`. Dark mode swaps the surfaces (`#14161A` ground, `#E6E8EB` ink, `#2A2F36` rule) and keeps the same hues.
- **Type.** IBM Plex Sans for the interface; IBM Plex Mono for machine identifiers and command output, because those get compared character by character. Both are bundled, so an on-prem server works offline. Type scale: 12 / 13 / 15 / 18 / 24 / 32 px, line-height 1.5 for text and 1.3 for headings.
- **Layout.** A persistent left rail (200px, labels visible), a command bar holding search and the page's actions, then content. Tables are dense (36px rows), with a sticky header; identifiers are mono, counts are right-aligned.
- **The one bold element.** At the top of Devices, a single proportional fleet bar segmented by status, where each segment is the filter for that status. Everything around it stays quiet.
- **Motion.** Only in response to an action, 120–160ms, and disabled under `prefers-reduced-motion`.
- **Copy.** Plain and active: "Run script", "Retire device", "Sign in". Empty states say what to do next: "No devices yet. Create an enrollment token, then install the agent on a machine."

## Global Constraints

- The console is served by the Go binary from embedded files; no external CDN, font host or analytics. It must work fully offline.
- Every unsafe request sends `X-CSRF-Token`; a `401` sends the user to the login screen; a `403 forbidden` shows the action as unavailable rather than failing silently.
- Read-only admins see the same data but no write actions.
- Accessibility floor: visible keyboard focus, labelled form fields, one `<h1>` per screen, colour never the only signal (status dots carry text too), usable at 400px wide.
- TypeScript `strict` is on; no `any` in committed code.
- `npm run build` must produce `web/dist`; `npm run test` runs Vitest; both pass before each commit that touches `web/`.
- Go side: `go vet ./...` and `go test ./...` pass; the server must still start when the console has not been built, answering with a clear message instead of a panic.

## File Structure

```
web/
  package.json, tsconfig.json, vite.config.ts, index.html
  src/main.tsx                 app entry, router
  src/styles/tokens.css        colors, type scale, spacing, dark mode
  src/styles/base.css          resets and element defaults
  src/api/client.ts            fetch wrapper: CSRF, errors, 401 handling
  src/api/types.ts             API response types
  src/session/SessionContext.tsx  current admin, login, logout
  src/components/              Shell, Rail, CommandBar, Table, StatusDot,
                               FleetBar, Pagination, Field, Button, Dialog,
                               EmptyState, Toast
  src/pages/Login.tsx          sign-in (password + optional TOTP)
  src/pages/Devices.tsx        list, fleet bar, search, paging
  src/pages/DeviceDetail.tsx   identity, inventory, software, commands, actions
  src/pages/Commands.tsx       list + detail drawer
  src/pages/Tokens.tsx         list, create (shows token once), revoke
  src/pages/Audit.tsx          paged audit log
  src/pages/Admins.tsx         list, create, password, TOTP, disable
  src/test/setup.ts            Testing Library setup
internal/server/console/
  console.go                   go:embed dist, SPA handler, security headers
  console_test.go
internal/server/app/app.go     MODIFY: mount the console at /
```

---

### Task 1: Scaffold the console and its design tokens

**Files:**
- Create: `web/package.json`, `web/tsconfig.json`, `web/tsconfig.node.json`, `web/vite.config.ts`, `web/index.html`, `web/.gitignore`, `web/src/main.tsx`, `web/src/App.tsx`, `web/src/styles/tokens.css`, `web/src/styles/base.css`, `web/src/test/setup.ts`, `web/src/styles/tokens.test.ts`
- Modify: `.gitignore` (ignore `web/node_modules` and `web/dist`)

**Interfaces:**
- Produces: a Vite app that builds to `web/dist`, `npm run dev` proxying `/api` to `https://localhost:8443`, `npm run test` running Vitest, and the token stylesheet every component uses

- [ ] **Step 1: Create the project**

```bash
cd web
npm create vite@latest . -- --template react-ts
npm install
npm install react-router-dom @fontsource/ibm-plex-sans @fontsource/ibm-plex-mono
npm install -D vitest jsdom @testing-library/react @testing-library/user-event @testing-library/jest-dom
```

If `npm create` refuses to run in a non-empty directory, create the files by hand from the contents below.

- [ ] **Step 2: Configure Vite, TypeScript and tests**

`web/vite.config.ts`:

```ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", emptyOutDir: true },
  server: {
    proxy: {
      // `npm run dev` talks to a locally running retune-server.
      "/api": { target: "https://localhost:8443", changeOrigin: true, secure: false },
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    globals: true,
    css: true,
  },
});
```

`web/src/test/setup.ts`:

```ts
import "@testing-library/jest-dom/vitest";
```

`web/package.json` scripts:

```json
  "scripts": {
    "dev": "vite",
    "build": "tsc -b && vite build",
    "preview": "vite preview",
    "test": "vitest run",
    "test:watch": "vitest"
  },
```

`web/.gitignore`:

```gitignore
node_modules/
dist/
```

Add to the repository `.gitignore`:

```gitignore
/web/node_modules/
/web/dist/
```

- [ ] **Step 3: Write the design tokens**

`web/src/styles/tokens.css`:

```css
:root {
  /* Surfaces and text. Light is the default; dark mirrors it below. */
  --paper: #f7f8fa;
  --surface: #ffffff;
  --surface-sunken: #eef0f4;
  --ink: #1b1f24;
  --ink-muted: #5c6570;
  --rule: #d8dce2;

  /* One primary, used for actions and focus only. */
  --primary: #5b5bd6;
  --primary-ink: #ffffff;
  --primary-wash: #ecebfb;

  /* Status carries meaning; never use these for decoration. */
  --status-active: #12876f;
  --status-stale: #b4690e;
  --status-retired: #c4403a;
  --status-neutral: #6b7481;

  /* Type scale */
  --text-xs: 0.75rem;
  --text-sm: 0.8125rem;
  --text-base: 0.9375rem;
  --text-lg: 1.125rem;
  --text-xl: 1.5rem;
  --text-2xl: 2rem;

  --font-sans: "IBM Plex Sans", system-ui, sans-serif;
  --font-mono: "IBM Plex Mono", ui-monospace, "Cascadia Mono", monospace;

  /* Spacing: a 4px base */
  --space-1: 0.25rem;
  --space-2: 0.5rem;
  --space-3: 0.75rem;
  --space-4: 1rem;
  --space-6: 1.5rem;
  --space-8: 2rem;

  --radius: 6px;
  --rail-width: 200px;
  --row-height: 36px;
  --shadow-raised: 0 1px 2px rgba(27, 31, 36, 0.08), 0 4px 12px rgba(27, 31, 36, 0.06);
  --transition: 140ms ease;
}

@media (prefers-color-scheme: dark) {
  :root {
    --paper: #14161a;
    --surface: #1b1e24;
    --surface-sunken: #101216;
    --ink: #e6e8eb;
    --ink-muted: #9aa4b1;
    --rule: #2a2f36;
    --primary: #8b8bf0;
    --primary-ink: #14161a;
    --primary-wash: #23234a;
    --status-active: #3fbfa0;
    --status-stale: #d99a3f;
    --status-retired: #e0655e;
    --status-neutral: #8b95a3;
    --shadow-raised: 0 1px 2px rgba(0, 0, 0, 0.5), 0 4px 12px rgba(0, 0, 0, 0.35);
  }
}

@media (prefers-reduced-motion: reduce) {
  :root {
    --transition: 0ms;
  }
}
```

`web/src/styles/base.css`:

```css
@import "@fontsource/ibm-plex-sans/400.css";
@import "@fontsource/ibm-plex-sans/500.css";
@import "@fontsource/ibm-plex-sans/600.css";
@import "@fontsource/ibm-plex-mono/400.css";
@import "./tokens.css";

*,
*::before,
*::after {
  box-sizing: border-box;
}

body {
  margin: 0;
  background: var(--paper);
  color: var(--ink);
  font-family: var(--font-sans);
  font-size: var(--text-base);
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}

h1,
h2,
h3 {
  line-height: 1.3;
  margin: 0;
  font-weight: 600;
}

h1 {
  font-size: var(--text-xl);
}

h2 {
  font-size: var(--text-lg);
}

code,
.mono {
  font-family: var(--font-mono);
  font-size: 0.9em;
}

a {
  color: var(--primary);
}

:focus-visible {
  outline: 2px solid var(--primary);
  outline-offset: 2px;
  border-radius: 3px;
}

button {
  font: inherit;
}

table {
  border-collapse: collapse;
  width: 100%;
}

th,
td {
  text-align: left;
  padding: 0 var(--space-3);
  height: var(--row-height);
  border-bottom: 1px solid var(--rule);
  font-size: var(--text-sm);
}

th {
  color: var(--ink-muted);
  font-weight: 500;
  position: sticky;
  top: 0;
  background: var(--surface);
  z-index: 1;
}

td.numeric,
th.numeric {
  text-align: right;
  font-variant-numeric: tabular-nums;
}
```

- [ ] **Step 4: Write the entry point and a token test**

`web/index.html`:

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Retune</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

`web/src/main.tsx`:

```tsx
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";

import App from "./App";
import "./styles/base.css";

const root = document.getElementById("root");
if (!root) throw new Error("missing #root element");

createRoot(root).render(
  <StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </StrictMode>,
);
```

`web/src/App.tsx` (a placeholder until Task 4 adds routes):

```tsx
export default function App() {
  return <h1>Retune</h1>;
}
```

`web/src/styles/tokens.test.ts`:

```ts
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const tokens = readFileSync(new URL("./tokens.css", import.meta.url), "utf8");

describe("design tokens", () => {
  it("defines the status colors used across the console", () => {
    for (const token of ["--status-active", "--status-stale", "--status-retired"]) {
      expect(tokens).toContain(token);
    }
  });

  it("has a dark mode for every surface token", () => {
    const [, dark] = tokens.split("@media (prefers-color-scheme: dark)");
    for (const token of ["--paper", "--surface", "--ink", "--rule", "--primary"]) {
      expect(dark).toContain(token);
    }
  });

  it("disables motion when the viewer asks for less", () => {
    expect(tokens).toContain("prefers-reduced-motion");
    expect(tokens.slice(tokens.indexOf("prefers-reduced-motion"))).toContain("--transition: 0ms");
  });
});
```

- [ ] **Step 5: Verify**

```bash
cd web && npm run test && npm run build
```

Expected: the token tests pass and `web/dist/index.html` exists.

- [ ] **Step 6: Commit**

```bash
git add .gitignore web
git commit -m "feat(console): scaffold the Vite console with design tokens"
```

---

### Task 2: API client and session context

**Files:**
- Create: `web/src/api/types.ts`, `web/src/api/client.ts`, `web/src/api/client.test.ts`, `web/src/session/SessionContext.tsx`, `web/src/session/SessionContext.test.tsx`

**Interfaces:**
- Consumes: the M3a admin API
- Produces:
  - `api.get<T>(path)`, `api.post<T>(path, body?)`, `api.del<T>(path)`; every unsafe call sends `X-CSRF-Token` from `setCsrfToken`
  - `ApiError { status: number; code: string; message: string }`, thrown for any non-2xx
  - `setCsrfToken(token: string | null)`, `onUnauthenticated(handler)` — the session context uses this to drop back to the login screen
  - `SessionProvider`, `useSession(): { admin: Admin | null; loading: boolean; needsSetup: boolean; signIn(email, password, code?): Promise<void>; signOut(): Promise<void>; canWrite: boolean }`
  - Types: `Admin`, `Device`, `DeviceDetail`, `Command`, `CommandResult`, `Token`, `AuditEntry`, `ListResponse<T>`

- [ ] **Step 1: Write the failing tests**

`web/src/api/client.test.ts`:

```ts
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError, api, onUnauthenticated, setCsrfToken } from "./client";

const fetchMock = vi.fn();

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
  setCsrfToken(null);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("api client", () => {
  it("gets JSON from the admin API", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ items: [], total: 0 }));
    const result = await api.get<{ total: number }>("/devices");
    expect(result.total).toBe(0);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/admin/v1/devices");
    expect(init.credentials).toBe("same-origin");
  });

  it("sends the CSRF token on unsafe requests only", async () => {
    setCsrfToken("token-1");
    fetchMock.mockResolvedValue(jsonResponse({}));
    await api.get("/devices");
    expect(fetchMock.mock.calls[0][1].headers["X-CSRF-Token"]).toBeUndefined();

    await api.post("/tokens", { label: "office" });
    const init = fetchMock.mock.calls[1][1];
    expect(init.method).toBe("POST");
    expect(init.headers["X-CSRF-Token"]).toBe("token-1");
    expect(JSON.parse(init.body)).toEqual({ label: "office" });
  });

  it("throws ApiError with the server's code and message", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ code: "invalid_transition", message: "device is retired" }, 409),
    );
    await expect(api.post("/devices/1/retire")).rejects.toMatchObject({
      status: 409,
      code: "invalid_transition",
      message: "device is retired",
    });
    await expect(api.post("/devices/1/retire")).rejects.toBeInstanceOf(ApiError);
  });

  it("notifies the session when the server says we are signed out", async () => {
    const handler = vi.fn();
    onUnauthenticated(handler);
    fetchMock.mockResolvedValue(jsonResponse({ code: "unauthenticated", message: "sign in" }, 401));
    await expect(api.get("/devices")).rejects.toBeInstanceOf(ApiError);
    expect(handler).toHaveBeenCalledOnce();
    onUnauthenticated(null);
  });

  it("returns nothing for 204 responses", async () => {
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }));
    await expect(api.del("/session")).resolves.toBeUndefined();
  });
});
```

`web/src/session/SessionContext.test.tsx`:

```tsx
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { SessionProvider, useSession } from "./SessionContext";

const fetchMock = vi.fn();

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
});

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const admin = {
  id: "1",
  email: "ops@example.com",
  role: "admin",
  totp_enabled: false,
  disabled: false,
  created_at: "2026-09-12T12:00:00Z",
};

function Probe() {
  const { admin: current, loading, needsSetup, signIn, signOut, canWrite } = useSession();
  if (loading) return <p>Checking…</p>;
  return (
    <div>
      <p>{current ? `Signed in as ${current.email}` : "Signed out"}</p>
      <p>{needsSetup ? "Needs setup" : "Ready"}</p>
      <p>{canWrite ? "Can write" : "Read only"}</p>
      <button onClick={() => signIn("ops@example.com", "correct horse battery")}>Sign in</button>
      <button onClick={() => signOut()}>Sign out</button>
    </div>
  );
}

describe("SessionProvider", () => {
  it("starts signed out and signs in", async () => {
    fetchMock
      .mockResolvedValueOnce(json({ code: "unauthenticated", message: "sign in" }, 401))
      .mockResolvedValueOnce(json({ needs_setup: false }))
      .mockResolvedValueOnce(json({ admin, csrf_token: "csrf-1", expires_at: "2026-09-13T00:00:00Z" }));

    render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await screen.findByText("Signed out");
    expect(screen.getByText("Ready")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await screen.findByText("Signed in as ops@example.com");
    expect(screen.getByText("Can write")).toBeInTheDocument();
  });

  it("reports a read-only admin and the first-run state", async () => {
    fetchMock
      .mockResolvedValueOnce(json({ admin: { ...admin, role: "read_only" }, csrf_token: "c", expires_at: "x" }))
      .mockResolvedValueOnce(json({ needs_setup: true }));

    render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await screen.findByText("Signed in as ops@example.com");
    expect(screen.getByText("Read only")).toBeInTheDocument();
  });

  it("signs out", async () => {
    fetchMock
      .mockResolvedValueOnce(json({ admin, csrf_token: "csrf-1", expires_at: "x" }))
      .mockResolvedValueOnce(json({ needs_setup: false }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));

    render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await screen.findByText("Signed in as ops@example.com");
    await userEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await waitFor(() => expect(screen.getByText("Signed out")).toBeInTheDocument());
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd web && npm run test
```

Expected: FAIL — `./client` and `./SessionContext` do not exist.

- [ ] **Step 3: Write the types**

`web/src/api/types.ts`:

```ts
export type Role = "admin" | "read_only";

export interface Admin {
  id: string;
  email: string;
  role: Role;
  totp_enabled: boolean;
  disabled: boolean;
  created_at: string;
  last_login_at?: string;
}

export interface Device {
  id: string;
  hostname: string;
  status: "active" | "retired" | "replaced" | "unenrolled";
  os_version: string;
  os_build: string;
  manufacturer: string;
  model: string;
  serial: string;
  smbios_uuid: string;
  agent_version: string;
  enrolled_at: string;
  last_seen_at?: string;
  cert_expires_at: string;
  stale: boolean;
}

export interface Software {
  name: string;
  version: string;
  publisher: string;
  install_date: string;
  scope: string;
}

export interface Inventory {
  collected_at: string;
  received_at: string;
  ram_gb: number;
  disk_free_gb: number;
  document: unknown;
}

export interface Command {
  id: string;
  device_id: string;
  type: string;
  status: string;
  payload: unknown;
  created_by: string;
  created_at: string;
  delivered_at?: string;
  started_at?: string;
  completed_at?: string;
  expires_at: string;
}

export interface CommandResult {
  exit_code: number;
  stdout: string;
  stderr: string;
  stdout_truncated: boolean;
  stderr_truncated: boolean;
  error: string;
  started_at: string;
  finished_at: string;
}

export interface DeviceDetail {
  device: Device;
  inventory: Inventory | null;
  software: Software[];
  commands: Command[];
}

export interface Token {
  id: string;
  label: string;
  max_uses?: number;
  use_count: number;
  expires_at?: string;
  revoked_at?: string;
  created_by: string;
  created_at: string;
}

export interface AuditEntry {
  actor: string;
  action: string;
  target_kind: string;
  target_id: string;
  details: Record<string, unknown>;
  at: string;
}

export interface ListResponse<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface SessionResponse {
  admin: Admin;
  csrf_token: string;
  expires_at: string;
}
```

- [ ] **Step 4: Write the client**

`web/src/api/client.ts`:

```ts
const BASE = "/api/admin/v1";

/** ApiError carries the server's error code so callers can branch on it. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

let csrfToken: string | null = null;
let unauthenticatedHandler: (() => void) | null = null;

/** setCsrfToken stores the token the server issued at sign-in. */
export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

/** onUnauthenticated registers the callback used when a session has ended. */
export function onUnauthenticated(handler: (() => void) | null): void {
  unauthenticatedHandler = handler;
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  const init: RequestInit & { headers: Record<string, string> } = {
    method,
    headers,
    credentials: "same-origin",
  };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  if (method !== "GET" && method !== "HEAD" && csrfToken) {
    headers["X-CSRF-Token"] = csrfToken;
  }

  const response = await fetch(BASE + path, init);
  if (response.status === 204) {
    return undefined as T;
  }
  const text = await response.text();
  const payload: unknown = text ? JSON.parse(text) : {};
  if (!response.ok) {
    const { code, message } = payload as { code?: string; message?: string };
    if (response.status === 401) {
      unauthenticatedHandler?.();
    }
    throw new ApiError(response.status, code ?? "error", message ?? response.statusText);
  }
  return payload as T;
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body),
  del: <T>(path: string) => request<T>("DELETE", path),
};
```

- [ ] **Step 5: Write the session context**

`web/src/session/SessionContext.tsx`:

```tsx
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

import { ApiError, api, onUnauthenticated, setCsrfToken } from "../api/client";
import type { Admin, SessionResponse } from "../api/types";

interface SessionValue {
  admin: Admin | null;
  loading: boolean;
  needsSetup: boolean;
  canWrite: boolean;
  signIn: (email: string, password: string, totpCode?: string) => Promise<void>;
  signOut: () => Promise<void>;
}

const SessionContext = createContext<SessionValue | null>(null);

/** SessionProvider holds the signed-in admin and the CSRF token. */
export function SessionProvider({ children }: { children: ReactNode }) {
  const [admin, setAdmin] = useState<Admin | null>(null);
  const [loading, setLoading] = useState(true);
  const [needsSetup, setNeedsSetup] = useState(false);

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
    (async () => {
      try {
        const session = await api.get<SessionResponse>("/session");
        if (cancelled) return;
        setCsrfToken(session.csrf_token);
        setAdmin(session.admin);
      } catch {
        if (!cancelled) clear();
      }
      try {
        const setup = await api.get<{ needs_setup: boolean }>("/setup");
        if (!cancelled) setNeedsSetup(setup.needs_setup);
      } catch {
        // The setup hint is optional; ignore a failure here.
      }
      if (!cancelled) setLoading(false);
    })();
    return () => {
      cancelled = true;
    };
  }, [clear]);

  const signIn = useCallback(async (email: string, password: string, totpCode?: string) => {
    const session = await api.post<SessionResponse>("/session", {
      email,
      password,
      totp_code: totpCode ?? "",
    });
    setCsrfToken(session.csrf_token);
    setAdmin(session.admin);
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
      canWrite: admin?.role === "admin",
      signIn,
      signOut,
    }),
    [admin, loading, needsSetup, signIn, signOut],
  );

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

/** useSession reads the session; it throws outside a SessionProvider. */
export function useSession(): SessionValue {
  const value = useContext(SessionContext);
  if (!value) throw new Error("useSession must be used inside a SessionProvider");
  return value;
}
```

- [ ] **Step 6: Run the tests to verify they pass**

```bash
cd web && npm run test
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add web
git commit -m "feat(console): API client with CSRF handling and session context"
```

---

### Task 3: UI kit and the sign-in screen

**Files:**
- Create: `web/src/components/ui.tsx`, `web/src/components/ui.css`, `web/src/components/StatusDot.tsx`, `web/src/pages/Login.tsx`, `web/src/pages/Login.css`, `web/src/pages/Login.test.tsx`

**Interfaces:**
- Consumes: Task 2 session context
- Produces:
  - `Button({ variant?: "primary" | "quiet" | "danger", ... })`, `Field({ label, hint?, error?, children })`, `EmptyState({ title, children })`, `Spinner`, `Dialog({ title, open, onClose, children })`, `ErrorNote({ error })`
  - `StatusDot({ status, label? })` — a coloured dot plus text, so colour is never the only signal
  - `Login` — email, password, and an authenticator field that appears when the server asks for it; shows the first-run hint when no admin exists yet

- [ ] **Step 1: Write the failing test**

`web/src/pages/Login.test.tsx`:

```tsx
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "../api/client";
import Login from "./Login";

const signIn = vi.fn();
let needsSetup = false;

vi.mock("../session/SessionContext", () => ({
  useSession: () => ({
    admin: null,
    loading: false,
    needsSetup,
    canWrite: false,
    signIn,
    signOut: vi.fn(),
  }),
}));

beforeEach(() => {
  signIn.mockReset();
  needsSetup = false;
});

describe("Login", () => {
  it("signs in with an email and password", async () => {
    signIn.mockResolvedValue(undefined);
    render(<Login />);

    await userEvent.type(screen.getByLabelText("Email"), "ops@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "correct horse battery");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

    expect(signIn).toHaveBeenCalledWith("ops@example.com", "correct horse battery", "");
    expect(screen.queryByLabelText("Authenticator code")).not.toBeInTheDocument();
  });

  it("asks for the authenticator code when the server requires one", async () => {
    signIn.mockRejectedValueOnce(new ApiError(401, "totp_required", "enter your authenticator code"));
    render(<Login />);

    await userEvent.type(screen.getByLabelText("Email"), "ops@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "correct horse battery");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

    const code = await screen.findByLabelText("Authenticator code");
    signIn.mockResolvedValueOnce(undefined);
    await userEvent.type(code, "123456");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(signIn).toHaveBeenLastCalledWith("ops@example.com", "correct horse battery", "123456");
  });

  it("shows why a sign-in failed", async () => {
    signIn.mockRejectedValue(new ApiError(401, "invalid_credentials", "invalid email or password"));
    render(<Login />);
    await userEvent.type(screen.getByLabelText("Email"), "ops@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "nope");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("invalid email or password");
  });

  it("tells a new operator how to create the first account", () => {
    needsSetup = true;
    render(<Login />);
    expect(screen.getByText(/bootstrap-admin/)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd web && npm run test
```

Expected: FAIL — `./Login` does not exist.

- [ ] **Step 3: Write the UI kit**

`web/src/components/ui.css`:

```css
.button {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2);
  height: 32px;
  padding: 0 var(--space-3);
  border: 1px solid var(--rule);
  border-radius: var(--radius);
  background: var(--surface);
  color: var(--ink);
  font-size: var(--text-sm);
  font-weight: 500;
  cursor: pointer;
  transition: background var(--transition), border-color var(--transition);
}

.button:hover:not(:disabled) {
  background: var(--surface-sunken);
}

.button:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}

.button--primary {
  background: var(--primary);
  border-color: var(--primary);
  color: var(--primary-ink);
}

.button--primary:hover:not(:disabled) {
  filter: brightness(1.08);
  background: var(--primary);
}

.button--quiet {
  border-color: transparent;
  background: transparent;
  color: var(--ink-muted);
}

.button--danger {
  color: var(--status-retired);
  border-color: color-mix(in srgb, var(--status-retired) 40%, var(--rule));
}

.field {
  display: grid;
  gap: var(--space-1);
  margin-bottom: var(--space-4);
}

.field label {
  font-size: var(--text-sm);
  font-weight: 500;
}

.field input,
.field select,
.field textarea {
  width: 100%;
  padding: var(--space-2) var(--space-3);
  border: 1px solid var(--rule);
  border-radius: var(--radius);
  background: var(--surface);
  color: var(--ink);
  font: inherit;
  font-size: var(--text-sm);
}

.field textarea {
  font-family: var(--font-mono);
  min-height: 8rem;
  resize: vertical;
}

.field .hint {
  font-size: var(--text-xs);
  color: var(--ink-muted);
}

.field .error {
  font-size: var(--text-xs);
  color: var(--status-retired);
}

.note {
  padding: var(--space-3);
  border: 1px solid color-mix(in srgb, var(--status-retired) 35%, var(--rule));
  border-radius: var(--radius);
  background: color-mix(in srgb, var(--status-retired) 8%, var(--surface));
  color: var(--ink);
  font-size: var(--text-sm);
}

.empty {
  display: grid;
  gap: var(--space-2);
  padding: var(--space-8);
  text-align: center;
  color: var(--ink-muted);
  border: 1px dashed var(--rule);
  border-radius: var(--radius);
}

.empty h2 {
  color: var(--ink);
}

.status {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2);
  white-space: nowrap;
}

.status::before {
  content: "";
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--status-neutral);
}

.status--active::before {
  background: var(--status-active);
}

.status--stale::before {
  background: var(--status-stale);
}

.status--retired::before,
.status--failed::before {
  background: var(--status-retired);
}

.dialog-backdrop {
  position: fixed;
  inset: 0;
  display: grid;
  place-items: center;
  background: rgba(11, 14, 18, 0.45);
  padding: var(--space-4);
  z-index: 10;
}

.dialog {
  width: min(560px, 100%);
  max-height: 85vh;
  overflow: auto;
  background: var(--surface);
  border: 1px solid var(--rule);
  border-radius: var(--radius);
  box-shadow: var(--shadow-raised);
  padding: var(--space-6);
}

.dialog header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: var(--space-4);
}

.spinner {
  color: var(--ink-muted);
  font-size: var(--text-sm);
}
```

`web/src/components/ui.tsx`:

```tsx
import type { ButtonHTMLAttributes, ReactNode } from "react";
import { useEffect } from "react";

import { ApiError } from "../api/client";
import "./ui.css";

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "quiet" | "danger";
};

export function Button({ variant, className, ...props }: ButtonProps) {
  const classes = ["button", variant ? `button--${variant}` : "", className ?? ""].join(" ").trim();
  return <button className={classes} {...props} />;
}

export function Field({
  label,
  hint,
  error,
  children,
}: {
  label: string;
  hint?: string;
  error?: string;
  children: ReactNode;
}) {
  return (
    <div className="field">
      <label>
        {label}
        <div style={{ marginTop: "var(--space-1)" }}>{children}</div>
      </label>
      {hint ? <p className="hint">{hint}</p> : null}
      {error ? <p className="error">{error}</p> : null}
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <h2>{title}</h2>
      {children}
    </div>
  );
}

export function Spinner({ label = "Loading…" }: { label?: string }) {
  return (
    <p className="spinner" role="status">
      {label}
    </p>
  );
}

/** ErrorNote turns an unknown thrown value into something readable. */
export function ErrorNote({ error }: { error: unknown }) {
  if (!error) return null;
  const message =
    error instanceof ApiError
      ? error.message
      : error instanceof Error
        ? error.message
        : String(error);
  return (
    <p className="note" role="alert">
      {message}
    </p>
  );
}

export function Dialog({
  title,
  open,
  onClose,
  children,
}: {
  title: string;
  open: boolean;
  onClose: () => void;
  children: ReactNode;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div className="dialog-backdrop" onClick={onClose}>
      <div
        className="dialog"
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onClick={(event) => event.stopPropagation()}
      >
        <header>
          <h2>{title}</h2>
          <Button variant="quiet" onClick={onClose} aria-label="Close">
            ✕
          </Button>
        </header>
        {children}
      </div>
    </div>
  );
}
```

`web/src/components/StatusDot.tsx`:

```tsx
/** StatusDot pairs a colour with its word, so colour is never the only signal. */
export function StatusDot({ status, label }: { status: string; label?: string }) {
  const tone =
    status === "active" || status === "succeeded"
      ? "active"
      : status === "stale" || status === "queued" || status === "delivered" || status === "running"
        ? "stale"
        : status === "retired" || status === "failed" || status === "timed_out" || status === "unenrolled"
          ? "retired"
          : "neutral";
  return <span className={`status status--${tone}`}>{label ?? status.replace("_", " ")}</span>;
}
```

- [ ] **Step 4: Write the sign-in screen**

`web/src/pages/Login.css`:

```css
.login {
  min-height: 100vh;
  display: grid;
  place-items: center;
  padding: var(--space-6);
}

.login__panel {
  width: min(380px, 100%);
}

.login__mark {
  font-size: var(--text-2xl);
  font-weight: 600;
  letter-spacing: -0.02em;
  margin-bottom: var(--space-1);
}

.login__lede {
  color: var(--ink-muted);
  font-size: var(--text-sm);
  margin: 0 0 var(--space-6);
}

.login__setup {
  margin-top: var(--space-6);
  padding: var(--space-3);
  border: 1px solid var(--rule);
  border-radius: var(--radius);
  background: var(--surface-sunken);
  font-size: var(--text-sm);
}

.login__setup code {
  display: block;
  margin-top: var(--space-2);
  word-break: break-all;
}
```

`web/src/pages/Login.tsx`:

```tsx
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
          <Button type="submit" variant="primary" disabled={busy} style={{ marginTop: "var(--space-4)" }}>
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
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd web && npm run test
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add web
git commit -m "feat(console): UI kit and sign-in screen"
```

---

### Task 4: Shell, routing and the devices screen

**Files:**
- Create: `web/src/components/Shell.tsx`, `web/src/components/Shell.css`, `web/src/components/FleetBar.tsx`, `web/src/components/FleetBar.css`, `web/src/components/FleetBar.test.tsx`, `web/src/hooks/useList.ts`, `web/src/pages/Devices.tsx`, `web/src/pages/Devices.css`, `web/src/pages/Devices.test.tsx`
- Modify: `web/src/App.tsx`, `web/src/main.tsx` (wrap in `SessionProvider`)

**Interfaces:**
- Consumes: Tasks 2–3
- Produces:
  - `App` — shows `Spinner` while the session loads, `Login` when signed out, otherwise `Shell` with the routes `/devices`, `/devices/:id`, `/commands`, `/tokens`, `/audit`, `/admins`; `/` redirects to `/devices`
  - `Shell` — left rail (Devices, Commands, Tokens, Audit, Admins), the signed-in email, a sign-out button, and `children`
  - `useList<T>(path, params)` → `{ data, total, loading, error, reload, limit, offset, setOffset }`
  - `FleetBar({ counts, active, onSelect })` — one proportional bar; each segment is a filter button with an accessible name like "Active, 12 devices"
  - `Devices` — fleet bar, search box, table (hostname, status, OS, last seen, agent), paging, and links into the detail screen

- [ ] **Step 1: Write the failing tests**

`web/src/components/FleetBar.test.tsx`:

```tsx
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { FleetBar } from "./FleetBar";

describe("FleetBar", () => {
  it("sizes each segment by its share of the fleet", () => {
    render(<FleetBar counts={{ active: 30, stale: 10, retired: 10 }} active="" onSelect={vi.fn()} />);
    const activeSegment = screen.getByRole("button", { name: "Active, 30 devices" });
    expect(activeSegment).toHaveStyle({ flexGrow: "30" });
    expect(screen.getByRole("button", { name: "Stale, 10 devices" })).toHaveStyle({ flexGrow: "10" });
  });

  it("filters when a segment is chosen", async () => {
    const onSelect = vi.fn();
    render(<FleetBar counts={{ active: 1, stale: 0, retired: 0 }} active="" onSelect={onSelect} />);
    await userEvent.click(screen.getByRole("button", { name: "Active, 1 device" }));
    expect(onSelect).toHaveBeenCalledWith("active");
  });

  it("says so when no devices are enrolled", () => {
    render(<FleetBar counts={{ active: 0, stale: 0, retired: 0 }} active="" onSelect={vi.fn()} />);
    expect(screen.getByText("No devices enrolled yet")).toBeInTheDocument();
  });
});
```

`web/src/pages/Devices.test.tsx`:

```tsx
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Devices from "./Devices";

const fetchMock = vi.fn();

vi.mock("../session/SessionContext", () => ({
  useSession: () => ({ admin: { role: "admin" }, canWrite: true, loading: false, needsSetup: false }),
}));

function device(overrides: Record<string, unknown> = {}) {
  return {
    id: "01a0-1",
    hostname: "PC-ALPHA",
    status: "active",
    os_version: "Microsoft Windows 11 Pro 10.0.26200",
    os_build: "26200",
    manufacturer: "Contoso",
    model: "Book 9",
    serial: "SN-1",
    smbios_uuid: "U-1",
    agent_version: "0.1.0",
    enrolled_at: "2026-09-12T12:00:00Z",
    last_seen_at: "2026-09-12T12:30:00Z",
    cert_expires_at: "2026-12-12T12:00:00Z",
    stale: false,
    ...overrides,
  };
}

function json(body: unknown) {
  return new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json" } });
}

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
});

describe("Devices", () => {
  it("lists devices and their status", async () => {
    fetchMock.mockResolvedValue(
      json({ items: [device(), device({ id: "01a0-2", hostname: "PC-BETA", stale: true })], total: 2, limit: 50, offset: 0 }),
    );
    render(
      <MemoryRouter>
        <Devices />
      </MemoryRouter>,
    );
    expect(await screen.findByRole("link", { name: "PC-ALPHA" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "PC-BETA" })).toBeInTheDocument();
    expect(screen.getAllByText("active").length).toBeGreaterThan(0);
  });

  it("searches", async () => {
    fetchMock.mockResolvedValue(json({ items: [], total: 0, limit: 50, offset: 0 }));
    render(
      <MemoryRouter>
        <Devices />
      </MemoryRouter>,
    );
    await screen.findByText("No devices match this search.");
    await userEvent.type(screen.getByRole("searchbox", { name: "Search devices" }), "beta");
    await waitFor(() => {
      const urls = fetchMock.mock.calls.map(([url]) => String(url));
      expect(urls.some((url) => url.includes("search=beta"))).toBe(true);
    });
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd web && npm run test
```

Expected: FAIL — `./FleetBar` and `./Devices` do not exist.

- [ ] **Step 3: Write the list hook**

`web/src/hooks/useList.ts`:

```ts
import { useCallback, useEffect, useState } from "react";

import { api } from "../api/client";
import type { ListResponse } from "../api/types";

/** useList fetches one page of a listing endpoint and re-fetches on change. */
export function useList<T>(path: string, params: Record<string, string | number | undefined> = {}) {
  const [items, setItems] = useState<T[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [offset, setOffset] = useState(0);
  const [reloadToken, setReloadToken] = useState(0);

  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") query.set(key, String(value));
  }
  query.set("offset", String(offset));
  const search = query.toString();

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    api
      .get<ListResponse<T>>(`${path}?${search}`)
      .then((page) => {
        if (cancelled) return;
        setItems(page.items);
        setTotal(page.total);
        setError(null);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [path, search, reloadToken]);

  const reload = useCallback(() => setReloadToken((n) => n + 1), []);
  return { items, total, loading, error, offset, setOffset, reload };
}
```

- [ ] **Step 4: Write the fleet bar**

`web/src/components/FleetBar.css`:

```css
.fleet {
  display: grid;
  gap: var(--space-2);
  margin-bottom: var(--space-6);
}

.fleet__bar {
  display: flex;
  height: 28px;
  border: 1px solid var(--rule);
  border-radius: var(--radius);
  overflow: hidden;
  background: var(--surface-sunken);
}

.fleet__segment {
  border: 0;
  padding: 0;
  min-width: 2px;
  cursor: pointer;
  color: transparent;
  transition: filter var(--transition);
}

.fleet__segment:hover {
  filter: brightness(1.12);
}

.fleet__segment[aria-pressed="true"] {
  box-shadow: inset 0 0 0 2px var(--ink);
}

.fleet__segment--active {
  background: var(--status-active);
}

.fleet__segment--stale {
  background: var(--status-stale);
}

.fleet__segment--retired {
  background: var(--status-retired);
}

.fleet__legend {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-4);
  font-size: var(--text-sm);
  color: var(--ink-muted);
}

.fleet__legend b {
  color: var(--ink);
  font-variant-numeric: tabular-nums;
}

.fleet__empty {
  font-size: var(--text-sm);
  color: var(--ink-muted);
}
```

`web/src/components/FleetBar.tsx`:

```tsx
import { StatusDot } from "./StatusDot";
import "./FleetBar.css";

export interface FleetCounts {
  active: number;
  stale: number;
  retired: number;
}

const SEGMENTS: { key: keyof FleetCounts; filter: string; label: string }[] = [
  { key: "active", filter: "active", label: "Active" },
  { key: "stale", filter: "stale", label: "Stale" },
  { key: "retired", filter: "retired", label: "Retired" },
];

/**
 * FleetBar shows the shape of the fleet as one proportional bar. Each segment
 * is also the filter for that status.
 */
export function FleetBar({
  counts,
  active,
  onSelect,
}: {
  counts: FleetCounts;
  active: string;
  onSelect: (filter: string) => void;
}) {
  const total = counts.active + counts.stale + counts.retired;
  if (total === 0) {
    return <p className="fleet__empty">No devices enrolled yet</p>;
  }
  return (
    <div className="fleet">
      <div className="fleet__bar">
        {SEGMENTS.filter((segment) => counts[segment.key] > 0).map((segment) => {
          const count = counts[segment.key];
          return (
            <button
              key={segment.key}
              type="button"
              className={`fleet__segment fleet__segment--${segment.key}`}
              style={{ flexGrow: count, flexBasis: 0 }}
              aria-pressed={active === segment.filter}
              aria-label={`${segment.label}, ${count} ${count === 1 ? "device" : "devices"}`}
              onClick={() => onSelect(active === segment.filter ? "" : segment.filter)}
            />
          );
        })}
      </div>
      <div className="fleet__legend">
        {SEGMENTS.map((segment) => (
          <span key={segment.key}>
            <StatusDot status={segment.key} label={segment.label} /> <b>{counts[segment.key]}</b>
          </span>
        ))}
      </div>
    </div>
  );
}
```

- [ ] **Step 5: Write the shell and the devices screen**

`web/src/components/Shell.css`:

```css
.shell {
  display: grid;
  grid-template-columns: var(--rail-width) 1fr;
  min-height: 100vh;
}

.rail {
  border-right: 1px solid var(--rule);
  background: var(--surface);
  padding: var(--space-4);
  display: flex;
  flex-direction: column;
  gap: var(--space-6);
}

.rail__mark {
  font-size: var(--text-lg);
  font-weight: 600;
  letter-spacing: -0.02em;
}

.rail nav {
  display: grid;
  gap: 2px;
}

.rail a {
  padding: var(--space-2) var(--space-3);
  border-radius: var(--radius);
  color: var(--ink);
  text-decoration: none;
  font-size: var(--text-sm);
}

.rail a:hover {
  background: var(--surface-sunken);
}

.rail a[aria-current="page"] {
  background: var(--primary-wash);
  color: var(--primary);
  font-weight: 500;
}

.rail__footer {
  margin-top: auto;
  font-size: var(--text-xs);
  color: var(--ink-muted);
  display: grid;
  gap: var(--space-2);
}

.content {
  padding: var(--space-6) var(--space-8);
  max-width: 1200px;
}

.content__head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: var(--space-4);
  margin-bottom: var(--space-6);
}

@media (max-width: 720px) {
  .shell {
    grid-template-columns: 1fr;
  }

  .rail {
    border-right: 0;
    border-bottom: 1px solid var(--rule);
  }

  .content {
    padding: var(--space-4);
  }
}
```

`web/src/components/Shell.tsx`:

```tsx
import { NavLink } from "react-router-dom";
import type { ReactNode } from "react";

import { useSession } from "../session/SessionContext";
import { Button } from "./ui";
import "./Shell.css";

const LINKS = [
  { to: "/devices", label: "Devices" },
  { to: "/commands", label: "Commands" },
  { to: "/tokens", label: "Enrollment" },
  { to: "/audit", label: "Audit" },
  { to: "/admins", label: "Admins" },
];

export function Shell({ children }: { children: ReactNode }) {
  const { admin, signOut } = useSession();
  return (
    <div className="shell">
      <aside className="rail">
        <div className="rail__mark">Retune</div>
        <nav>
          {LINKS.map((link) => (
            <NavLink key={link.to} to={link.to}>
              {link.label}
            </NavLink>
          ))}
        </nav>
        <div className="rail__footer">
          <span className="mono">{admin?.email}</span>
          {admin?.role === "read_only" ? <span>Read-only access</span> : null}
          <Button variant="quiet" onClick={() => void signOut()}>
            Sign out
          </Button>
        </div>
      </aside>
      <main className="content">{children}</main>
    </div>
  );
}
```

`web/src/pages/Devices.css`:

```css
.devices__search {
  width: min(320px, 100%);
}

.devices__table a {
  color: var(--ink);
  text-decoration: none;
  font-family: var(--font-mono);
}

.devices__table a:hover {
  text-decoration: underline;
}

.pager {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  margin-top: var(--space-4);
  font-size: var(--text-sm);
  color: var(--ink-muted);
}
```

`web/src/pages/Devices.tsx`:

```tsx
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { api } from "../api/client";
import type { Device, ListResponse } from "../api/types";
import { FleetBar } from "../components/FleetBar";
import type { FleetCounts } from "../components/FleetBar";
import { StatusDot } from "../components/StatusDot";
import { Button, EmptyState, ErrorNote, Spinner } from "../components/ui";
import { useList } from "../hooks/useList";
import "./Devices.css";

/** relative renders a timestamp as "3 minutes ago", or "never". */
export function relative(value?: string): string {
  if (!value) return "never";
  const then = new Date(value).getTime();
  const seconds = Math.round((Date.now() - then) / 1000);
  if (seconds < 60) return "just now";
  const units: [number, string][] = [
    [60, "minute"],
    [24, "hour"],
    [7, "day"],
  ];
  let amount = seconds / 60;
  let unit = "minute";
  for (const [step, name] of units) {
    if (amount < step) {
      unit = name;
      break;
    }
    amount /= step;
    unit = name;
  }
  const rounded = Math.round(amount);
  return `${rounded} ${unit}${rounded === 1 ? "" : "s"} ago`;
}

export default function Devices() {
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("");
  const [counts, setCounts] = useState<FleetCounts>({ active: 0, stale: 0, retired: 0 });
  const query = status === "stale" ? { search, status: "active" } : { search, status };
  const { items, total, loading, error, offset, setOffset } = useList<Device>("/devices", query);

  // The fleet bar summarises the whole fleet, not the current page.
  useEffect(() => {
    api
      .get<ListResponse<Device>>("/devices?limit=200")
      .then((page) => {
        const summary = { active: 0, stale: 0, retired: 0 };
        for (const device of page.items) {
          if (device.status === "active") {
            device.stale ? summary.stale++ : summary.active++;
          } else {
            summary.retired++;
          }
        }
        setCounts(summary);
      })
      .catch(() => setCounts({ active: 0, stale: 0, retired: 0 }));
  }, [items]);

  const shown = status === "stale" ? items.filter((device) => device.stale) : items;

  return (
    <>
      <div className="content__head">
        <h1>Devices</h1>
        <input
          className="devices__search field"
          type="search"
          aria-label="Search devices"
          placeholder="Hostname, serial or model"
          value={search}
          onChange={(event) => {
            setOffset(0);
            setSearch(event.target.value);
          }}
        />
      </div>

      <FleetBar
        counts={counts}
        active={status}
        onSelect={(next) => {
          setOffset(0);
          setStatus(next === "retired" ? "retired" : next);
        }}
      />

      <ErrorNote error={error} />
      {loading ? <Spinner /> : null}

      {!loading && shown.length === 0 ? (
        search || status ? (
          <EmptyState title="No devices match this search." />
        ) : (
          <EmptyState title="No devices yet.">
            <p>Create an enrollment token, then install the agent on a machine.</p>
            <Link to="/tokens">Create a token</Link>
          </EmptyState>
        )
      ) : null}

      {shown.length > 0 ? (
        <table className="devices__table">
          <thead>
            <tr>
              <th>Hostname</th>
              <th>Status</th>
              <th>Operating system</th>
              <th>Last seen</th>
              <th>Agent</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((device) => (
              <tr key={device.id}>
                <td>
                  <Link to={`/devices/${device.id}`}>{device.hostname}</Link>
                </td>
                <td>
                  <StatusDot status={device.stale && device.status === "active" ? "stale" : device.status} />
                </td>
                <td>{device.os_version || "—"}</td>
                <td>{relative(device.last_seen_at)}</td>
                <td className="mono">{device.agent_version || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}

      {total > items.length ? (
        <div className="pager">
          <Button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 50))}>
            Previous
          </Button>
          <span>
            {offset + 1}–{offset + items.length} of {total}
          </span>
          <Button disabled={offset + items.length >= total} onClick={() => setOffset(offset + 50)}>
            Next
          </Button>
        </div>
      ) : null}
    </>
  );
}
```

- [ ] **Step 6: Wire the routes**

`web/src/App.tsx`:

```tsx
import { Navigate, Route, Routes } from "react-router-dom";

import { Shell } from "./components/Shell";
import { Spinner } from "./components/ui";
import Devices from "./pages/Devices";
import Login from "./pages/Login";
import { useSession } from "./session/SessionContext";

export default function App() {
  const { admin, loading } = useSession();
  if (loading) return <Spinner label="Loading the console…" />;
  if (!admin) return <Login />;
  return (
    <Shell>
      <Routes>
        <Route path="/" element={<Navigate to="/devices" replace />} />
        <Route path="/devices" element={<Devices />} />
        <Route path="*" element={<Navigate to="/devices" replace />} />
      </Routes>
    </Shell>
  );
}
```

`web/src/main.tsx` wraps `App` in `SessionProvider` inside `BrowserRouter`.

- [ ] **Step 7: Run the tests and build**

```bash
cd web && npm run test && npm run build
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add web
git commit -m "feat(console): shell, routing and the devices screen"
```

---

### Task 5: Device detail and actions

**Files:**
- Create: `web/src/pages/DeviceDetail.tsx`, `web/src/pages/DeviceDetail.css`, `web/src/pages/DeviceDetail.test.tsx`, `web/src/components/RunScriptDialog.tsx`
- Modify: `web/src/App.tsx` (add the `/devices/:id` route)

**Interfaces:**
- Consumes: Tasks 2–4
- Produces:
  - `DeviceDetail` — identity summary, inventory figures, tabbed software and command history, and the actions "Run script", "Refresh inventory", "Restart", "Retire device", "Unenroll device"
  - `RunScriptDialog({ deviceIds, open, onClose, onQueued })` — a script box with a timeout, posting to `/commands`
  - Write actions are hidden for read-only admins; destructive ones confirm first

- [ ] **Step 1: Write the failing test**

`web/src/pages/DeviceDetail.test.tsx`:

```tsx
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import DeviceDetail from "./DeviceDetail";

const fetchMock = vi.fn();
let canWrite = true;

vi.mock("../session/SessionContext", () => ({
  useSession: () => ({ admin: { role: canWrite ? "admin" : "read_only" }, canWrite }),
}));

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const detail = {
  device: {
    id: "01a0-1",
    hostname: "PC-ALPHA",
    status: "active",
    os_version: "Microsoft Windows 11 Pro 10.0.26200",
    os_build: "26200",
    manufacturer: "Contoso",
    model: "Book 9",
    serial: "SN-1",
    smbios_uuid: "U-1",
    agent_version: "0.1.0",
    enrolled_at: "2026-09-12T12:00:00Z",
    last_seen_at: "2026-09-12T12:30:00Z",
    cert_expires_at: "2026-12-12T12:00:00Z",
    stale: false,
  },
  inventory: {
    collected_at: "2026-09-12T12:30:00Z",
    received_at: "2026-09-12T12:30:00Z",
    ram_gb: 16,
    disk_free_gb: 240.5,
    document: {},
  },
  software: [{ name: "7-Zip", version: "24.08", publisher: "Igor Pavlov", install_date: "", scope: "machine" }],
  commands: [],
};

function renderDetail() {
  return render(
    <MemoryRouter initialEntries={["/devices/01a0-1"]}>
      <Routes>
        <Route path="/devices/:id" element={<DeviceDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
  canWrite = true;
});

describe("DeviceDetail", () => {
  it("shows identity and inventory", async () => {
    fetchMock.mockResolvedValue(json(detail));
    renderDetail();
    expect(await screen.findByRole("heading", { name: "PC-ALPHA" })).toBeInTheDocument();
    expect(screen.getByText("Contoso Book 9")).toBeInTheDocument();
    expect(screen.getByText("16 GB")).toBeInTheDocument();
    expect(screen.getByText("7-Zip")).toBeInTheDocument();
  });

  it("queues a script", async () => {
    fetchMock.mockResolvedValueOnce(json(detail));
    renderDetail();
    await screen.findByRole("heading", { name: "PC-ALPHA" });

    await userEvent.click(screen.getByRole("button", { name: "Run script" }));
    await userEvent.type(screen.getByLabelText("PowerShell script"), "Get-Date");
    fetchMock.mockResolvedValueOnce(json({ commands: [{ id: "c1", device_id: "01a0-1" }] }, 201));
    fetchMock.mockResolvedValueOnce(json(detail));
    await userEvent.click(screen.getByRole("button", { name: "Queue script" }));

    await waitFor(() => {
      const call = fetchMock.mock.calls.find(([url]) => String(url).endsWith("/commands"));
      expect(call).toBeDefined();
      expect(JSON.parse(call![1].body)).toMatchObject({
        device_ids: ["01a0-1"],
        type: "run_powershell",
        script: "Get-Date",
      });
    });
  });

  it("hides write actions from a read-only admin", async () => {
    canWrite = false;
    fetchMock.mockResolvedValue(json(detail));
    renderDetail();
    await screen.findByRole("heading", { name: "PC-ALPHA" });
    expect(screen.queryByRole("button", { name: "Run script" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Retire device" })).not.toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd web && npm run test
```

Expected: FAIL — `./DeviceDetail` does not exist.

- [ ] **Step 3: Write the run-script dialog**

`web/src/components/RunScriptDialog.tsx`:

```tsx
import { useState } from "react";

import { api } from "../api/client";
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
  const [timeout, setTimeoutSeconds] = useState(600);
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
        timeout_seconds: timeout,
      });
      setScript("");
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
          value={timeout}
          onChange={(event) => setTimeoutSeconds(Number(event.target.value))}
        />
      </Field>
      <ErrorNote error={error} />
      <div style={{ display: "flex", gap: "var(--space-2)", marginTop: "var(--space-4)" }}>
        <Button variant="primary" disabled={busy || script.trim() === ""} onClick={() => void queue()}>
          {busy ? "Queueing…" : "Queue script"}
        </Button>
        <Button variant="quiet" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </Dialog>
  );
}
```

- [ ] **Step 4: Write the detail screen**

`web/src/pages/DeviceDetail.css`:

```css
.detail__grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: var(--space-4);
  padding: var(--space-4);
  border: 1px solid var(--rule);
  border-radius: var(--radius);
  background: var(--surface);
  margin-bottom: var(--space-6);
}

.detail__grid dt {
  font-size: var(--text-xs);
  color: var(--ink-muted);
  margin-bottom: var(--space-1);
}

.detail__grid dd {
  margin: 0;
  font-size: var(--text-sm);
}

.detail__actions {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
  margin-bottom: var(--space-6);
}

.tabs {
  display: flex;
  gap: var(--space-1);
  border-bottom: 1px solid var(--rule);
  margin-bottom: var(--space-4);
}

.tabs button {
  border: 0;
  background: none;
  padding: var(--space-2) var(--space-3);
  color: var(--ink-muted);
  border-bottom: 2px solid transparent;
  cursor: pointer;
  font-size: var(--text-sm);
}

.tabs button[aria-selected="true"] {
  color: var(--ink);
  border-bottom-color: var(--primary);
  font-weight: 500;
}
```

`web/src/pages/DeviceDetail.tsx`:

```tsx
import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { api } from "../api/client";
import type { DeviceDetail as Detail } from "../api/types";
import { RunScriptDialog } from "../components/RunScriptDialog";
import { StatusDot } from "../components/StatusDot";
import { Button, ErrorNote, Spinner } from "../components/ui";
import { useSession } from "../session/SessionContext";
import { relative } from "./Devices";
import "./DeviceDetail.css";

export default function DeviceDetail() {
  const { id = "" } = useParams();
  const { canWrite } = useSession();
  const [detail, setDetail] = useState<Detail | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [tab, setTab] = useState<"software" | "commands">("software");
  const [scriptOpen, setScriptOpen] = useState(false);

  const load = useCallback(() => {
    api
      .get<Detail>(`/devices/${id}`)
      .then((next) => {
        setDetail(next);
        setError(null);
      })
      .catch(setError);
  }, [id]);

  useEffect(load, [load]);

  async function act(path: string, confirmation?: string) {
    if (confirmation && !window.confirm(confirmation)) return;
    try {
      await api.post(`/devices/${id}/${path}`);
      load();
    } catch (err) {
      setError(err);
    }
  }

  async function queueSimple(type: string) {
    try {
      await api.post("/commands", { device_ids: [id], type });
      load();
    } catch (err) {
      setError(err);
    }
  }

  if (error && !detail) return <ErrorNote error={error} />;
  if (!detail) return <Spinner />;
  const { device, inventory, software, commands } = detail;

  return (
    <>
      <div className="content__head">
        <div>
          <h1>{device.hostname}</h1>
          <p style={{ margin: "var(--space-1) 0 0", color: "var(--ink-muted)", fontSize: "var(--text-sm)" }}>
            <StatusDot status={device.stale && device.status === "active" ? "stale" : device.status} />
            {" · last seen "}
            {relative(device.last_seen_at)}
          </p>
        </div>
        <Link to="/devices">Back to devices</Link>
      </div>

      <ErrorNote error={error} />

      <dl className="detail__grid">
        <div>
          <dt>Hardware</dt>
          <dd>{[device.manufacturer, device.model].filter(Boolean).join(" ") || "—"}</dd>
        </div>
        <div>
          <dt>Operating system</dt>
          <dd>{device.os_version || "—"}</dd>
        </div>
        <div>
          <dt>Serial</dt>
          <dd className="mono">{device.serial || "—"}</dd>
        </div>
        <div>
          <dt>Memory</dt>
          <dd>{inventory ? `${inventory.ram_gb} GB` : "—"}</dd>
        </div>
        <div>
          <dt>Free disk</dt>
          <dd>{inventory ? `${inventory.disk_free_gb} GB` : "—"}</dd>
        </div>
        <div>
          <dt>Agent</dt>
          <dd className="mono">{device.agent_version || "—"}</dd>
        </div>
        <div>
          <dt>Certificate expires</dt>
          <dd>{new Date(device.cert_expires_at).toLocaleDateString()}</dd>
        </div>
        <div>
          <dt>Inventory collected</dt>
          <dd>{inventory ? relative(inventory.collected_at) : "never"}</dd>
        </div>
      </dl>

      {canWrite && device.status === "active" ? (
        <div className="detail__actions">
          <Button variant="primary" onClick={() => setScriptOpen(true)}>
            Run script
          </Button>
          <Button onClick={() => void queueSimple("refresh_inventory")}>Refresh inventory</Button>
          <Button onClick={() => void queueSimple("restart")}>Restart</Button>
          <Button
            variant="danger"
            onClick={() => void act("retire", `Stop accepting check-ins from ${device.hostname}?`)}
          >
            Retire device
          </Button>
          <Button
            variant="danger"
            onClick={() =>
              void act("unenroll", `Tell ${device.hostname} to delete its identity and stop managing it?`)
            }
          >
            Unenroll device
          </Button>
        </div>
      ) : null}

      <div className="tabs" role="tablist">
        <button role="tab" aria-selected={tab === "software"} onClick={() => setTab("software")}>
          Software ({software.length})
        </button>
        <button role="tab" aria-selected={tab === "commands"} onClick={() => setTab("commands")}>
          Commands ({commands.length})
        </button>
      </div>

      {tab === "software" ? (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Version</th>
              <th>Publisher</th>
              <th>Scope</th>
            </tr>
          </thead>
          <tbody>
            {software.map((item) => (
              <tr key={`${item.name}-${item.version}-${item.scope}`}>
                <td>{item.name}</td>
                <td className="mono">{item.version || "—"}</td>
                <td>{item.publisher || "—"}</td>
                <td>{item.scope}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Type</th>
              <th>Status</th>
              <th>Queued</th>
              <th>By</th>
            </tr>
          </thead>
          <tbody>
            {commands.map((command) => (
              <tr key={command.id}>
                <td>
                  <Link to={`/commands?device_id=${device.id}`}>{command.type}</Link>
                </td>
                <td>
                  <StatusDot status={command.status} />
                </td>
                <td>{relative(command.created_at)}</td>
                <td>{command.created_by}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <RunScriptDialog
        deviceIds={[device.id]}
        open={scriptOpen}
        onClose={() => setScriptOpen(false)}
        onQueued={load}
      />
    </>
  );
}
```

Add the route to `App.tsx`: `<Route path="/devices/:id" element={<DeviceDetail />} />`.

- [ ] **Step 5: Run the tests and commit**

```bash
cd web && npm run test && npm run build
git add web
git commit -m "feat(console): device detail with inventory, software and actions"
```

---

### Task 6: Commands, enrollment, audit and admins screens

**Files:**
- Create: `web/src/pages/Commands.tsx`, `web/src/pages/Tokens.tsx`, `web/src/pages/Audit.tsx`, `web/src/pages/Admins.tsx`, `web/src/pages/Tokens.test.tsx`, `web/src/pages/Admins.test.tsx`
- Modify: `web/src/App.tsx` (routes)

**Interfaces:**
- Consumes: Tasks 2–5; every screen follows the Devices pattern: `useList`, a table, `EmptyState`, `ErrorNote`, and paging
- Produces:
  - `Commands` — list with status and device filters; selecting a row expands its result (exit code, stdout, stderr in mono)
  - `Tokens` — list (label, uses, expiry, state), "Create token" dialog, and the created token shown once with a copy button plus the exact `msiexec` line to run; "Revoke" per row
  - `Audit` — paged table of actor, action, target and time, with details rendered as compact key/value text
  - `Admins` — list with role and state; "Add admin"; per-row "Change password", "Enable/Disable authenticator" (showing the otpauth URL once), "Disable/Enable account"
  - All write actions appear only when `canWrite`

- [ ] **Step 1: Write the failing tests**

`web/src/pages/Tokens.test.tsx` covers the part that must not regress: the plaintext token is shown exactly once, together with the install command.

```tsx
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Tokens from "./Tokens";

const fetchMock = vi.fn();
vi.mock("../session/SessionContext", () => ({
  useSession: () => ({ admin: { role: "admin" }, canWrite: true }),
}));

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
});

describe("Tokens", () => {
  it("creates a token and shows it once with the install command", async () => {
    fetchMock.mockResolvedValue(json({ items: [], total: 0, limit: 50, offset: 0 }));
    render(<Tokens />);
    await screen.findByText("No enrollment tokens yet.");

    await userEvent.click(screen.getByRole("button", { name: "Create token" }));
    await userEvent.type(screen.getByLabelText("Label"), "Office laptops");
    fetchMock.mockResolvedValueOnce(
      json({ id: "t1", token: "rt_secret", label: "Office laptops", created_at: "2026-09-12T12:00:00Z" }, 201),
    );
    fetchMock.mockResolvedValueOnce(json({ items: [], total: 0, limit: 50, offset: 0 }));
    await userEvent.click(screen.getByRole("button", { name: "Create" }));

    expect(await screen.findByText("rt_secret")).toBeInTheDocument();
    expect(screen.getByText(/msiexec/)).toHaveTextContent("rt_secret");
  });

  it("lists tokens without any plaintext", async () => {
    fetchMock.mockResolvedValue(
      json({
        items: [
          {
            id: "t1",
            label: "Office laptops",
            max_uses: 5,
            use_count: 2,
            created_by: "ops@example.com",
            created_at: "2026-09-12T12:00:00Z",
          },
        ],
        total: 1,
        limit: 50,
        offset: 0,
      }),
    );
    render(<Tokens />);
    expect(await screen.findByText("Office laptops")).toBeInTheDocument();
    expect(screen.getByText("2 of 5")).toBeInTheDocument();
    expect(screen.queryByText(/rt_/)).not.toBeInTheDocument();
  });
});
```

`web/src/pages/Admins.test.tsx` checks that a read-only admin sees the list without any management controls:

```tsx
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Admins from "./Admins";

const fetchMock = vi.fn();
let canWrite = false;
vi.mock("../session/SessionContext", () => ({
  useSession: () => ({ admin: { role: canWrite ? "admin" : "read_only" }, canWrite }),
}));

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
  canWrite = false;
});

describe("Admins", () => {
  it("shows accounts but no controls for a read-only admin", async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          items: [
            {
              id: "a1",
              email: "ops@example.com",
              role: "admin",
              totp_enabled: true,
              disabled: false,
              created_at: "2026-09-12T12:00:00Z",
            },
          ],
          total: 1,
          limit: 50,
          offset: 0,
        }),
        { headers: { "Content-Type": "application/json" } },
      ),
    );
    render(<Admins />);
    expect(await screen.findByText("ops@example.com")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add admin" })).not.toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail, then write the screens**

```bash
cd web && npm run test
```

Expected: FAIL — the four page modules do not exist.

Write each screen with the same shape as `Devices`: a `content__head` with the title and the page action, `ErrorNote`, `Spinner` while loading, `EmptyState` when there is nothing, then a table and the pager. Specifics:

- **Commands** reads `useList<Command>("/commands", { status, device_id })`, renders type, status via `StatusDot`, device link, queued time and author, and expands the selected row by fetching `/commands/{id}` and showing `exit_code`, `stdout` and `stderr` in `<pre className="mono">`.
- **Tokens** renders label, `use_count of max_uses` (or "unlimited"), expiry, and state ("revoked", "expired", "active"). "Create token" opens a `Dialog` with label, max uses and expiry-in-hours; on success it shows the plaintext once in a panel with a copy button and this line, with the values filled in:
  `msiexec /i retune-agent.msi SERVER_URL=<origin> ENROLL_TOKEN=<token> /qn`
- **Audit** reads `useList<AuditEntry>("/audit")` and shows actor, action, target and time, with `details` flattened to `key=value` pairs in mono.
- **Admins** reads `useList<Admin>("/admins")` and shows email, role, authenticator state, account state and last login. Write actions post to `/admins`, `/admins/{id}/password`, `/admins/{id}/totp` and `/admins/{id}/disabled`; enabling an authenticator shows the returned `otpauth_url` once.

- [ ] **Step 3: Add the routes, run the tests and commit**

```bash
cd web && npm run test && npm run build
git add web
git commit -m "feat(console): commands, enrollment, audit and admin screens"
```

---

### Task 7: Serve the console from the server

**Files:**
- Create: `internal/server/console/console.go`, `internal/server/console/console_test.go`, `web/dist/.gitkeep`
- Modify: `internal/server/app/app.go` (mount the console at `/`)

**Interfaces:**
- Consumes: the built `web/dist`
- Produces:
  - `console.Handler() http.Handler` — serves the embedded files, falls back to `index.html` for client-side routes, never serves a directory listing, and answers with a clear message when the console has not been built
  - `console.Built() bool`
  - Security headers on every console response: `Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`
  - Hashed assets under `/assets/` get `Cache-Control: public, max-age=31536000, immutable`; `index.html` gets `no-cache`

- [ ] **Step 1: Write the failing test**

`internal/server/console/console_test.go`:

```go
package console_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"retune/internal/server/console"
)

func get(t *testing.T, path string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	console.Handler().ServeHTTP(rec, req)
	return rec.Result()
}

func TestServesTheConsole(t *testing.T) {
	res := get(t, "/")
	defer res.Body.Close()
	if console.Built() && res.StatusCode != http.StatusOK {
		t.Fatalf("GET / = %d", res.StatusCode)
	}
	if !console.Built() && res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("without a build, GET / = %d, want 503", res.StatusCode)
	}
	if got := res.Header.Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'self'") {
		t.Fatalf("CSP = %q", got)
	}
	if got := res.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q", got)
	}
}

func TestClientRoutesFallBackToIndex(t *testing.T) {
	if !console.Built() {
		t.Skip("console has not been built")
	}
	res := get(t, "/devices/01a0-1")
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /devices/01a0-1 = %d, want the console's index", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q", ct)
	}
}

func TestUnknownAssetIsNotFound(t *testing.T) {
	if !console.Built() {
		t.Skip("console has not been built")
	}
	res := get(t, "/assets/does-not-exist.js")
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("missing asset = %d, want 404", res.StatusCode)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/server/console/`
Expected: FAIL — no such package.

- [ ] **Step 3: Write the handler**

Create `web/dist/.gitkeep` (empty) so the embed pattern always matches, and add `/web/dist/*` plus `!/web/dist/.gitkeep` to the repository `.gitignore`.

`internal/server/console/console.go`:

```go
// Package console serves the embedded admin console.
package console

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var files embed.FS

// dist is the built console, rooted at dist/.
var dist = func() fs.FS {
	sub, err := fs.Sub(files, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}()

// Built reports whether the console assets are present in this binary.
func Built() bool {
	_, err := fs.Stat(dist, "index.html")
	return err == nil
}

// Handler serves the console, falling back to index.html so client-side routes
// work on a hard refresh.
func Handler() http.Handler {
	server := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		if !Built() {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("The console has not been built. Run `npm --prefix web run build`, then rebuild the server.\n"))
			return
		}

		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			serveIndex(w, r)
			return
		}
		info, err := fs.Stat(dist, path)
		switch {
		case err == nil && !info.IsDir():
			if strings.HasPrefix(path, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			server.ServeHTTP(w, r)
		case strings.HasPrefix(path, "assets/"):
			// A missing hashed asset is a real 404, not a client-side route.
			http.NotFound(w, r)
		default:
			serveIndex(w, r)
		}
	})
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	index, err := fs.ReadFile(dist, "index.html")
	if err != nil {
		http.Error(w, "console index is missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(index)
	_ = r
}

func setSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy",
		"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
			"object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
}
```

- [ ] **Step 4: Mount it**

In `internal/server/app/app.go`, after the two API mounts:

```go
	root.Handle("/", console.Handler())
```

- [ ] **Step 5: Run the tests and commit**

```bash
npm --prefix web run build
go vet ./... && go test -count=1 ./internal/server/console/ ./internal/server/app/
git add .gitignore web/dist/.gitkeep internal/server/console internal/server/app
git commit -m "feat(server): serve the embedded console with SPA fallback"
```

---

### Task 8: Build integration, verification and smoke test

**Files:**
- Create: `Makefile`
- Modify: `README.md` (create it if missing) with how to build and run

**Interfaces:**
- Produces: `make console` (build the web app), `make build` (console then binaries), `make test` (Go plus web tests)

- [ ] **Step 1: Write the Makefile**

```makefile
# Retune build helpers. Windows users can run the same commands by hand.
.PHONY: console build test clean

console:
	npm --prefix web ci
	npm --prefix web run build

build: console
	go build -o bin/ ./cmd/...

test:
	go test ./...
	npm --prefix web run test

clean:
	rm -rf bin web/dist
```

- [ ] **Step 2: Full verification**

```bash
npm --prefix web run test
npm --prefix web run build
go vet ./... && go test -count=1 ./... && go build -o bin/ ./cmd/...
```

Expected: everything passes and `bin/retune-server` contains the console.

- [ ] **Step 3: Smoke test in a real browser**

```powershell
docker run -d --name retune-m3b-pg -e POSTGRES_USER=retune -e POSTGRES_PASSWORD=retune -e POSTGRES_DB=retune -p 127.0.0.1::5432 postgres:17-alpine
$port = ((docker port retune-m3b-pg 5432) -split ':')[-1]
$env:DATABASE_URL = "postgres://retune:retune@127.0.0.1:$port/retune?sslmode=disable"
$env:PUBLIC_URL = "https://localhost:18443"
$env:AGENT_API_LISTEN = "127.0.0.1:18443"
.\bin\retune-server.exe migrate
.\bin\retune-server.exe bootstrap-admin --email ops@example.com
.\bin\retune-server.exe serve
```

Then open `https://localhost:18443/` (accept the self-signed certificate) and check:
- the sign-in screen appears, and a wrong password shows a readable error;
- signing in lands on Devices, showing the empty state with its instruction;
- Enrollment creates a token, shows it once with the `msiexec` line, and lists it without the plaintext afterwards;
- enrolling a real agent makes the device appear, with its detail screen showing inventory and software;
- "Run script" queues a script, and the Commands screen shows its output once the agent checks in;
- a reload on `/devices/<id>` still works (SPA fallback);
- the console is usable at 400px wide and with the keyboard alone.

- [ ] **Step 4: Clean up and commit**

```powershell
docker rm -f retune-m3b-pg
```

```bash
git add -A
git commit -m "docs: build instructions for the console"
```
