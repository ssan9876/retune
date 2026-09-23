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

/**
 * postBinary uploads a raw body rather than JSON, for payloads — such as an
 * agent build — where base64 in a JSON object would inflate a multi-megabyte
 * binary by a third for no benefit. It follows the same CSRF and credentials
 * handling as `request`, since it bypasses `request` to avoid JSON-encoding
 * the body. Extra `headers` — such as a signature sidecar — are spread in
 * ahead of the content type, so a caller can never override it.
 */
async function postBinary<T>(
  path: string,
  body: Blob | ArrayBuffer,
  headers: Record<string, string> = {},
): Promise<T> {
  const allHeaders: Record<string, string> = { ...headers, "Content-Type": "application/octet-stream" };
  if (csrfToken) allHeaders["X-CSRF-Token"] = csrfToken;
  const response = await fetch(BASE + path, {
    method: "POST",
    headers: allHeaders,
    body,
    credentials: "same-origin",
  });
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
  put: <T>(path: string, body?: unknown) => request<T>("PUT", path, body),
  postBinary: <T>(path: string, body: Blob | ArrayBuffer, headers?: Record<string, string>) =>
    postBinary<T>(path, body, headers),
  del: <T>(path: string) => request<T>("DELETE", path),
};
