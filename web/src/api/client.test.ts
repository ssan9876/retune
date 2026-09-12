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

/**
 * mockJSON answers every call with a fresh Response, because a response body
 * can only be read once.
 */
function mockJSON(body: unknown, status = 200) {
  fetchMock.mockImplementation(() =>
    Promise.resolve(
      new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }),
    ),
  );
}

describe("api client", () => {
  it("gets JSON from the admin API", async () => {
    mockJSON({ items: [], total: 0 });
    const result = await api.get<{ total: number }>("/devices");
    expect(result.total).toBe(0);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/admin/v1/devices");
    expect(init.credentials).toBe("same-origin");
  });

  it("sends the CSRF token on unsafe requests only", async () => {
    setCsrfToken("token-1");
    mockJSON({});
    await api.get("/devices");
    expect(fetchMock.mock.calls[0][1].headers["X-CSRF-Token"]).toBeUndefined();

    await api.post("/tokens", { label: "office" });
    const init = fetchMock.mock.calls[1][1];
    expect(init.method).toBe("POST");
    expect(init.headers["X-CSRF-Token"]).toBe("token-1");
    expect(JSON.parse(init.body)).toEqual({ label: "office" });
  });

  it("throws ApiError with the server's code and message", async () => {
    mockJSON({ code: "invalid_transition", message: "device is retired" }, 409);
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
    mockJSON({ code: "unauthenticated", message: "sign in" }, 401);
    await expect(api.get("/devices")).rejects.toBeInstanceOf(ApiError);
    expect(handler).toHaveBeenCalledOnce();
    onUnauthenticated(null);
  });

  it("returns nothing for 204 responses", async () => {
    fetchMock.mockImplementation(() => Promise.resolve(new Response(null, { status: 204 })));
    await expect(api.del("/session")).resolves.toBeUndefined();
  });
});
