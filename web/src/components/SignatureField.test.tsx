import { describe, expect, it } from "vitest";

import { parseSignature, parseSignedOrder } from "./SignatureField";

describe("parseSignature", () => {
  it("reads what retune-sign sign-script prints", () => {
    expect(parseSignature('{"key_id":"abc","signature":"c2ln"}\n')).toEqual({ key_id: "abc", signature: "c2ln" });
  });

  it("refuses anything else", () => {
    expect(parseSignature("")).toBeNull();
    expect(parseSignature("c2ln")).toBeNull();
    expect(parseSignature('{"key_id":"abc"}')).toBeNull();
  });
});

describe("parseSignedOrder", () => {
  it("needs an expiry", () => {
    expect(parseSignedOrder('{"key_id":"a","signature":"s"}')).toBeNull();
    expect(
      parseSignedOrder('{"device":"d1","protected":false,"expires":"2026-09-23T14:00:00Z","key_id":"a","signature":"s"}'),
    ).toEqual({ device: "d1", protected: false, expires: "2026-09-23T14:00:00Z", key_id: "a", signature: "s" });
  });
});
