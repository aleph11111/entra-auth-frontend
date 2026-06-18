import { afterEach, describe, expect, it } from "vitest";
import { assertAuthSecret, resolveAuthSecret } from "./env";

describe("assertAuthSecret", () => {
  it("returns a real secret unchanged", () => {
    expect(assertAuthSecret("a-real-rotated-secret-9f8a7b")).toBe("a-real-rotated-secret-9f8a7b");
  });

  it("throws when unset", () => {
    expect(() => assertAuthSecret(undefined)).toThrow(/AUTH_SECRET is not set/);
  });

  it("throws when empty/whitespace", () => {
    expect(() => assertAuthSecret("   ")).toThrow(/AUTH_SECRET is not set/);
  });

  it("throws on a known placeholder", () => {
    expect(() => assertAuthSecret("change-me")).toThrow(/placeholder/);
    expect(() => assertAuthSecret("your-secret-here")).toThrow(/placeholder/);
  });
});

describe("resolveAuthSecret", () => {
  const saved = { ...process.env };
  afterEach(() => {
    process.env = { ...saved };
  });

  it("prefers AUTH_SECRET", () => {
    process.env.AUTH_SECRET = "primary-secret-123456";
    process.env.NEXTAUTH_SECRET = "legacy-secret-123456";
    expect(resolveAuthSecret()).toBe("primary-secret-123456");
  });

  it("falls back to NEXTAUTH_SECRET", () => {
    delete process.env.AUTH_SECRET;
    process.env.NEXTAUTH_SECRET = "legacy-secret-123456";
    expect(resolveAuthSecret()).toBe("legacy-secret-123456");
  });

  it("throws when neither is set", () => {
    delete process.env.AUTH_SECRET;
    delete process.env.NEXTAUTH_SECRET;
    expect(() => resolveAuthSecret()).toThrow(/AUTH_SECRET is not set/);
  });
});
