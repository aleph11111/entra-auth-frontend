import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createAuthConfig } from "./config";

// Narrow helpers — the Auth.js callback types are wide; tests only touch the
// fields ADR-0048 reads/writes.
type Callback = (a: Record<string, unknown>) => Promise<Record<string, unknown>>;

function makeConfig(overrides: Partial<Parameters<typeof createAuthConfig>[0]> = {}) {
  return createAuthConfig({
    azure: { tenantId: "tenant-abc", clientId: "client-abc", clientSecret: "client-secret-abc" },
    authSecret: "test-secret-not-a-placeholder-value-123456",
    ...overrides,
  });
}

const jwtCb = (cfg: ReturnType<typeof createAuthConfig>) =>
  (cfg.callbacks!.jwt as unknown as Callback);
const sessionCb = (cfg: ReturnType<typeof createAuthConfig>) =>
  (cfg.callbacks!.session as unknown as Callback);

const now = () => Math.floor(Date.now() / 1000);
const fetchMock = vi.fn();

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("session-lifetime config (ADR-0048)", () => {
  it("sets a 30-minute sliding idle timeout by default", () => {
    expect(makeConfig().session?.maxAge).toBe(30 * 60);
  });

  it("honours an overridden idle timeout", () => {
    expect(makeConfig({ session: { idleMinutes: 45 } }).session?.maxAge).toBe(45 * 60);
  });

  it("makes the session cookie a browser-session cookie (no maxAge/expires)", () => {
    const cfg = makeConfig();
    const opts = cfg.cookies?.sessionToken?.options ?? {};
    expect("maxAge" in opts).toBe(false);
    expect("expires" in opts).toBe(false);
  });

  it("defaults to the v5 cookie name and honours an override", () => {
    expect(makeConfig().cookies?.sessionToken?.name).toBe("authjs.session-token");
    expect(makeConfig({ cookieName: "next-auth.session-token" }).cookies?.sessionToken?.name).toBe(
      "next-auth.session-token",
    );
  });
});

describe("providers", () => {
  it("registers only Entra when dev bypass is off", () => {
    expect(makeConfig().providers).toHaveLength(1);
  });
  it("adds the dev-bypass credentials provider when enabled with a secret", () => {
    const cfg = makeConfig({ devBypass: { enabled: true, secret: "shared-dev-secret" } });
    expect(cfg.providers).toHaveLength(2);
  });
  it("omits the dev-bypass provider when enabled but secret is empty", () => {
    const cfg = makeConfig({ devBypass: { enabled: true, secret: "" } });
    expect(cfg.providers).toHaveLength(1);
  });
});

describe("jwt callback — initial sign-in (ADR-0048)", () => {
  it("persists id_token, refresh_token, expiry, and loginAt", async () => {
    const account = { id_token: "id-1", refresh_token: "refresh-1", expires_at: now() + 3600 };
    const token = await jwtCb(makeConfig())({ token: {}, account });
    expect(token.idToken).toBe("id-1");
    expect(token.refreshToken).toBe("refresh-1");
    expect(token.expiresAt).toBe(account.expires_at);
    expect(token.loginAt).toBeGreaterThan(0);
    expect(token.error).toBeUndefined();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("jwt callback — silent refresh (ADR-0048)", () => {
  it("does not refresh while the id_token is comfortably valid", async () => {
    const token = { idToken: "id-1", refreshToken: "refresh-1", loginAt: now(), expiresAt: now() + 3600 };
    const result = await jwtCb(makeConfig())({ token });
    expect(result.idToken).toBe("id-1");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refreshes within the skew window and rotates the refresh token", async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ id_token: "id-2", refresh_token: "refresh-2", expires_in: 3600 }),
    });
    const token = { idToken: "id-1", refreshToken: "refresh-1", loginAt: now(), expiresAt: now() + 30 };
    const result = await jwtCb(makeConfig())({ token });
    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toContain("login.microsoftonline.com/tenant-abc/oauth2/v2.0/token");
    expect((init.body as URLSearchParams).get("grant_type")).toBe("refresh_token");
    expect((init.body as URLSearchParams).get("refresh_token")).toBe("refresh-1");
    expect(result.idToken).toBe("id-2");
    expect(result.refreshToken).toBe("refresh-2");
    expect(result.expiresAt).toBeGreaterThan(now() + 3500);
    expect(result.error).toBeUndefined();
  });

  it("keeps the old refresh token if Entra does not rotate it", async () => {
    fetchMock.mockResolvedValueOnce({ ok: true, json: async () => ({ id_token: "id-2", expires_in: 3600 }) });
    const token = { idToken: "id-1", refreshToken: "refresh-1", loginAt: now(), expiresAt: now() - 10 };
    const result = await jwtCb(makeConfig())({ token });
    expect(result.refreshToken).toBe("refresh-1");
  });
});

describe("jwt callback — failure modes (ADR-0048)", () => {
  it("sets error=RefreshFailed when the refresh token is revoked/expired", async () => {
    fetchMock.mockResolvedValueOnce({ ok: false, json: async () => ({ error: "invalid_grant" }) });
    const token = { idToken: "id-1", refreshToken: "refresh-1", loginAt: now(), expiresAt: now() - 10 };
    const result = await jwtCb(makeConfig())({ token });
    expect(result.error).toBe("RefreshFailed");
  });

  it("sets error=RefreshFailed when the token endpoint is unreachable", async () => {
    fetchMock.mockRejectedValueOnce(new Error("network"));
    const token = { idToken: "id-1", refreshToken: "refresh-1", loginAt: now(), expiresAt: now() - 10 };
    const result = await jwtCb(makeConfig())({ token });
    expect(result.error).toBe("RefreshFailed");
  });

  it("sets error=SessionExpired once the absolute cap is exceeded, without refreshing", async () => {
    const token = { idToken: "id-1", refreshToken: "refresh-1", loginAt: now() - 13 * 3600, expiresAt: now() + 3600 };
    const result = await jwtCb(makeConfig())({ token });
    expect(result.error).toBe("SessionExpired");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("session callback (ADR-0048)", () => {
  it("surfaces the id_token as accessToken and propagates error", async () => {
    const result = await sessionCb(makeConfig())({ session: {}, token: { idToken: "id-9", error: "RefreshFailed" } });
    expect(result.accessToken).toBe("id-9");
    expect(result.error).toBe("RefreshFailed");
  });

  it("leaves error undefined for a healthy session", async () => {
    const result = await sessionCb(makeConfig())({ session: {}, token: { idToken: "id-9" } });
    expect(result.accessToken).toBe("id-9");
    expect(result.error).toBeUndefined();
  });
});
