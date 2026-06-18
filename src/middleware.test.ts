import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { createAuthMiddleware } from "./middleware";

// Fake `auth` wrapper: NextAuth()'s auth() takes a handler and returns a
// function that, when called with a request, attaches `auth` to it and invokes
// the handler. We let the test set whether a session exists.
function fakeAuth(session: unknown) {
  return (handler: (req: any) => any) => (req: any) => {
    req.auth = session;
    return handler(req);
  };
}

function reqFor(path: string, ip = "1.2.3.4") {
  const r = new NextRequest(`https://app.example.com${path}`, {
    headers: { "x-forwarded-for": ip },
  });
  return r;
}

const PROTECTED = ["/workspace", "/admin"];

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

describe("protected-route gating", () => {
  it("redirects unauthenticated requests to /login with callbackUrl", () => {
    const mw = createAuthMiddleware({ auth: fakeAuth(null), protectedPaths: PROTECTED });
    const res = mw(reqFor("/workspace/reports"));
    expect(res.status).toBe(307); // NextResponse.redirect default
    const location = res.headers.get("location")!;
    expect(location).toContain("/login");
    expect(location).toContain("callbackUrl=");
    expect(decodeURIComponent(location)).toContain("/workspace/reports");
  });

  it("passes authenticated requests through", () => {
    const mw = createAuthMiddleware({ auth: fakeAuth({ user: { email: "a@b.c" } }), protectedPaths: PROTECTED });
    const res = mw(reqFor("/workspace/reports"));
    expect(res.status).toBe(200); // NextResponse.next()
  });

  it("passes non-protected paths through without a session", () => {
    const mw = createAuthMiddleware({ auth: fakeAuth(null), protectedPaths: PROTECTED });
    const res = mw(reqFor("/public/landing"));
    expect(res.status).toBe(200);
  });
});

describe("callback rate limiting", () => {
  it("allows the first 10 callback requests then 429s the 11th", () => {
    const mw = createAuthMiddleware({ auth: fakeAuth(null), protectedPaths: PROTECTED });
    for (let i = 0; i < 10; i++) {
      const res = mw(reqFor("/api/auth/callback/microsoft-entra-id"));
      expect(res.status).toBe(200);
    }
    const limited = mw(reqFor("/api/auth/callback/microsoft-entra-id"));
    expect(limited.status).toBe(429);
    expect(limited.headers.get("Retry-After")).toBeTruthy();
  });

  it("resets the bucket after the window elapses", () => {
    const mw = createAuthMiddleware({ auth: fakeAuth(null), protectedPaths: PROTECTED });
    for (let i = 0; i < 10; i++) mw(reqFor("/api/auth/callback/x"));
    expect(mw(reqFor("/api/auth/callback/x")).status).toBe(429);
    vi.advanceTimersByTime(60_001);
    expect(mw(reqFor("/api/auth/callback/x")).status).toBe(200);
  });

  it("never gates the callback path even without a session", () => {
    const mw = createAuthMiddleware({ auth: fakeAuth(null), protectedPaths: PROTECTED });
    const res = mw(reqFor("/api/auth/callback/microsoft-entra-id"));
    expect(res.status).toBe(200); // rate-limit pass-through, not a /login redirect
  });
});
