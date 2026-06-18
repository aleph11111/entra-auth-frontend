import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

// Parameterized lift of controlling-app frontend/src/middleware.ts.
// - ADR-0022 per-IP rate limiter on the auth callback path.
// - ADR-0029 server-side gate for protected app routes.
// - ADR-0051 v5 `auth((req) => …)` wrapper (the app passes in its own `auth`).

// The shape of the value NextAuth(config) returns as `auth`: a function that
// takes a per-request handler and returns the middleware entrypoint.
export type AuthWrapper = (
  handler: (req: NextRequest & { auth: unknown }) => Response | void | Promise<Response | void>,
) => (req: NextRequest) => Response | Promise<Response>;

export interface CreateAuthMiddlewareOptions {
  auth: AuthWrapper;
  protectedPaths: string[];
  rateLimit?: { windowMs?: number; maxRequests?: number; pathPrefix?: string };
}

type Bucket = { count: number; resetAt: number };

function clientIp(req: NextRequest): string {
  // Next 16 removed NextRequest.ip; use the forwarded headers (always set behind
  // the standalone reverse proxy — ADR-0021).
  const fwd = req.headers.get("x-forwarded-for");
  if (fwd) return fwd.split(",")[0].trim();
  return req.headers.get("x-real-ip") ?? "anonymous";
}

export function createAuthMiddleware(opts: CreateAuthMiddlewareOptions) {
  const windowMs = opts.rateLimit?.windowMs ?? 60_000;
  const maxRequests = opts.rateLimit?.maxRequests ?? 10;
  const rateLimitedPrefix = opts.rateLimit?.pathPrefix ?? "/api/auth/callback";
  const buckets = new Map<string, Bucket>();

  function check(ip: string): { ok: true } | { ok: false; retryAfter: number } {
    const now = Date.now();
    const bucket = buckets.get(ip);
    if (!bucket || now >= bucket.resetAt) {
      buckets.set(ip, { count: 1, resetAt: now + windowMs });
      return { ok: true };
    }
    if (bucket.count >= maxRequests) {
      return { ok: false, retryAfter: Math.ceil((bucket.resetAt - now) / 1000) };
    }
    bucket.count += 1;
    return { ok: true };
  }

  return opts.auth((req) => {
    const { pathname } = req.nextUrl;

    // Public + rate-limited: the callback terminates the OIDC dance without a
    // session, so never gate it — only apply the ADR-0022 rate limiter.
    if (pathname.startsWith(rateLimitedPrefix)) {
      const result = check(clientIp(req));
      if (!result.ok) {
        return new NextResponse(JSON.stringify({ error: "Too many requests" }), {
          status: 429,
          headers: {
            "Content-Type": "application/json",
            "Retry-After": String(result.retryAfter),
          },
        });
      }
      return NextResponse.next();
    }

    // Protected app route: require a session, else redirect to /login carrying
    // the original path as callbackUrl.
    const isProtected = opts.protectedPaths.some((p) => pathname.startsWith(p));
    if (isProtected && !req.auth) {
      const signInUrl = req.nextUrl.clone();
      signInUrl.pathname = "/login";
      signInUrl.searchParams.set("callbackUrl", req.nextUrl.href);
      return NextResponse.redirect(signInUrl);
    }
    return NextResponse.next();
  });
}
