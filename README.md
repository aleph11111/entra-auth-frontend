# @cb/entra-auth-frontend

Microsoft Entra ID authentication for Next.js App Router apps, on Auth.js v5.
Part of the `@cb/*` baseline toolkit. Install by git tag — there is no registry.

```bash
npm i "git+ssh://git@github.com/aleph11111/entra-auth-frontend.git#v0.1.0"
```

Peer deps: `next >=16`, `next-auth@5.0.0-beta.31`.

## The 5 wiring files your app writes

**`src/lib/auth.ts`**
```ts
import NextAuth from "next-auth";
import { createAuthConfig, resolveAuthSecret } from "@cb/entra-auth-frontend";

export const { handlers, auth } = NextAuth(
  createAuthConfig({
    azure: {
      tenantId: process.env.AZURE_AD_TENANT_ID!,
      clientId: process.env.AZURE_AD_CLIENT_ID!,
      clientSecret: process.env.AZURE_AD_CLIENT_SECRET!,
    },
    authSecret: resolveAuthSecret(),
    devBypass: { enabled: process.env.DEV_AUTH_BYPASS === "true", secret: process.env.DEV_AUTH_SECRET ?? "" },
    session: {
      idleMinutes: Number(process.env.SESSION_IDLE_TIMEOUT_MINUTES) || 30,
      absoluteHours: Number(process.env.SESSION_ABSOLUTE_TIMEOUT_HOURS) || 12,
    },
  }),
);
```

**`src/app/api/auth/[...nextauth]/route.ts`**
```ts
import { handlers } from "@/lib/auth";
export const { GET, POST } = handlers;
```

**`src/middleware.ts`**
```ts
import { createAuthMiddleware } from "@cb/entra-auth-frontend";
import { auth } from "./lib/auth";

export default createAuthMiddleware({
  auth,
  protectedPaths: ["/workspace", "/admin", "/settings"],
});

export const config = {
  matcher: [
    "/api/auth/callback/:provider*",
    "/workspace/:path*",
    "/admin/:path*",
    "/settings/:path*",
  ],
};
```

> **Note:** The per-IP callback rate limiter in `createAuthMiddleware` reads the client IP from the `x-forwarded-for` and `x-real-ip` headers (Next 16 removed `NextRequest.ip`). Deploy behind a reverse proxy that sets those headers; without them all requests share a single rate-limit bucket.

**`src/components/.../Providers.tsx`** — wrap the tree in `<SessionProvider>` from `next-auth/react`.

**`src/app/login/page.tsx`** — branded sign-in. Call `signIn("microsoft-entra-id", { callbackUrl })`. To show the offline dev-bypass form only when enabled, check `getProviders()` for `DEV_BYPASS_PROVIDER_ID`:
```ts
import { DEV_BYPASS_PROVIDER_ID } from "@cb/entra-auth-frontend";
// const providers = await getProviders();
// const devBypassAvailable = Boolean(providers?.[DEV_BYPASS_PROVIDER_ID]);
```

## Env vars

`AUTH_SECRET` (or legacy `NEXTAUTH_SECRET`), `AUTH_URL`, `AZURE_AD_TENANT_ID`,
`AZURE_AD_CLIENT_ID`, `AZURE_AD_CLIENT_SECRET`, `SESSION_IDLE_TIMEOUT_MINUTES`,
`SESSION_ABSOLUTE_TIMEOUT_HOURS`, `DEV_AUTH_BYPASS`, `DEV_AUTH_SECRET`.

For local dev without Entra: `DEV_AUTH_BYPASS=true` + a shared `DEV_AUTH_SECRET`
(the backend must use the same secret).

## Release checklist (no CI — manual)

1. `npm test` — all green.
2. `npm run build` — `dist/` emits.
3. Note any breaking changes in this README.
4. `git tag vX.Y.Z && git push --tags`.
5. Consuming apps bump their install ref to opt in.
