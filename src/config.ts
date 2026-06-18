import type { NextAuthConfig } from "next-auth";
import type { JWT } from "next-auth/jwt";
import MicrosoftEntraID from "next-auth/providers/microsoft-entra-id";
import Credentials from "next-auth/providers/credentials";
import { SignJWT } from "jose";

// Parameterized lift of controlling-app frontend/src/lib/auth.config.ts.
// Behaviour (ADR-0040 id_token forwarding, ADR-0048 silent refresh + idle/
// absolute caps, ADR-0051 v5 provider/cookie shape) is unchanged; all inputs
// that were module-level process.env reads are now function arguments.

export const DEV_BYPASS_PROVIDER_ID = "dev-bypass";

const DEFAULT_SCOPE = "openid profile email offline_access";
const REFRESH_SKEW_SECONDS = 60;

export interface CreateAuthConfigOptions {
  azure: { tenantId: string; clientId: string; clientSecret: string };
  authSecret: string;
  devBypass?: { enabled: boolean; secret: string };
  session?: { idleMinutes?: number; absoluteHours?: number };
  scope?: string;
  cookieName?: string;
  authUrl?: string;
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

// Mint an HS256 id_token carrying the claims the backend reads (`email`, with
// `preferred_username` as the Entra-parity fallback). Signed with the shared dev
// secret so the backend's DevHS256Verifier validates it offline.
export async function mintDevIdToken(opts: {
  email: string;
  name: string;
  secret: string;
  expiresIn?: string;
}): Promise<string> {
  const key = new TextEncoder().encode(opts.secret);
  return new SignJWT({ email: opts.email, name: opts.name, preferred_username: opts.email })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(`dev|${opts.email}`)
    .setIssuedAt()
    .setExpirationTime(opts.expiresIn ?? "12h")
    .sign(key);
}

export function createAuthConfig(opts: CreateAuthConfigOptions): NextAuthConfig {
  const { tenantId, clientId, clientSecret } = opts.azure;
  const scope = opts.scope ?? DEFAULT_SCOPE;
  const idleSeconds = (opts.session?.idleMinutes ?? 30) * 60;
  const absoluteSeconds = (opts.session?.absoluteHours ?? 12) * 3600;
  const devBypassEnabled = Boolean(opts.devBypass?.enabled) && (opts.devBypass?.secret.length ?? 0) > 0;

  if (opts.devBypass?.enabled && !opts.devBypass.secret) {
    // Loud, non-fatal: operator asked for the bypass but it cannot work without
    // a secret the backend also has. Fail closed (provider not added).
    console.warn("[auth] dev bypass enabled but secret is empty — offline bypass disabled.");
  }

  // Exchange the stored refresh token for a fresh id_token at the Entra token
  // endpoint. Entra rotates the refresh token, so persist the new one. On any
  // failure mark the token in error so the session callback can surface it.
  async function refreshIdToken(token: JWT): Promise<JWT> {
    try {
      const response = await fetch(
        `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
        {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            client_id: clientId,
            client_secret: clientSecret,
            grant_type: "refresh_token",
            refresh_token: token.refreshToken as string,
            scope,
          }),
        },
      );
      const refreshed = await response.json();
      if (!response.ok) {
        throw new Error(refreshed?.error ?? "refresh_failed");
      }
      return {
        ...token,
        idToken: refreshed.id_token,
        expiresAt: nowSeconds() + (Number(refreshed.expires_in) || 3600),
        refreshToken: refreshed.refresh_token ?? token.refreshToken,
        error: undefined,
      };
    } catch {
      return { ...token, error: "RefreshFailed" };
    }
  }

  const secureSource = opts.authUrl ?? process.env.AUTH_URL ?? process.env.NEXTAUTH_URL ?? "";
  const useSecureCookies = secureSource.startsWith("https://");
  const cookiePrefix = useSecureCookies ? "__Secure-" : "";
  const cookieName = opts.cookieName ?? "authjs.session-token";

  return {
    trustHost: true,
    secret: opts.authSecret,
    providers: [
      MicrosoftEntraID({
        clientId,
        clientSecret,
        issuer: `https://login.microsoftonline.com/${tenantId}/v2.0`,
        authorization: { params: { scope } },
      }),
      ...(devBypassEnabled
        ? [
            Credentials({
              id: DEV_BYPASS_PROVIDER_ID,
              name: "Offline Dev Bypass",
              credentials: { email: { label: "Email", type: "email" } },
              async authorize(creds) {
                const raw = typeof creds?.email === "string" ? creds.email.trim() : "";
                const email = raw || "dev@localhost";
                const name = email.split("@")[0];
                const idToken = await mintDevIdToken({ email, name, secret: opts.devBypass!.secret });
                return { id: email, email, name, idToken };
              },
            }),
          ]
        : []),
    ],
    session: {
      strategy: "jwt",
      maxAge: idleSeconds,
    },
    cookies: {
      sessionToken: {
        name: `${cookiePrefix}${cookieName}`,
        options: {
          httpOnly: true,
          sameSite: "lax",
          path: "/",
          secure: useSecureCookies,
        },
      },
    },
    callbacks: {
      async jwt({ token, account, user }) {
        if (account?.provider === DEV_BYPASS_PROVIDER_ID) {
          token.idToken = (user as { idToken?: string } | undefined)?.idToken;
          token.loginAt = nowSeconds();
          token.error = undefined;
          return token;
        }
        if (account) {
          token.idToken = account.id_token;
          token.refreshToken = account.refresh_token;
          token.expiresAt = account.expires_at;
          token.loginAt = nowSeconds();
          token.error = undefined;
          return token;
        }
        const loginAt = token.loginAt as number | undefined;
        if (loginAt && nowSeconds() - loginAt >= absoluteSeconds) {
          return { ...token, error: "SessionExpired" };
        }
        const expiresAt = token.expiresAt as number | undefined;
        if (expiresAt && nowSeconds() < expiresAt - REFRESH_SKEW_SECONDS) {
          return token;
        }
        if (token.refreshToken) {
          return refreshIdToken(token);
        }
        return token;
      },
      async session({ session, token }) {
        (session as { accessToken?: string }).accessToken = token.idToken as string | undefined;
        (session as { error?: string }).error = token.error as string | undefined;
        return session;
      },
    },
    pages: {
      signIn: "/login",
    },
  };
}
