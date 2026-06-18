// Fail-closed validation of the Auth.js session secret (controlling-app ADR-0042).
//
// Auth.js errors on a *missing* secret in production but not on a known
// placeholder left in `.env` (e.g. an un-rotated `.env.example` copy). A
// placeholder boots fine yet encrypts every session cookie with a public key.
//
// Edge-safe: no Node-only imports, so the app can call resolveAuthSecret() from
// both the Node runtime (lib/auth.ts) and the Edge runtime (middleware.ts).

export const PLACEHOLDER_VALUES: ReadonlySet<string> = new Set([
  "change-me",
  "change-me-to-a-random-secret-in-production",
  "your-secret-here",
  "secret",
]);

export function assertAuthSecret(value: string | undefined): string {
  if (!value || value.trim() === "") {
    throw new Error(
      "AUTH_SECRET is not set. Generate one with `openssl rand -base64 32` and add it to your environment / .env file.",
    );
  }
  if (PLACEHOLDER_VALUES.has(value)) {
    throw new Error(
      "AUTH_SECRET is set to a known placeholder value. Generate a real secret with `openssl rand -base64 32`.",
    );
  }
  return value;
}

// ADR-0051: prefer AUTH_SECRET (v5), fall back to the legacy NEXTAUTH_SECRET.
export function resolveAuthSecret(): string {
  return assertAuthSecret(process.env.AUTH_SECRET ?? process.env.NEXTAUTH_SECRET);
}
