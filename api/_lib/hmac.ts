import { createHmac, timingSafeEqual } from "node:crypto";

export const SIGNATURE_HEADER = "x-agent-games-signature";

/** HMAC-SHA256 over the raw body, hex-encoded. */
export function computeSignature(secret: string, rawBody: Buffer | string): string {
  return createHmac("sha256", secret).update(rawBody).digest("hex");
}

/**
 * Verify an inbound x-agent-games-signature header against the RAW body.
 *
 * The signature encoding is not documented on /build (see README). We accept
 * the plain hex digest and tolerate a "sha256=" prefix. Comparison is
 * constant-time. Anything else fails closed.
 */
export function verifySignature(
  secret: string,
  rawBody: Buffer,
  headerValue: string | undefined,
): boolean {
  if (!headerValue) return false;
  let candidate = headerValue.trim();
  if (candidate.toLowerCase().startsWith("sha256=")) {
    candidate = candidate.slice("sha256=".length);
  }
  if (!/^[0-9a-fA-F]{64}$/.test(candidate)) return false;
  const expected = computeSignature(secret, rawBody);
  const a = Buffer.from(candidate.toLowerCase(), "utf8");
  const b = Buffer.from(expected, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Signature header value for an outbound response body. */
export function signBody(secret: string, body: string): string {
  return computeSignature(secret, body);
}
