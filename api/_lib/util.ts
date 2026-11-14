import { createHash } from "node:crypto";

/** BN128 (bn254) scalar field prime — the gatekeeper circuit's field. */
export const BN128_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Parse a non-negative integer given as a JS number, a decimal string, or a
 * 0x-prefixed hex string. Returns null for anything else (floats, negatives,
 * junk) so callers can fail closed.
 */
export function toBigIntStrict(v: unknown): bigint | null {
  if (typeof v === "bigint") return v >= 0n ? v : null;
  if (typeof v === "number") {
    if (!Number.isFinite(v) || !Number.isInteger(v) || v < 0) return null;
    return BigInt(v);
  }
  if (typeof v === "string") {
    const s = v.trim();
    if (/^0[xX][0-9a-fA-F]+$/.test(s)) return BigInt(s);
    if (/^[0-9]+$/.test(s)) return BigInt(s);
    return null;
  }
  return null;
}

/**
 * Parse a timestamp into epoch seconds. Accepts epoch seconds, epoch
 * milliseconds (numbers or numeric strings), and ISO-8601 strings.
 */
export function parseTimestampToSec(v: unknown): number | null {
  if (typeof v === "number" && Number.isFinite(v)) {
    return v > 1e11 ? Math.floor(v / 1000) : Math.floor(v);
  }
  if (typeof v === "string") {
    const s = v.trim();
    if (/^[0-9]+$/.test(s)) {
      const n = Number(s);
      return n > 1e11 ? Math.floor(n / 1000) : n;
    }
    const ms = Date.parse(s);
    if (!Number.isNaN(ms)) return Math.floor(ms / 1000);
  }
  return null;
}

/**
 * Map an envelope value to a BN128 field element for the decision proof.
 *
 * ASSUMED ENCODING (not stated on /build — see README "Proof module"):
 *  - integers and decimal strings are used as-is (mod p);
 *  - 0x-hex strings (addresses, 32-byte hashes) are read as integers, mod p;
 *  - any other string is hashed with SHA-256 and reduced mod p.
 */
export function fieldElementFromValue(v: string | number | bigint): bigint {
  const bi = toBigIntStrict(v);
  if (bi !== null) return bi % BN128_PRIME;
  const digest = createHash("sha256").update(String(v).trim(), "utf8").digest("hex");
  return BigInt("0x" + digest) % BN128_PRIME;
}

/** Deterministic per-task salt when the envelope does not carry one. */
export function deriveSalt(taskId: string): bigint {
  const digest = createHash("sha256")
    .update("gatekeeper-salt:" + taskId, "utf8")
    .digest("hex");
  return BigInt("0x" + digest) % BN128_PRIME;
}

/** Normalise an identifier string for equality checks (hex is case-insensitive). */
export function normalizeId(v: string): string {
  return v.trim().toLowerCase();
}

/** Coerce a string-or-number field to a string; null for other types. */
export function asString(v: unknown): string | null {
  if (typeof v === "string") return v;
  if (typeof v === "number" && Number.isFinite(v)) return String(v);
  return null;
}
