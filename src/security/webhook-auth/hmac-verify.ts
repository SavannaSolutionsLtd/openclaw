/**
 * HMAC Signature Verification
 *
 * Provides timing-safe HMAC verification for webhook payloads,
 * supporting multiple signature schemes used by popular services.
 *
 * @module security/webhook-auth/hmac-verify
 */

import { timingSafeEqual, createHmac } from "node:crypto";

/**
 * Supported HMAC algorithms
 */
export type HmacAlgorithm = "sha1" | "sha256" | "sha384" | "sha512";

/**
 * HMAC verification result
 */
export interface HmacVerifyResult {
  /** Whether the signature is valid */
  valid: boolean;
  /** Algorithm used */
  algorithm: HmacAlgorithm;
  /** Reason for failure */
  reason?: string;
}

/**
 * Verify a webhook HMAC signature
 *
 * Uses timing-safe comparison to prevent timing attacks.
 *
 * @param payload - Raw request payload
 * @param signature - Signature to verify (hex-encoded)
 * @param secret - HMAC secret key
 * @param algorithm - HMAC algorithm (default: sha256)
 */
export function verifyWebhookSignature(
  payload: Buffer | string,
  signature: string,
  secret: string,
  algorithm: HmacAlgorithm = "sha256",
): HmacVerifyResult {
  if (!payload || !signature || !secret) {
    return {
      valid: false,
      algorithm,
      reason: "Missing payload, signature, or secret",
    };
  }

  const payloadBuffer = typeof payload === "string" ? Buffer.from(payload) : payload;
  const expected = createHmac(algorithm, secret).update(payloadBuffer).digest("hex");

  // Strip common prefixes (e.g., "sha256=..." used by GitHub)
  const cleanSignature = signature.replace(/^sha\d+=/, "").trim();

  try {
    const sigBuffer = Buffer.from(cleanSignature, "hex");
    const expBuffer = Buffer.from(expected, "hex");

    if (sigBuffer.length !== expBuffer.length) {
      return {
        valid: false,
        algorithm,
        reason: "Signature length mismatch",
      };
    }

    const valid = timingSafeEqual(sigBuffer, expBuffer);
    return {
      valid,
      algorithm,
      reason: valid ? undefined : "Signature mismatch",
    };
  } catch {
    return {
      valid: false,
      algorithm,
      reason: "Invalid signature format",
    };
  }
}

/**
 * Compute HMAC signature for a payload
 */
export function computeHmacSignature(
  payload: Buffer | string,
  secret: string,
  algorithm: HmacAlgorithm = "sha256",
): string {
  const payloadBuffer = typeof payload === "string" ? Buffer.from(payload) : payload;
  return createHmac(algorithm, secret).update(payloadBuffer).digest("hex");
}

/**
 * Parse a webhook signature header
 *
 * Supports formats:
 * - Raw hex: "abcdef1234..."
 * - Prefixed: "sha256=abcdef1234..."
 * - Multiple: "v1=abcdef,v2=123456" (returns first match)
 */
export function parseSignatureHeader(
  header: string,
): { signature: string; algorithm?: HmacAlgorithm } | null {
  if (!header) {
    return null;
  }

  const trimmed = header.trim();

  // Check for algorithm prefix (e.g., "sha256=...")
  const prefixMatch = /^(sha(?:1|256|384|512))=(.+)$/i.exec(trimmed);
  if (prefixMatch) {
    return {
      algorithm: prefixMatch[1].toLowerCase() as HmacAlgorithm,
      signature: prefixMatch[2],
    };
  }

  // Check for versioned format (e.g., "v1=...")
  const versionedMatch = /^v\d+=(.+)$/.exec(trimmed);
  if (versionedMatch) {
    return { signature: versionedMatch[1] };
  }

  // Raw hex signature
  if (/^[0-9a-f]+$/i.test(trimmed)) {
    return { signature: trimmed };
  }

  return null;
}
