/**
 * Skill Hash Verification
 *
 * Provides cryptographic hash verification for ClawHub skill
 * manifests to ensure integrity of installed skills.
 *
 * @module security/skill-gate/hash-verify
 */

import { createHash } from "node:crypto";

/**
 * Hash verification result
 */
export interface HashVerifyResult {
  /** Whether the hash matches */
  valid: boolean;
  /** Computed hash of the content */
  computedHash: string;
  /** Expected hash from manifest */
  expectedHash: string;
  /** Reason for failure */
  reason?: string;
}

/**
 * Supported hash algorithms
 */
export type HashAlgorithm = "sha256" | "sha384" | "sha512";

/**
 * Compute hash of content
 */
export function computeHash(content: string, algorithm: HashAlgorithm = "sha256"): string {
  return createHash(algorithm).update(content, "utf-8").digest("hex");
}

/**
 * Verify content against an expected hash
 *
 * Uses constant-time comparison to prevent timing attacks.
 */
export function verifyHash(
  content: string,
  expectedHash: string,
  algorithm: HashAlgorithm = "sha256",
): HashVerifyResult {
  const computedHash = computeHash(content, algorithm);

  // Normalize to lowercase for comparison
  const normalizedExpected = expectedHash.toLowerCase().trim();
  const normalizedComputed = computedHash.toLowerCase();

  // Constant-time comparison
  if (normalizedExpected.length !== normalizedComputed.length) {
    return {
      valid: false,
      computedHash: normalizedComputed,
      expectedHash: normalizedExpected,
      reason: "Hash length mismatch",
    };
  }

  let mismatch = 0;
  for (let i = 0; i < normalizedExpected.length; i++) {
    mismatch |= normalizedExpected.charCodeAt(i) ^ normalizedComputed.charCodeAt(i);
  }

  const valid = mismatch === 0;
  return {
    valid,
    computedHash: normalizedComputed,
    expectedHash: normalizedExpected,
    reason: valid ? undefined : "Hash mismatch",
  };
}

/**
 * Parse a Subresource Integrity (SRI) hash string
 *
 * Format: "algorithm-base64hash"
 * Example: "sha256-abc123..."
 */
export function parseSriHash(sri: string): { algorithm: HashAlgorithm; hash: string } | null {
  const match = /^(sha256|sha384|sha512)-(.+)$/.exec(sri);
  if (!match) {
    return null;
  }
  return {
    algorithm: match[1] as HashAlgorithm,
    hash: Buffer.from(match[2], "base64").toString("hex"),
  };
}

/**
 * Create an SRI hash string from content
 */
export function createSriHash(content: string, algorithm: HashAlgorithm = "sha256"): string {
  const hash = createHash(algorithm).update(content, "utf-8").digest("base64");
  return `${algorithm}-${hash}`;
}
