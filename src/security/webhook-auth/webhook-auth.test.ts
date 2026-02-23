import { describe, expect, test } from "vitest";
import {
  verifyWebhookSignature,
  computeHmacSignature,
  parseSignatureHeader,
  createIpAllowlist,
  ipMatchesCidr,
} from "./index.js";

// =============================================================================
// HMAC Verification Tests
// =============================================================================

describe("computeHmacSignature", () => {
  test("computes hex-encoded HMAC-SHA256 by default", () => {
    const sig = computeHmacSignature("payload", "secret");
    expect(sig).toMatch(/^[0-9a-f]+$/);
  });

  test("produces deterministic output", () => {
    const sig1 = computeHmacSignature("payload", "secret");
    const sig2 = computeHmacSignature("payload", "secret");
    expect(sig1).toBe(sig2);
  });

  test("different payloads produce different signatures", () => {
    const sig1 = computeHmacSignature("payload-a", "secret");
    const sig2 = computeHmacSignature("payload-b", "secret");
    expect(sig1).not.toBe(sig2);
  });

  test("different secrets produce different signatures", () => {
    const sig1 = computeHmacSignature("payload", "secret-a");
    const sig2 = computeHmacSignature("payload", "secret-b");
    expect(sig1).not.toBe(sig2);
  });

  test("supports SHA-1", () => {
    const sig = computeHmacSignature("payload", "secret", "sha1");
    // SHA-1 produces 40 hex chars
    expect(sig).toMatch(/^[0-9a-f]{40}$/);
  });

  test("supports SHA-384", () => {
    const sig = computeHmacSignature("payload", "secret", "sha384");
    // SHA-384 produces 96 hex chars
    expect(sig).toMatch(/^[0-9a-f]{96}$/);
  });

  test("supports SHA-512", () => {
    const sig = computeHmacSignature("payload", "secret", "sha512");
    // SHA-512 produces 128 hex chars
    expect(sig).toMatch(/^[0-9a-f]{128}$/);
  });

  test("works with Buffer payloads", () => {
    const payload = Buffer.from("payload");
    const sig = computeHmacSignature(payload, "secret");
    const sigStr = computeHmacSignature("payload", "secret");
    expect(sig).toBe(sigStr);
  });
});

describe("verifyWebhookSignature", () => {
  const secret = "test-webhook-secret";
  const payload = '{"event":"push","ref":"refs/heads/main"}';

  test("verifies valid signature", () => {
    const sig = computeHmacSignature(payload, secret);
    const result = verifyWebhookSignature(payload, sig, secret);
    expect(result.valid).toBe(true);
    expect(result.algorithm).toBe("sha256");
    expect(result.reason).toBeUndefined();
  });

  test("rejects invalid signature", () => {
    const result = verifyWebhookSignature(payload, "0".repeat(64), secret);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("Signature mismatch");
  });

  test("strips sha256= prefix (GitHub-style)", () => {
    const sig = computeHmacSignature(payload, secret);
    const result = verifyWebhookSignature(payload, `sha256=${sig}`, secret);
    expect(result.valid).toBe(true);
  });

  test("strips sha1= prefix", () => {
    const sig = computeHmacSignature(payload, secret, "sha1");
    const result = verifyWebhookSignature(payload, `sha1=${sig}`, secret, "sha1");
    expect(result.valid).toBe(true);
  });

  test("handles missing payload", () => {
    const result = verifyWebhookSignature("", "sig", secret);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("Missing");
  });

  test("handles missing signature", () => {
    const result = verifyWebhookSignature(payload, "", secret);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("Missing");
  });

  test("handles missing secret", () => {
    const result = verifyWebhookSignature(payload, "sig", "");
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("Missing");
  });

  test("handles invalid hex signature", () => {
    const result = verifyWebhookSignature(payload, "not-hex-data!!!", secret);
    expect(result.valid).toBe(false);
  });

  test("rejects signature with wrong length", () => {
    const result = verifyWebhookSignature(payload, "abcd", secret);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("length mismatch");
  });

  test("works with Buffer payloads", () => {
    const bufPayload = Buffer.from(payload);
    const sig = computeHmacSignature(bufPayload, secret);
    const result = verifyWebhookSignature(bufPayload, sig, secret);
    expect(result.valid).toBe(true);
  });

  test("uses specified algorithm", () => {
    const sig = computeHmacSignature(payload, secret, "sha512");
    const result = verifyWebhookSignature(payload, sig, secret, "sha512");
    expect(result.valid).toBe(true);
    expect(result.algorithm).toBe("sha512");
  });

  test("fails with wrong algorithm", () => {
    const sig = computeHmacSignature(payload, secret, "sha256");
    const result = verifyWebhookSignature(payload, sig, secret, "sha512");
    expect(result.valid).toBe(false);
  });
});

// =============================================================================
// Signature Header Parsing Tests
// =============================================================================

describe("parseSignatureHeader", () => {
  test("parses sha256= prefixed header", () => {
    const result = parseSignatureHeader("sha256=abcdef1234567890");
    expect(result).not.toBeNull();
    expect(result!.algorithm).toBe("sha256");
    expect(result!.signature).toBe("abcdef1234567890");
  });

  test("parses sha1= prefixed header", () => {
    const result = parseSignatureHeader("sha1=abcdef1234567890");
    expect(result).not.toBeNull();
    expect(result!.algorithm).toBe("sha1");
    expect(result!.signature).toBe("abcdef1234567890");
  });

  test("parses sha384= prefixed header", () => {
    const result = parseSignatureHeader("sha384=abcdef1234567890");
    expect(result).not.toBeNull();
    expect(result!.algorithm).toBe("sha384");
  });

  test("parses sha512= prefixed header", () => {
    const result = parseSignatureHeader("sha512=abcdef1234567890");
    expect(result).not.toBeNull();
    expect(result!.algorithm).toBe("sha512");
  });

  test("parses versioned format (v1=...)", () => {
    const result = parseSignatureHeader("v1=abcdef1234567890");
    expect(result).not.toBeNull();
    expect(result!.signature).toBe("abcdef1234567890");
    expect(result!.algorithm).toBeUndefined();
  });

  test("parses raw hex signature", () => {
    const result = parseSignatureHeader("abcdef1234567890");
    expect(result).not.toBeNull();
    expect(result!.signature).toBe("abcdef1234567890");
    expect(result!.algorithm).toBeUndefined();
  });

  test("returns null for empty string", () => {
    expect(parseSignatureHeader("")).toBeNull();
  });

  test("returns null for invalid format", () => {
    expect(parseSignatureHeader("not-a-valid-signature!@#")).toBeNull();
  });

  test("handles whitespace", () => {
    const result = parseSignatureHeader("  sha256=abcdef1234567890  ");
    expect(result).not.toBeNull();
    expect(result!.algorithm).toBe("sha256");
  });

  test("is case-insensitive for algorithm prefix", () => {
    const result = parseSignatureHeader("SHA256=abcdef1234567890");
    expect(result).not.toBeNull();
    expect(result!.algorithm).toBe("sha256");
  });
});

// =============================================================================
// IP Allowlist Tests
// =============================================================================

describe("ipMatchesCidr", () => {
  test("matches exact IP with /32", () => {
    expect(ipMatchesCidr("192.168.1.1", "192.168.1.1/32")).toBe(true);
  });

  test("rejects different IP with /32", () => {
    expect(ipMatchesCidr("192.168.1.2", "192.168.1.1/32")).toBe(false);
  });

  test("matches within /24 subnet", () => {
    expect(ipMatchesCidr("192.168.1.100", "192.168.1.0/24")).toBe(true);
    expect(ipMatchesCidr("192.168.1.0", "192.168.1.0/24")).toBe(true);
    expect(ipMatchesCidr("192.168.1.255", "192.168.1.0/24")).toBe(true);
  });

  test("rejects outside /24 subnet", () => {
    expect(ipMatchesCidr("192.168.2.1", "192.168.1.0/24")).toBe(false);
  });

  test("matches within /16 subnet", () => {
    expect(ipMatchesCidr("10.0.5.100", "10.0.0.0/16")).toBe(true);
    expect(ipMatchesCidr("10.0.255.255", "10.0.0.0/16")).toBe(true);
  });

  test("rejects outside /16 subnet", () => {
    expect(ipMatchesCidr("10.1.0.1", "10.0.0.0/16")).toBe(false);
  });

  test("/0 matches everything", () => {
    expect(ipMatchesCidr("1.2.3.4", "0.0.0.0/0")).toBe(true);
    expect(ipMatchesCidr("255.255.255.255", "0.0.0.0/0")).toBe(true);
  });

  test("handles invalid IP gracefully", () => {
    expect(ipMatchesCidr("not-an-ip", "192.168.1.0/24")).toBe(false);
    expect(ipMatchesCidr("256.256.256.256", "192.168.1.0/24")).toBe(false);
  });

  test("handles invalid CIDR gracefully", () => {
    expect(ipMatchesCidr("192.168.1.1", "invalid")).toBe(false);
    expect(ipMatchesCidr("192.168.1.1", "192.168.1.0/33")).toBe(false);
    expect(ipMatchesCidr("192.168.1.1", "192.168.1.0/-1")).toBe(false);
  });
});

describe("createIpAllowlist", () => {
  test("allows IPs in allowlist (single IPs)", () => {
    const allowlist = createIpAllowlist(["192.168.1.1", "10.0.0.1"]);
    expect(allowlist.check("192.168.1.1").allowed).toBe(true);
    expect(allowlist.check("10.0.0.1").allowed).toBe(true);
  });

  test("rejects IPs not in allowlist", () => {
    const allowlist = createIpAllowlist(["192.168.1.1"]);
    const result = allowlist.check("192.168.1.2");
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("not in allowlist");
  });

  test("supports CIDR ranges", () => {
    const allowlist = createIpAllowlist(["192.168.1.0/24"]);
    expect(allowlist.check("192.168.1.50").allowed).toBe(true);
    expect(allowlist.check("192.168.1.200").allowed).toBe(true);
    expect(allowlist.check("192.168.2.1").allowed).toBe(false);
  });

  test("empty allowlist allows all IPs", () => {
    const allowlist = createIpAllowlist([]);
    expect(allowlist.check("1.2.3.4").allowed).toBe(true);
    expect(allowlist.check("10.0.0.1").allowed).toBe(true);
  });

  test("returns matched rule when allowed", () => {
    const allowlist = createIpAllowlist(["192.168.1.0/24"]);
    const result = allowlist.check("192.168.1.50");
    expect(result.allowed).toBe(true);
    expect(result.matchedRule).toBe("192.168.1.0/24");
  });

  test("normalizes single IPs to /32", () => {
    const allowlist = createIpAllowlist(["192.168.1.1"]);
    const rules = allowlist.getRules();
    expect(rules).toEqual(["192.168.1.1/32"]);
  });

  test("preserves CIDR notation", () => {
    const allowlist = createIpAllowlist(["10.0.0.0/8"]);
    const rules = allowlist.getRules();
    expect(rules).toEqual(["10.0.0.0/8"]);
  });

  test("getRules returns a copy", () => {
    const allowlist = createIpAllowlist(["192.168.1.1"]);
    const rules1 = allowlist.getRules();
    const rules2 = allowlist.getRules();
    expect(rules1).toEqual(rules2);
    // Mutating one doesn't affect the other
    rules1.push("extra");
    expect(allowlist.getRules().length).toBe(1);
  });

  test("supports mixed single IPs and CIDR", () => {
    const allowlist = createIpAllowlist(["192.168.1.1", "10.0.0.0/8"]);
    expect(allowlist.check("192.168.1.1").allowed).toBe(true);
    expect(allowlist.check("10.5.5.5").allowed).toBe(true);
    expect(allowlist.check("172.16.0.1").allowed).toBe(false);
  });
});
