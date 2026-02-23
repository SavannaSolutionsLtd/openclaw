import { describe, expect, test } from "vitest";
import {
  computeHash,
  verifyHash,
  parseSriHash,
  createSriHash,
  createSkillGate,
  SkillInstallationError,
  DEFAULT_SKILL_GATE_CONFIG,
  type SkillApprovalRequest,
} from "./index.js";

// =============================================================================
// Hash Verification Tests
// =============================================================================

describe("computeHash", () => {
  test("computes SHA-256 hash by default", () => {
    const hash = computeHash("hello world");
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  test("produces deterministic output", () => {
    const hash1 = computeHash("test content");
    const hash2 = computeHash("test content");
    expect(hash1).toBe(hash2);
  });

  test("different inputs produce different hashes", () => {
    const hash1 = computeHash("input-a");
    const hash2 = computeHash("input-b");
    expect(hash1).not.toBe(hash2);
  });

  test("computes SHA-384 hash", () => {
    const hash = computeHash("hello world", "sha384");
    expect(hash).toMatch(/^[0-9a-f]{96}$/);
  });

  test("computes SHA-512 hash", () => {
    const hash = computeHash("hello world", "sha512");
    expect(hash).toMatch(/^[0-9a-f]{128}$/);
  });
});

describe("verifyHash", () => {
  test("returns valid for matching hash", () => {
    const content = "test content";
    const hash = computeHash(content);
    const result = verifyHash(content, hash);
    expect(result.valid).toBe(true);
    expect(result.computedHash).toBe(hash);
    expect(result.expectedHash).toBe(hash);
    expect(result.reason).toBeUndefined();
  });

  test("returns invalid for mismatched hash", () => {
    const result = verifyHash("content", "0".repeat(64));
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("Hash mismatch");
  });

  test("handles case-insensitive comparison", () => {
    const content = "hello";
    const hash = computeHash(content);
    const result = verifyHash(content, hash.toUpperCase());
    expect(result.valid).toBe(true);
  });

  test("handles whitespace in expected hash", () => {
    const content = "hello";
    const hash = computeHash(content);
    const result = verifyHash(content, `  ${hash}  `);
    expect(result.valid).toBe(true);
  });

  test("returns invalid for wrong-length hash", () => {
    const result = verifyHash("content", "abc123");
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("Hash length mismatch");
  });

  test("verifies with SHA-384", () => {
    const content = "test";
    const hash = computeHash(content, "sha384");
    const result = verifyHash(content, hash, "sha384");
    expect(result.valid).toBe(true);
  });

  test("verifies with SHA-512", () => {
    const content = "test";
    const hash = computeHash(content, "sha512");
    const result = verifyHash(content, hash, "sha512");
    expect(result.valid).toBe(true);
  });

  test("fails when algorithm doesn't match", () => {
    const content = "test";
    const sha256Hash = computeHash(content, "sha256");
    const result = verifyHash(content, sha256Hash, "sha512");
    expect(result.valid).toBe(false);
  });
});

describe("parseSriHash", () => {
  test("parses SHA-256 SRI hash", () => {
    const content = "hello";
    const sri = createSriHash(content, "sha256");
    const parsed = parseSriHash(sri);
    expect(parsed).not.toBeNull();
    expect(parsed!.algorithm).toBe("sha256");
    expect(parsed!.hash).toBe(computeHash(content, "sha256"));
  });

  test("parses SHA-384 SRI hash", () => {
    const content = "hello";
    const sri = createSriHash(content, "sha384");
    const parsed = parseSriHash(sri);
    expect(parsed).not.toBeNull();
    expect(parsed!.algorithm).toBe("sha384");
  });

  test("parses SHA-512 SRI hash", () => {
    const content = "hello";
    const sri = createSriHash(content, "sha512");
    const parsed = parseSriHash(sri);
    expect(parsed).not.toBeNull();
    expect(parsed!.algorithm).toBe("sha512");
  });

  test("returns null for invalid SRI format", () => {
    expect(parseSriHash("md5-abc123")).toBeNull();
    expect(parseSriHash("invalid")).toBeNull();
    expect(parseSriHash("")).toBeNull();
  });
});

describe("createSriHash", () => {
  test("creates valid SRI format string", () => {
    const sri = createSriHash("test content");
    expect(sri).toMatch(/^sha256-.+$/);
  });

  test("roundtrips through parse", () => {
    const content = "roundtrip test";
    const sri = createSriHash(content, "sha256");
    const parsed = parseSriHash(sri);
    expect(parsed).not.toBeNull();
    const result = verifyHash(content, parsed!.hash, parsed!.algorithm);
    expect(result.valid).toBe(true);
  });
});

// =============================================================================
// Skill Gate Approval Flow Tests
// =============================================================================

function makeRequest(overrides: Partial<SkillApprovalRequest> = {}): SkillApprovalRequest {
  return {
    skillId: `skill-${Date.now()}-${Math.random()}`,
    name: "Test Skill",
    author: "test-author",
    description: "A test skill",
    manifestHash: computeHash("manifest content"),
    ...overrides,
  };
}

describe("createSkillGate", () => {
  describe("Default Configuration", () => {
    test("uses default config values", () => {
      const gate = createSkillGate();
      expect(gate.config.autoInstall).toBe(false);
      expect(gate.config.requireOwnerApproval).toBe(true);
      expect(gate.config.verifyHashes).toBe(true);
      expect(gate.config.hashAlgorithm).toBe("sha256");
      expect(gate.config.approvalExpirationMs).toBe(DEFAULT_SKILL_GATE_CONFIG.approvalExpirationMs);
      expect(gate.config.maxPendingApprovals).toBe(50);
    });

    test("allows overriding individual config values", () => {
      const gate = createSkillGate({ autoInstall: true, maxPendingApprovals: 10 });
      expect(gate.config.autoInstall).toBe(true);
      expect(gate.config.maxPendingApprovals).toBe(10);
      // Other defaults preserved
      expect(gate.config.verifyHashes).toBe(true);
    });
  });

  describe("Approval Request", () => {
    test("creates a pending approval request", () => {
      const gate = createSkillGate();
      const request = makeRequest();
      const record = gate.requestApproval(request);

      expect(record.status).toBe("pending");
      expect(record.request.skillId).toBe(request.skillId);
      expect(record.requestedAt).toBeGreaterThan(0);
      expect(record.decidedAt).toBeUndefined();
    });

    test("auto-approves when autoInstall is enabled", () => {
      const gate = createSkillGate({ autoInstall: true });
      const request = makeRequest();
      const record = gate.requestApproval(request);

      expect(record.status).toBe("approved");
      expect(record.decidedAt).toBeGreaterThan(0);
      expect(record.reason).toBe("Auto-install enabled");
    });

    test("throws when max pending approvals exceeded", () => {
      const gate = createSkillGate({ maxPendingApprovals: 2 });

      gate.requestApproval(makeRequest({ skillId: "skill-1" }));
      gate.requestApproval(makeRequest({ skillId: "skill-2" }));

      expect(() => {
        gate.requestApproval(makeRequest({ skillId: "skill-3" }));
      }).toThrow(SkillInstallationError);
    });

    test("error includes skill ID and code", () => {
      const gate = createSkillGate({ maxPendingApprovals: 1 });
      gate.requestApproval(makeRequest({ skillId: "first" }));

      try {
        gate.requestApproval(makeRequest({ skillId: "second" }));
        expect.unreachable("Should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(SkillInstallationError);
        const error = err as SkillInstallationError;
        expect(error.skillId).toBe("second");
        expect(error.code).toBe("MAX_PENDING_EXCEEDED");
      }
    });
  });

  describe("Approve", () => {
    test("approves a pending request", () => {
      const gate = createSkillGate();
      const request = makeRequest();
      gate.requestApproval(request);

      const record = gate.approve(request.skillId, "admin", "Looks good");
      expect(record.status).toBe("approved");
      expect(record.decidedBy).toBe("admin");
      expect(record.reason).toBe("Looks good");
      expect(record.decidedAt).toBeGreaterThan(0);
    });

    test("throws for non-existent skill", () => {
      const gate = createSkillGate();
      expect(() => {
        gate.approve("non-existent", "admin");
      }).toThrow(SkillInstallationError);
    });

    test("throws for already approved skill", () => {
      const gate = createSkillGate();
      const request = makeRequest();
      gate.requestApproval(request);
      gate.approve(request.skillId, "admin");

      expect(() => {
        gate.approve(request.skillId, "admin");
      }).toThrow(SkillInstallationError);
    });
  });

  describe("Deny", () => {
    test("denies a pending request", () => {
      const gate = createSkillGate();
      const request = makeRequest();
      gate.requestApproval(request);

      const record = gate.deny(request.skillId, "admin", "Suspicious");
      expect(record.status).toBe("denied");
      expect(record.decidedBy).toBe("admin");
      expect(record.reason).toBe("Suspicious");
    });

    test("throws for non-existent skill", () => {
      const gate = createSkillGate();
      expect(() => {
        gate.deny("non-existent", "admin");
      }).toThrow(SkillInstallationError);
    });
  });

  describe("isApproved", () => {
    test("returns true for approved skills", () => {
      const gate = createSkillGate();
      const request = makeRequest();
      gate.requestApproval(request);
      gate.approve(request.skillId, "admin");

      expect(gate.isApproved(request.skillId)).toBe(true);
    });

    test("returns false for pending skills", () => {
      const gate = createSkillGate();
      const request = makeRequest();
      gate.requestApproval(request);

      expect(gate.isApproved(request.skillId)).toBe(false);
    });

    test("returns false for denied skills", () => {
      const gate = createSkillGate();
      const request = makeRequest();
      gate.requestApproval(request);
      gate.deny(request.skillId, "admin");

      expect(gate.isApproved(request.skillId)).toBe(false);
    });

    test("returns false for unknown skills", () => {
      const gate = createSkillGate();
      expect(gate.isApproved("unknown")).toBe(false);
    });
  });

  describe("Hash Verification", () => {
    test("verifies correct content hash", () => {
      const gate = createSkillGate();
      const content = "skill manifest content";
      const hash = computeHash(content);
      expect(gate.verifySkillContent(content, hash)).toBe(true);
    });

    test("rejects incorrect content hash", () => {
      const gate = createSkillGate();
      expect(gate.verifySkillContent("content", "0".repeat(64))).toBe(false);
    });

    test("skips verification when disabled", () => {
      const gate = createSkillGate({ verifyHashes: false });
      expect(gate.verifySkillContent("anything", "wrong-hash")).toBe(true);
    });
  });

  describe("Installation Tracking", () => {
    test("records and retrieves installations", () => {
      const gate = createSkillGate();
      const hash = computeHash("manifest");

      gate.recordInstallation("skill-1", hash, "1.0.0");

      expect(gate.isInstalled("skill-1")).toBe(true);
      expect(gate.isInstalled("skill-2")).toBe(false);

      const info = gate.getInstalledSkill("skill-1");
      expect(info).toEqual({ hash, version: "1.0.0" });
    });

    test("returns undefined for uninstalled skills", () => {
      const gate = createSkillGate();
      expect(gate.getInstalledSkill("unknown")).toBeUndefined();
    });
  });

  describe("Pending Approvals", () => {
    test("lists pending approvals", () => {
      const gate = createSkillGate();
      gate.requestApproval(makeRequest({ skillId: "s1" }));
      gate.requestApproval(makeRequest({ skillId: "s2" }));
      gate.requestApproval(makeRequest({ skillId: "s3" }));
      gate.approve("s1", "admin");

      const pending = gate.getPendingApprovals();
      expect(pending.length).toBe(2);
      expect(pending.every((r) => r.status === "pending")).toBe(true);
    });
  });

  describe("Approval Expiration", () => {
    test("expires old pending approvals", () => {
      // Use very short expiration for testing
      const gate = createSkillGate({ approvalExpirationMs: 1 });
      const request = makeRequest();
      gate.requestApproval(request);

      // Wait just enough for expiration
      const start = Date.now();
      while (Date.now() - start < 5) {
        // spin
      }

      const status = gate.getApprovalStatus(request.skillId);
      expect(status?.status).toBe("expired");
    });
  });

  describe("Approval Status", () => {
    test("returns approval record by skill ID", () => {
      const gate = createSkillGate();
      const request = makeRequest();
      gate.requestApproval(request);

      const status = gate.getApprovalStatus(request.skillId);
      expect(status).toBeDefined();
      expect(status!.request.skillId).toBe(request.skillId);
    });

    test("returns undefined for unknown skill", () => {
      const gate = createSkillGate();
      expect(gate.getApprovalStatus("unknown")).toBeUndefined();
    });
  });
});
