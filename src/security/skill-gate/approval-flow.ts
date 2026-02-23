/**
 * Skill Approval Flow
 *
 * Implements the approval gate for ClawHub skill installation,
 * requiring owner approval before skills can be installed or updated.
 *
 * @module security/skill-gate/approval-flow
 */

import { verifyHash, type HashAlgorithm } from "./hash-verify.js";

/**
 * Skill approval request
 */
export interface SkillApprovalRequest {
  /** Unique skill identifier */
  skillId: string;
  /** Skill display name */
  name: string;
  /** Skill author */
  author: string;
  /** Skill description */
  description: string;
  /** SHA-256 hash of the skill manifest */
  manifestHash: string;
  /** Skill version */
  version?: string;
  /** Required permissions */
  permissions?: string[];
}

/**
 * Skill approval status
 */
export type ApprovalStatus = "pending" | "approved" | "denied" | "expired";

/**
 * Approval record
 */
export interface ApprovalRecord {
  /** Approval request */
  request: SkillApprovalRequest;
  /** Current status */
  status: ApprovalStatus;
  /** When the request was created */
  requestedAt: number;
  /** When the decision was made */
  decidedAt?: number;
  /** Who approved/denied */
  decidedBy?: string;
  /** Reason for decision */
  reason?: string;
}

/**
 * Skill gate configuration
 */
export interface SkillGateConfig {
  /** Automatically install skills without approval */
  autoInstall: boolean;
  /** Require owner approval for new skills */
  requireOwnerApproval: boolean;
  /** Verify skill content hashes */
  verifyHashes: boolean;
  /** Hash algorithm for verification */
  hashAlgorithm: HashAlgorithm;
  /** Approval expiration time in milliseconds */
  approvalExpirationMs: number;
  /** Maximum pending approvals */
  maxPendingApprovals: number;
}

/**
 * Default skill gate configuration
 */
export const DEFAULT_SKILL_GATE_CONFIG: SkillGateConfig = {
  autoInstall: false,
  requireOwnerApproval: true,
  verifyHashes: true,
  hashAlgorithm: "sha256",
  approvalExpirationMs: 24 * 60 * 60 * 1000, // 24 hours
  maxPendingApprovals: 50,
};

/**
 * Skill installation error
 */
export class SkillInstallationError extends Error {
  readonly skillId: string;
  readonly code: string;

  constructor(message: string, skillId: string, code: string) {
    super(message);
    this.name = "SkillInstallationError";
    this.skillId = skillId;
    this.code = code;
  }
}

/**
 * Create a skill gate
 */
export function createSkillGate(config: Partial<SkillGateConfig> = {}) {
  const cfg = { ...DEFAULT_SKILL_GATE_CONFIG, ...config };
  const approvals = new Map<string, ApprovalRecord>();
  const installedSkills = new Map<string, { hash: string; version?: string }>();

  /**
   * Cleanup expired approvals
   */
  function cleanupExpired(): void {
    const now = Date.now();
    for (const [key, record] of approvals) {
      if (record.status === "pending" && now - record.requestedAt > cfg.approvalExpirationMs) {
        record.status = "expired";
        approvals.set(key, record);
      }
    }
  }

  return {
    /**
     * Request approval to install a skill
     *
     * @returns The approval record
     * @throws SkillInstallationError if auto-install is disabled and limits exceeded
     */
    requestApproval(request: SkillApprovalRequest): ApprovalRecord {
      cleanupExpired();

      // Check if auto-install is enabled
      if (cfg.autoInstall) {
        const record: ApprovalRecord = {
          request,
          status: "approved",
          requestedAt: Date.now(),
          decidedAt: Date.now(),
          reason: "Auto-install enabled",
        };
        approvals.set(request.skillId, record);
        return record;
      }

      // Check pending approvals limit
      const pendingCount = Array.from(approvals.values()).filter(
        (r) => r.status === "pending",
      ).length;
      if (pendingCount >= cfg.maxPendingApprovals) {
        throw new SkillInstallationError(
          `Too many pending approvals: ${pendingCount}/${cfg.maxPendingApprovals}`,
          request.skillId,
          "MAX_PENDING_EXCEEDED",
        );
      }

      const record: ApprovalRecord = {
        request,
        status: "pending",
        requestedAt: Date.now(),
      };
      approvals.set(request.skillId, record);
      return record;
    },

    /**
     * Approve a skill installation
     */
    approve(skillId: string, approvedBy: string, reason?: string): ApprovalRecord {
      const record = approvals.get(skillId);
      if (!record) {
        throw new SkillInstallationError(
          `No approval request found for skill: ${skillId}`,
          skillId,
          "NOT_FOUND",
        );
      }
      if (record.status !== "pending") {
        throw new SkillInstallationError(
          `Approval request is not pending: ${record.status}`,
          skillId,
          "INVALID_STATUS",
        );
      }

      record.status = "approved";
      record.decidedAt = Date.now();
      record.decidedBy = approvedBy;
      record.reason = reason;
      approvals.set(skillId, record);
      return record;
    },

    /**
     * Deny a skill installation
     */
    deny(skillId: string, deniedBy: string, reason?: string): ApprovalRecord {
      const record = approvals.get(skillId);
      if (!record) {
        throw new SkillInstallationError(
          `No approval request found for skill: ${skillId}`,
          skillId,
          "NOT_FOUND",
        );
      }

      record.status = "denied";
      record.decidedAt = Date.now();
      record.decidedBy = deniedBy;
      record.reason = reason;
      approvals.set(skillId, record);
      return record;
    },

    /**
     * Check if a skill is approved for installation
     */
    isApproved(skillId: string): boolean {
      cleanupExpired();
      const record = approvals.get(skillId);
      return record?.status === "approved";
    },

    /**
     * Verify a skill's content hash before installation
     */
    verifySkillContent(content: string, expectedHash: string): boolean {
      if (!cfg.verifyHashes) {
        return true;
      }
      const result = verifyHash(content, expectedHash, cfg.hashAlgorithm);
      return result.valid;
    },

    /**
     * Record a successful skill installation
     */
    recordInstallation(skillId: string, hash: string, version?: string): void {
      installedSkills.set(skillId, { hash, version });
    },

    /**
     * Check if a skill is installed
     */
    isInstalled(skillId: string): boolean {
      return installedSkills.has(skillId);
    },

    /**
     * Get installed skill info
     */
    getInstalledSkill(skillId: string): { hash: string; version?: string } | undefined {
      return installedSkills.get(skillId);
    },

    /**
     * Get all pending approvals
     */
    getPendingApprovals(): ApprovalRecord[] {
      cleanupExpired();
      return Array.from(approvals.values()).filter((r) => r.status === "pending");
    },

    /**
     * Get approval status for a skill
     */
    getApprovalStatus(skillId: string): ApprovalRecord | undefined {
      cleanupExpired();
      return approvals.get(skillId);
    },

    /**
     * Get configuration
     */
    get config(): SkillGateConfig {
      return { ...cfg };
    },
  };
}
