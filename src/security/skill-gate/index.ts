/**
 * ClawHub Skill Gate
 *
 * Security module for controlling skill installation from ClawHub.
 * Enforces owner approval, hash verification, and installation tracking.
 *
 * @module security/skill-gate
 */

export {
  type HashVerifyResult,
  type HashAlgorithm,
  computeHash,
  verifyHash,
  parseSriHash,
  createSriHash,
} from "./hash-verify.js";

export {
  type SkillApprovalRequest,
  type ApprovalStatus,
  type ApprovalRecord,
  type SkillGateConfig,
  DEFAULT_SKILL_GATE_CONFIG,
  SkillInstallationError,
  createSkillGate,
} from "./approval-flow.js";
