/**
 * Capability Matrix for Tool Access Control
 *
 * Defines session types and their allowed capabilities based on
 * the principle of least privilege.
 *
 * @module security/tool-policy/capability-matrix
 */

/**
 * Session types with different privilege levels
 */
export type SessionType =
  | "main-elevated" // Owner with explicit elevation
  | "main-standard" // Owner without elevation
  | "sandbox" // Sandboxed execution environment
  | "webhook" // Webhook-triggered sessions
  | "cron" // Scheduled/cron jobs
  | "api" // API-triggered sessions
  | "guest"; // Unauthenticated/limited sessions

/**
 * Available capabilities that can be granted to sessions
 */
export type Capability =
  // Bash/Shell capabilities
  | "bash-unrestricted" // Full shell access
  | "bash-sandboxed" // Sandboxed shell (restricted commands)
  | "bash-read-only" // Read-only file system commands

  // Browser capabilities
  | "browser-cdp" // Chrome DevTools Protocol access
  | "browser-screenshot" // Screenshot capability only
  | "browser-navigate" // URL navigation

  // File system capabilities
  | "file-read" // Read files
  | "file-write" // Write files
  | "file-delete" // Delete files

  // Code execution
  | "canvas-eval" // Canvas/eval execution
  | "node-invoke" // Node.js execution

  // Session management
  | "sessions-send" // Send messages to sessions
  | "sessions-history-own" // Read own session history
  | "sessions-history-other" // Read other sessions' history
  | "sessions-create" // Create new sessions

  // Scheduling
  | "cron-create" // Create cron jobs
  | "cron-delete" // Delete cron jobs
  | "cron-list" // List cron jobs

  // Integration
  | "webhook-register" // Register webhooks
  | "webhook-delete" // Delete webhooks

  // Extension/skill management
  | "skill-install" // Install ClawHub skills
  | "skill-execute" // Execute installed skills

  // Configuration
  | "config-read" // Read configuration
  | "config-write"; // Write configuration

/**
 * Access level for a capability
 */
export type AccessLevel = "allow" | "confirm" | "deny";

/**
 * Capability matrix defining access levels per session type
 */
export const CAPABILITY_MATRIX: Record<SessionType, Record<Capability, AccessLevel>> = {
  "main-elevated": {
    // Full access with explicit elevation
    "bash-unrestricted": "allow",
    "bash-sandboxed": "allow",
    "bash-read-only": "allow",
    "browser-cdp": "allow",
    "browser-screenshot": "allow",
    "browser-navigate": "allow",
    "file-read": "allow",
    "file-write": "allow",
    "file-delete": "confirm",
    "canvas-eval": "allow",
    "node-invoke": "allow",
    "sessions-send": "allow",
    "sessions-history-own": "allow",
    "sessions-history-other": "confirm",
    "sessions-create": "allow",
    "cron-create": "allow",
    "cron-delete": "allow",
    "cron-list": "allow",
    "webhook-register": "allow",
    "webhook-delete": "allow",
    "skill-install": "confirm",
    "skill-execute": "allow",
    "config-read": "allow",
    "config-write": "confirm",
  },

  "main-standard": {
    // Standard owner access (no elevation)
    "bash-unrestricted": "confirm",
    "bash-sandboxed": "allow",
    "bash-read-only": "allow",
    "browser-cdp": "confirm",
    "browser-screenshot": "allow",
    "browser-navigate": "allow",
    "file-read": "allow",
    "file-write": "allow",
    "file-delete": "confirm",
    "canvas-eval": "confirm",
    "node-invoke": "confirm",
    "sessions-send": "allow",
    "sessions-history-own": "allow",
    "sessions-history-other": "deny",
    "sessions-create": "allow",
    "cron-create": "confirm",
    "cron-delete": "confirm",
    "cron-list": "allow",
    "webhook-register": "confirm",
    "webhook-delete": "confirm",
    "skill-install": "confirm",
    "skill-execute": "allow",
    "config-read": "allow",
    "config-write": "confirm",
  },

  sandbox: {
    // Sandboxed environment with limited access
    "bash-unrestricted": "deny",
    "bash-sandboxed": "allow",
    "bash-read-only": "allow",
    "browser-cdp": "deny",
    "browser-screenshot": "allow",
    "browser-navigate": "confirm",
    "file-read": "allow",
    "file-write": "confirm",
    "file-delete": "deny",
    "canvas-eval": "allow",
    "node-invoke": "deny",
    "sessions-send": "deny",
    "sessions-history-own": "allow",
    "sessions-history-other": "deny",
    "sessions-create": "deny",
    "cron-create": "deny",
    "cron-delete": "deny",
    "cron-list": "allow",
    "webhook-register": "deny",
    "webhook-delete": "deny",
    "skill-install": "deny",
    "skill-execute": "confirm",
    "config-read": "allow",
    "config-write": "deny",
  },

  webhook: {
    // Webhook-triggered sessions (limited)
    "bash-unrestricted": "deny",
    "bash-sandboxed": "confirm",
    "bash-read-only": "allow",
    "browser-cdp": "deny",
    "browser-screenshot": "deny",
    "browser-navigate": "deny",
    "file-read": "allow",
    "file-write": "confirm",
    "file-delete": "deny",
    "canvas-eval": "deny",
    "node-invoke": "deny",
    "sessions-send": "confirm",
    "sessions-history-own": "allow",
    "sessions-history-other": "deny",
    "sessions-create": "deny",
    "cron-create": "deny",
    "cron-delete": "deny",
    "cron-list": "allow",
    "webhook-register": "deny",
    "webhook-delete": "deny",
    "skill-install": "deny",
    "skill-execute": "confirm",
    "config-read": "allow",
    "config-write": "deny",
  },

  cron: {
    // Scheduled job sessions
    "bash-unrestricted": "deny",
    "bash-sandboxed": "allow",
    "bash-read-only": "allow",
    "browser-cdp": "deny",
    "browser-screenshot": "allow",
    "browser-navigate": "confirm",
    "file-read": "allow",
    "file-write": "allow",
    "file-delete": "deny",
    "canvas-eval": "deny",
    "node-invoke": "deny",
    "sessions-send": "allow",
    "sessions-history-own": "allow",
    "sessions-history-other": "deny",
    "sessions-create": "deny",
    "cron-create": "deny",
    "cron-delete": "deny",
    "cron-list": "allow",
    "webhook-register": "deny",
    "webhook-delete": "deny",
    "skill-install": "deny",
    "skill-execute": "allow",
    "config-read": "allow",
    "config-write": "deny",
  },

  api: {
    // API-triggered sessions
    "bash-unrestricted": "deny",
    "bash-sandboxed": "confirm",
    "bash-read-only": "allow",
    "browser-cdp": "deny",
    "browser-screenshot": "confirm",
    "browser-navigate": "confirm",
    "file-read": "allow",
    "file-write": "confirm",
    "file-delete": "deny",
    "canvas-eval": "deny",
    "node-invoke": "deny",
    "sessions-send": "allow",
    "sessions-history-own": "allow",
    "sessions-history-other": "deny",
    "sessions-create": "confirm",
    "cron-create": "deny",
    "cron-delete": "deny",
    "cron-list": "allow",
    "webhook-register": "deny",
    "webhook-delete": "deny",
    "skill-install": "deny",
    "skill-execute": "confirm",
    "config-read": "allow",
    "config-write": "deny",
  },

  guest: {
    // Unauthenticated/limited sessions
    "bash-unrestricted": "deny",
    "bash-sandboxed": "deny",
    "bash-read-only": "deny",
    "browser-cdp": "deny",
    "browser-screenshot": "deny",
    "browser-navigate": "deny",
    "file-read": "deny",
    "file-write": "deny",
    "file-delete": "deny",
    "canvas-eval": "deny",
    "node-invoke": "deny",
    "sessions-send": "deny",
    "sessions-history-own": "deny",
    "sessions-history-other": "deny",
    "sessions-create": "deny",
    "cron-create": "deny",
    "cron-delete": "deny",
    "cron-list": "deny",
    "webhook-register": "deny",
    "webhook-delete": "deny",
    "skill-install": "deny",
    "skill-execute": "deny",
    "config-read": "deny",
    "config-write": "deny",
  },
};

/**
 * Result of capability check
 */
export interface CapabilityCheckResult {
  /** Whether the capability is allowed */
  allowed: boolean;
  /** Whether confirmation is required */
  requiresConfirmation: boolean;
  /** Reason for the decision */
  reason: string;
  /** Session type that was checked */
  sessionType: SessionType;
  /** Capability that was checked */
  capability: Capability;
}

/**
 * Check if a session type has a specific capability
 *
 * @param sessionType - The type of session
 * @param capability - The capability to check
 * @returns Check result with allowed status and reason
 */
export function checkCapability(
  sessionType: SessionType,
  capability: Capability,
): CapabilityCheckResult {
  const matrix = CAPABILITY_MATRIX[sessionType];
  if (!matrix) {
    return {
      allowed: false,
      requiresConfirmation: false,
      reason: `Unknown session type: ${sessionType}`,
      sessionType,
      capability,
    };
  }

  const accessLevel = matrix[capability];
  if (!accessLevel) {
    return {
      allowed: false,
      requiresConfirmation: false,
      reason: `Unknown capability: ${capability}`,
      sessionType,
      capability,
    };
  }

  switch (accessLevel) {
    case "allow":
      return {
        allowed: true,
        requiresConfirmation: false,
        reason: `Capability ${capability} is allowed for ${sessionType} sessions`,
        sessionType,
        capability,
      };
    case "confirm":
      return {
        allowed: true,
        requiresConfirmation: true,
        reason: `Capability ${capability} requires confirmation for ${sessionType} sessions`,
        sessionType,
        capability,
      };
    case "deny":
      return {
        allowed: false,
        requiresConfirmation: false,
        reason: `Capability ${capability} is denied for ${sessionType} sessions`,
        sessionType,
        capability,
      };
  }
}

/**
 * Check if a session can perform an action without confirmation
 */
export function canPerformWithoutConfirmation(
  sessionType: SessionType,
  capability: Capability,
): boolean {
  const result = checkCapability(sessionType, capability);
  return result.allowed && !result.requiresConfirmation;
}

/**
 * Check if a session can perform an action (with or without confirmation)
 */
export function canPerform(sessionType: SessionType, capability: Capability): boolean {
  return checkCapability(sessionType, capability).allowed;
}

/**
 * Get all capabilities for a session type
 */
export function getSessionCapabilities(sessionType: SessionType): Record<Capability, AccessLevel> {
  return { ...CAPABILITY_MATRIX[sessionType] };
}

/**
 * Get all allowed capabilities for a session type
 */
export function getAllowedCapabilities(sessionType: SessionType): Capability[] {
  const matrix = CAPABILITY_MATRIX[sessionType];
  return (Object.entries(matrix) as [Capability, AccessLevel][])
    .filter(([, level]) => level === "allow" || level === "confirm")
    .map(([cap]) => cap);
}

/**
 * Get capabilities that require confirmation for a session type
 */
export function getConfirmationRequiredCapabilities(sessionType: SessionType): Capability[] {
  const matrix = CAPABILITY_MATRIX[sessionType];
  return (Object.entries(matrix) as [Capability, AccessLevel][])
    .filter(([, level]) => level === "confirm")
    .map(([cap]) => cap);
}

/**
 * Get denied capabilities for a session type
 */
export function getDeniedCapabilities(sessionType: SessionType): Capability[] {
  const matrix = CAPABILITY_MATRIX[sessionType];
  return (Object.entries(matrix) as [Capability, AccessLevel][])
    .filter(([, level]) => level === "deny")
    .map(([cap]) => cap);
}
