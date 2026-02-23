/**
 * Tool Execution Policy
 *
 * This module enforces security policies for tool execution including:
 * - Capability-based access control (RBAC by session type)
 * - Rate limiting to prevent abuse
 * - Schema validation for tool parameters
 * - Confirmation gates for destructive actions
 *
 * @module security/tool-policy
 */

// Capability Matrix exports
export {
  type SessionType,
  type Capability,
  type AccessLevel,
  type CapabilityCheckResult,
  CAPABILITY_MATRIX,
  checkCapability,
  canPerform,
  canPerformWithoutConfirmation,
  getSessionCapabilities,
  getAllowedCapabilities,
  getConfirmationRequiredCapabilities,
  getDeniedCapabilities,
} from "./capability-matrix.js";

// Rate Limiter exports
export {
  type RateLimitConfig,
  type RateLimitResult,
  RateLimitError,
  QuotaExceededError,
  DEFAULT_RATE_LIMITS,
  createRateLimiter,
  defaultRateLimiter,
  checkAndRecordToolCall,
} from "./rate-limiter.js";

// Schema Validator exports
export {
  type PropertyType,
  type PropertySchema,
  type ToolSchema,
  type ValidationResult,
  SchemaValidationError,
  validateToolParams,
  validateToolCall,
  registerToolSchema,
  getToolSchema,
  createToolValidator,
  COMMON_SCHEMAS,
} from "./schema-validator.js";

// Confirmation Gate exports
export {
  type ActionCategory,
  type DestructivePattern,
  type ConfirmationRequirement,
  type PendingConfirmation,
  type ConfirmationResult,
  type ConfirmationGateConfig,
  DESTRUCTIVE_BASH_PATTERNS,
  DEFAULT_CONFIRMATION_CONFIG,
  checkBashCommandConfirmation,
  createConfirmationGate,
  defaultConfirmationGate,
  isDestructiveCommand,
  getCommandCategory,
} from "./confirmation-gate.js";

/**
 * Policy configuration
 */
export interface ToolPolicyConfig {
  /** Enable capability checks */
  enableCapabilityChecks: boolean;
  /** Enable rate limiting */
  enableRateLimiting: boolean;
  /** Enable schema validation */
  enableSchemaValidation: boolean;
  /** Enable confirmation gates */
  enableConfirmationGates: boolean;
  /** Default session type */
  defaultSessionType: import("./capability-matrix.js").SessionType;
  /** Rate limit configuration */
  rateLimits: Partial<import("./rate-limiter.js").RateLimitConfig>;
  /** Confirmation gate configuration */
  confirmationGate: Partial<import("./confirmation-gate.js").ConfirmationGateConfig>;
}

/**
 * Default policy configuration
 */
export const DEFAULT_POLICY_CONFIG: ToolPolicyConfig = {
  enableCapabilityChecks: true,
  enableRateLimiting: true,
  enableSchemaValidation: true,
  enableConfirmationGates: true,
  defaultSessionType: "main-standard",
  rateLimits: {},
  confirmationGate: {},
};

/**
 * Policy check result
 */
export interface PolicyCheckResult {
  /** Whether the action is allowed */
  allowed: boolean;
  /** Reason for the decision */
  reason: string;
  /** Whether confirmation is required */
  requiresConfirmation: boolean;
  /** Confirmation details if required */
  confirmationDetails?: {
    reason: string;
    category: import("./confirmation-gate.js").ActionCategory;
    severity: "high" | "medium" | "low";
  };
  /** Validation errors if any */
  validationErrors?: import("./schema-validator.js").SchemaValidationError[];
  /** Rate limit status */
  rateLimitStatus?: import("./rate-limiter.js").RateLimitResult;
}

import { checkCapability } from "./capability-matrix.js";
import { createConfirmationGate } from "./confirmation-gate.js";
import { createRateLimiter } from "./rate-limiter.js";
import { validateToolCall } from "./schema-validator.js";

/**
 * Create a tool policy enforcer
 */
export function createToolPolicy(config: Partial<ToolPolicyConfig> = {}) {
  const cfg = { ...DEFAULT_POLICY_CONFIG, ...config };
  const rateLimiter = createRateLimiter(cfg.rateLimits);
  const confirmationGate = createConfirmationGate(cfg.confirmationGate);

  return {
    /**
     * Check if a tool call is allowed
     *
     * @param sessionId - Session identifier
     * @param sessionType - Type of session
     * @param toolName - Name of the tool
     * @param capability - Required capability
     * @param params - Tool parameters
     * @returns Policy check result
     */
    check(
      sessionId: string,
      sessionType: import("./capability-matrix.js").SessionType,
      toolName: string,
      capability: import("./capability-matrix.js").Capability,
      params: Record<string, unknown>,
    ): PolicyCheckResult {
      // 1. Check capability
      if (cfg.enableCapabilityChecks) {
        const capResult = checkCapability(sessionType, capability);
        if (!capResult.allowed) {
          return {
            allowed: false,
            reason: capResult.reason,
            requiresConfirmation: false,
          };
        }
      }

      // 2. Check rate limits
      let rateLimitStatus: import("./rate-limiter.js").RateLimitResult | undefined;
      if (cfg.enableRateLimiting) {
        try {
          rateLimitStatus = rateLimiter.checkToolCall(sessionId);
        } catch (error) {
          if (error instanceof Error) {
            return {
              allowed: false,
              reason: error.message,
              requiresConfirmation: false,
              rateLimitStatus: undefined,
            };
          }
          throw error;
        }
      }

      // 3. Validate schema
      if (cfg.enableSchemaValidation) {
        const validationResult = validateToolCall(toolName, params);
        if (!validationResult.valid) {
          return {
            allowed: false,
            reason: `Validation failed: ${validationResult.errors[0]?.message ?? "Unknown error"}`,
            requiresConfirmation: false,
            validationErrors: validationResult.errors,
            rateLimitStatus,
          };
        }
      }

      // 4. Check confirmation requirements
      let requiresConfirmation = false;
      let confirmationDetails: PolicyCheckResult["confirmationDetails"];

      if (cfg.enableConfirmationGates) {
        const confirmResult = confirmationGate.requiresConfirmation(toolName, params);

        // Also check capability-level confirmation
        if (cfg.enableCapabilityChecks) {
          const capResult = checkCapability(sessionType, capability);
          if (capResult.requiresConfirmation) {
            requiresConfirmation = true;
            confirmationDetails = {
              reason: capResult.reason,
              category: "privileged",
              severity: "medium",
            };
          }
        }

        if (confirmResult.required) {
          requiresConfirmation = true;
          confirmationDetails = {
            reason: confirmResult.reason,
            category: confirmResult.category,
            severity: confirmResult.severity,
          };
        }
      }

      return {
        allowed: true,
        reason: "Policy checks passed",
        requiresConfirmation,
        confirmationDetails,
        rateLimitStatus,
      };
    },

    /**
     * Record that a tool call was executed
     */
    recordExecution(sessionId: string): void {
      if (cfg.enableRateLimiting) {
        rateLimiter.recordToolCall(sessionId);
      }
    },

    /**
     * Get rate limiter instance
     */
    getRateLimiter() {
      return rateLimiter;
    },

    /**
     * Get confirmation gate instance
     */
    getConfirmationGate() {
      return confirmationGate;
    },

    /**
     * Get configuration
     */
    get config(): ToolPolicyConfig {
      return { ...cfg };
    },
  };
}

/**
 * Default tool policy instance
 */
export const defaultToolPolicy = createToolPolicy();
