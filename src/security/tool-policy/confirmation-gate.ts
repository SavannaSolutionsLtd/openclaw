/**
 * Confirmation Gate for Destructive Actions
 *
 * Requires explicit user confirmation for potentially destructive
 * or sensitive operations before execution.
 *
 * @module security/tool-policy/confirmation-gate
 */

/**
 * Action category for classification
 */
export type ActionCategory =
  | "destructive" // Deletes or modifies data irreversibly
  | "privileged" // Requires elevated permissions
  | "external" // Communicates with external systems
  | "financial" // Involves financial transactions
  | "security" // Modifies security settings
  | "configuration"; // Changes system configuration

/**
 * Destructive command patterns
 */
export interface DestructivePattern {
  pattern: RegExp;
  category: ActionCategory;
  description: string;
  severity: "high" | "medium" | "low";
}

/**
 * Known destructive bash command patterns
 */
export const DESTRUCTIVE_BASH_PATTERNS: DestructivePattern[] = [
  // File/directory deletion
  {
    pattern: /\brm\s+(-[rRf]+\s+)*[^|&;]+/i,
    category: "destructive",
    description: "File or directory deletion",
    severity: "high",
  },
  {
    pattern: /\brmdir\b/i,
    category: "destructive",
    description: "Directory deletion",
    severity: "medium",
  },
  {
    pattern: /\bunlink\b/i,
    category: "destructive",
    description: "File unlinking",
    severity: "high",
  },

  // Disk operations
  {
    pattern: /\bmkfs\b/i,
    category: "destructive",
    description: "Filesystem creation (disk format)",
    severity: "high",
  },
  {
    pattern: /\bdd\s+/i,
    category: "destructive",
    description: "Direct disk write",
    severity: "high",
  },
  {
    pattern: /\bfdisk\b/i,
    category: "destructive",
    description: "Disk partitioning",
    severity: "high",
  },

  // Git destructive operations
  {
    pattern:
      /\bgit\s+(push\s+(-f|--force)|reset\s+--hard|clean\s+-f|checkout\s+\.\s*$|restore\s+\.)/i,
    category: "destructive",
    description: "Destructive git operation",
    severity: "high",
  },
  {
    pattern: /\bgit\s+branch\s+-[dD]\b/i,
    category: "destructive",
    description: "Git branch deletion",
    severity: "medium",
  },

  // Database operations
  {
    pattern: /\bDROP\s+(TABLE|DATABASE|INDEX|VIEW)\b/i,
    category: "destructive",
    description: "Database drop operation",
    severity: "high",
  },
  {
    pattern: /\bTRUNCATE\s+TABLE\b/i,
    category: "destructive",
    description: "Database truncation",
    severity: "high",
  },
  {
    pattern: /\bDELETE\s+FROM\s+\w+\s*(;|$)/i,
    category: "destructive",
    description: "Delete all rows from table",
    severity: "high",
  },

  // System modifications
  {
    pattern: /\bchmod\s+(-R\s+)?[0-7]{3,4}\b/i,
    category: "security",
    description: "Permission modification",
    severity: "medium",
  },
  {
    pattern: /\bchown\s+/i,
    category: "security",
    description: "Ownership modification",
    severity: "medium",
  },
  {
    pattern: /\bsudo\b/i,
    category: "privileged",
    description: "Superuser command",
    severity: "high",
  },

  // Network operations
  {
    pattern: /\bcurl\s+.*(-X\s*(POST|PUT|DELETE|PATCH)|-d\s|--data\b)/i,
    category: "external",
    description: "HTTP request with data modification",
    severity: "medium",
  },
  {
    pattern: /\bwget\s+.*--post/i,
    category: "external",
    description: "HTTP POST request",
    severity: "medium",
  },

  // Package management
  {
    pattern: /\b(npm|yarn|pnpm)\s+(publish|unpublish)\b/i,
    category: "external",
    description: "Package publication",
    severity: "high",
  },
  {
    pattern: /\bpip\s+install\s+--user\b/i,
    category: "configuration",
    description: "User-level package installation",
    severity: "low",
  },

  // Service management
  {
    pattern: /\b(systemctl|service)\s+(stop|restart|disable)\b/i,
    category: "configuration",
    description: "Service management",
    severity: "high",
  },

  // Kill processes
  {
    pattern: /\bkill\s+(-9\s+)?/i,
    category: "destructive",
    description: "Process termination",
    severity: "medium",
  },
  {
    pattern: /\bkillall\b/i,
    category: "destructive",
    description: "Multiple process termination",
    severity: "high",
  },

  // Environment modifications
  {
    pattern: />\s*\/etc\//i,
    category: "configuration",
    description: "System configuration modification",
    severity: "high",
  },
  {
    pattern: />\s*~?\/?\.bashrc|\.zshrc|\.profile/i,
    category: "configuration",
    description: "Shell configuration modification",
    severity: "medium",
  },
];

/**
 * Confirmation requirement result
 */
export interface ConfirmationRequirement {
  required: boolean;
  reason: string;
  category: ActionCategory;
  severity: "high" | "medium" | "low";
  matchedPattern?: string;
}

/**
 * Check if a bash command requires confirmation
 *
 * @param command - The bash command to check
 * @returns Confirmation requirement
 */
export function checkBashCommandConfirmation(command: string): ConfirmationRequirement {
  for (const { pattern, category, description, severity } of DESTRUCTIVE_BASH_PATTERNS) {
    if (pattern.test(command)) {
      return {
        required: true,
        reason: description,
        category,
        severity,
        matchedPattern: pattern.source,
      };
    }
  }

  return {
    required: false,
    reason: "No destructive patterns detected",
    category: "destructive",
    severity: "low",
  };
}

/**
 * Confirmation state for pending actions
 */
export interface PendingConfirmation {
  id: string;
  action: string;
  params: Record<string, unknown>;
  reason: string;
  category: ActionCategory;
  severity: "high" | "medium" | "low";
  createdAt: number;
  expiresAt: number;
  sessionId: string;
}

/**
 * Confirmation result
 */
export interface ConfirmationResult {
  confirmed: boolean;
  confirmationId?: string;
  reason?: string;
}

/**
 * Pending confirmations storage
 */
const pendingConfirmations = new Map<string, PendingConfirmation>();

/**
 * Configuration for confirmation gate
 */
export interface ConfirmationGateConfig {
  /** Confirmation timeout in milliseconds */
  timeoutMs: number;
  /** Whether to require confirmation for high severity actions */
  requireHighSeverity: boolean;
  /** Whether to require confirmation for medium severity actions */
  requireMediumSeverity: boolean;
  /** Whether to require confirmation for low severity actions */
  requireLowSeverity: boolean;
  /** Custom patterns to add */
  customPatterns?: DestructivePattern[];
}

/**
 * Default configuration
 */
export const DEFAULT_CONFIRMATION_CONFIG: ConfirmationGateConfig = {
  timeoutMs: 5 * 60 * 1000, // 5 minutes
  requireHighSeverity: true,
  requireMediumSeverity: true,
  requireLowSeverity: false,
  customPatterns: [],
};

/**
 * Generate a unique confirmation ID
 */
function generateConfirmationId(): string {
  return `confirm_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
}

/**
 * Create a confirmation gate
 */
export function createConfirmationGate(config: Partial<ConfirmationGateConfig> = {}) {
  const cfg = { ...DEFAULT_CONFIRMATION_CONFIG, ...config };
  const _allPatterns = [...DESTRUCTIVE_BASH_PATTERNS, ...(cfg.customPatterns ?? [])];

  return {
    /**
     * Check if an action requires confirmation
     */
    requiresConfirmation(action: string, params: Record<string, unknown>): ConfirmationRequirement {
      // For bash commands, check the command string
      if (action === "bash" && typeof params.command === "string") {
        const result = checkBashCommandConfirmation(params.command);

        // Apply severity filtering
        if (!result.required) {
          return result;
        }

        if (result.severity === "high" && !cfg.requireHighSeverity) {
          return { ...result, required: false };
        }
        if (result.severity === "medium" && !cfg.requireMediumSeverity) {
          return { ...result, required: false };
        }
        if (result.severity === "low" && !cfg.requireLowSeverity) {
          return { ...result, required: false };
        }

        return result;
      }

      // For other actions, check based on action name
      const actionPatterns: Record<string, ConfirmationRequirement> = {
        "file-delete": {
          required: cfg.requireHighSeverity,
          reason: "File deletion",
          category: "destructive",
          severity: "high",
        },
        "config-write": {
          required: cfg.requireMediumSeverity,
          reason: "Configuration modification",
          category: "configuration",
          severity: "medium",
        },
        "skill-install": {
          required: cfg.requireMediumSeverity,
          reason: "Skill installation",
          category: "security",
          severity: "medium",
        },
        "cron-create": {
          required: cfg.requireLowSeverity,
          reason: "Scheduled job creation",
          category: "configuration",
          severity: "low",
        },
        "webhook-register": {
          required: cfg.requireLowSeverity,
          reason: "Webhook registration",
          category: "external",
          severity: "low",
        },
      };

      return (
        actionPatterns[action] ?? {
          required: false,
          reason: "No confirmation required",
          category: "configuration",
          severity: "low",
        }
      );
    },

    /**
     * Request confirmation for an action
     */
    requestConfirmation(
      sessionId: string,
      action: string,
      params: Record<string, unknown>,
      reason: string,
      category: ActionCategory,
      severity: "high" | "medium" | "low",
    ): PendingConfirmation {
      const id = generateConfirmationId();
      const now = Date.now();

      const pending: PendingConfirmation = {
        id,
        action,
        params,
        reason,
        category,
        severity,
        createdAt: now,
        expiresAt: now + cfg.timeoutMs,
        sessionId,
      };

      pendingConfirmations.set(id, pending);
      return pending;
    },

    /**
     * Confirm a pending action
     */
    confirm(confirmationId: string, sessionId: string): ConfirmationResult {
      const pending = pendingConfirmations.get(confirmationId);

      if (!pending) {
        return {
          confirmed: false,
          reason: "Confirmation not found or expired",
        };
      }

      if (pending.sessionId !== sessionId) {
        return {
          confirmed: false,
          reason: "Confirmation belongs to a different session",
        };
      }

      if (Date.now() > pending.expiresAt) {
        pendingConfirmations.delete(confirmationId);
        return {
          confirmed: false,
          reason: "Confirmation has expired",
        };
      }

      pendingConfirmations.delete(confirmationId);
      return {
        confirmed: true,
        confirmationId,
      };
    },

    /**
     * Cancel a pending confirmation
     */
    cancel(confirmationId: string): boolean {
      return pendingConfirmations.delete(confirmationId);
    },

    /**
     * Get pending confirmations for a session
     */
    getPending(sessionId: string): PendingConfirmation[] {
      const now = Date.now();
      const result: PendingConfirmation[] = [];

      for (const [id, pending] of pendingConfirmations) {
        if (pending.sessionId === sessionId) {
          if (now > pending.expiresAt) {
            pendingConfirmations.delete(id);
          } else {
            result.push(pending);
          }
        }
      }

      return result;
    },

    /**
     * Clean up expired confirmations
     */
    cleanup(): number {
      const now = Date.now();
      let cleaned = 0;

      for (const [id, pending] of pendingConfirmations) {
        if (now > pending.expiresAt) {
          pendingConfirmations.delete(id);
          cleaned++;
        }
      }

      return cleaned;
    },

    /**
     * Get configuration
     */
    get config(): ConfirmationGateConfig {
      return { ...cfg };
    },
  };
}

/**
 * Default confirmation gate instance
 */
export const defaultConfirmationGate = createConfirmationGate();

/**
 * Check if a bash command is blocked without confirmation
 */
export function isDestructiveCommand(command: string): boolean {
  return checkBashCommandConfirmation(command).required;
}

/**
 * Get the category of a destructive command
 */
export function getCommandCategory(command: string): ActionCategory | null {
  const result = checkBashCommandConfirmation(command);
  return result.required ? result.category : null;
}
