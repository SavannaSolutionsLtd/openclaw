/**
 * Output Redaction Filter
 *
 * This module provides defense against accidental credential leakage
 * by detecting and redacting API keys, tokens, and other secrets
 * from outbound messages.
 *
 * @module security/output-redaction
 */

import {
  calculateEntropy,
  isHighEntropy,
  detectHighEntropyStrings,
  detectBase64Secrets,
  detectAllHighEntropyData,
  type EntropyDetection,
  type EntropyDetectionConfig,
  DEFAULT_ENTROPY_CONFIG,
} from "./entropy.js";
import {
  redactSecrets,
  containsSecretsQuick,
  createRedactionFilter,
  type RedactionOptions,
  type RedactionResult,
  type RedactionEvent,
  DEFAULT_REDACTION_OPTIONS,
} from "./filter.js";
import {
  detectSecrets,
  containsSecrets,
  getHighConfidencePatterns,
  type SecretPattern,
  SECRET_PATTERNS,
} from "./patterns.js";

// Re-export core functions
export {
  // Filter functions
  redactSecrets,
  containsSecretsQuick,
  createRedactionFilter,
  DEFAULT_REDACTION_OPTIONS,

  // Pattern detection
  detectSecrets,
  containsSecrets,
  getHighConfidencePatterns,
  SECRET_PATTERNS,

  // Entropy detection
  calculateEntropy,
  isHighEntropy,
  detectHighEntropyStrings,
  detectBase64Secrets,
  detectAllHighEntropyData,
  DEFAULT_ENTROPY_CONFIG,
};

// Re-export types
export type {
  RedactionOptions,
  RedactionResult,
  RedactionEvent,
  SecretPattern,
  EntropyDetection,
  EntropyDetectionConfig,
};

/**
 * Default redaction filter instance
 */
export const defaultRedactionFilter = createRedactionFilter();

/**
 * Convenience function to redact secrets with default settings
 *
 * @param content - Content to redact
 * @returns Redaction result
 */
export function redactOutboundMessage(content: string): RedactionResult {
  return defaultRedactionFilter.redact(content);
}

/**
 * Convenience function to check if content contains secrets
 *
 * @param content - Content to check
 * @returns True if content contains potential secrets
 */
export function checkForSecrets(content: string): boolean {
  return defaultRedactionFilter.containsSecrets(content);
}

/**
 * Redaction statistics for monitoring
 */
export interface RedactionStats {
  totalChecked: number;
  totalRedacted: number;
  byType: Map<string, number>;
  byMethod: Map<string, number>;
}

/**
 * Create a monitored redaction filter with statistics
 */
export function createMonitoredRedactionFilter(options: Partial<RedactionOptions> = {}) {
  const stats: RedactionStats = {
    totalChecked: 0,
    totalRedacted: 0,
    byType: new Map(),
    byMethod: new Map(),
  };

  const innerFilter = createRedactionFilter(options);

  return {
    /**
     * Redact secrets and track statistics
     */
    redact(content: string): RedactionResult {
      stats.totalChecked++;
      const result = innerFilter.redact(content);

      if (result.modified) {
        stats.totalRedacted++;

        for (const [type, count] of result.redactionCounts) {
          stats.byType.set(type, (stats.byType.get(type) ?? 0) + count);
        }

        for (const event of result.events) {
          stats.byMethod.set(event.method, (stats.byMethod.get(event.method) ?? 0) + 1);
        }
      }

      return result;
    },

    /**
     * Quick check without full redaction
     */
    containsSecrets(content: string): boolean {
      return innerFilter.containsSecrets(content);
    },

    /**
     * Get current statistics
     */
    getStats(): RedactionStats {
      return {
        totalChecked: stats.totalChecked,
        totalRedacted: stats.totalRedacted,
        byType: new Map(stats.byType),
        byMethod: new Map(stats.byMethod),
      };
    },

    /**
     * Reset statistics
     */
    resetStats(): void {
      stats.totalChecked = 0;
      stats.totalRedacted = 0;
      stats.byType.clear();
      stats.byMethod.clear();
    },

    /**
     * Get current configuration
     */
    get config(): RedactionOptions {
      return innerFilter.config;
    },
  };
}
