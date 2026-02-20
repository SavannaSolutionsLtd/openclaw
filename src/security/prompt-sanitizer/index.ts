/**
 * Prompt Injection Sanitizer
 *
 * This module provides defense-in-depth against prompt injection attacks
 * by detecting, logging, and wrapping potentially malicious content in
 * inbound messages from all channels.
 *
 * @module security/prompt-sanitizer
 */

import {
  detectInjectionPatterns,
  containsHighSeverityPattern,
  containsBase64Payload,
  type DetectionResult,
} from "./patterns.js";
import {
  wrapUntrustedInput,
  wrapHighRiskContent,
  normalizeUntrustedText,
  stripDangerousUnicode,
  type UntrustedSource,
  type WrapOptions,
  type SanitizationResult,
} from "./wrapper.js";

// Re-export types and utilities
export {
  detectInjectionPatterns,
  containsHighSeverityPattern,
  containsBase64Payload,
  wrapUntrustedInput,
  wrapHighRiskContent,
  normalizeUntrustedText,
  stripDangerousUnicode,
};
export type { DetectionResult, UntrustedSource, WrapOptions, SanitizationResult };

/**
 * Configuration options for the sanitizer
 */
export interface SanitizerConfig {
  /** Whether sanitization is enabled (default: true) */
  enabled: boolean;
  /** Whether to log sanitization events (default: true) */
  logEvents: boolean;
  /** Whether to use strict mode - block instead of wrap high-risk content (default: false) */
  strictMode: boolean;
  /** Risk score threshold for high-risk classification (default: 50) */
  highRiskThreshold: number;
  /** Whether to strip dangerous unicode characters (default: true) */
  stripUnicode: boolean;
  /** Whether to normalize whitespace (default: true) */
  normalizeWhitespace: boolean;
  /** Custom log function */
  logger?: (event: SanitizationEvent) => void;
}

/**
 * Event logged when sanitization occurs
 */
export interface SanitizationEvent {
  timestamp: string;
  source: UntrustedSource;
  channel?: string;
  senderId?: string;
  detected: boolean;
  riskScore: number;
  categories: string[];
  highRisk: boolean;
  action: "wrapped" | "blocked" | "passed";
  contentLength: number;
  contentHash?: string;
}

/**
 * Default sanitizer configuration
 */
export const DEFAULT_CONFIG: SanitizerConfig = {
  enabled: true,
  logEvents: true,
  strictMode: false,
  highRiskThreshold: 50,
  stripUnicode: true,
  normalizeWhitespace: true,
};

/**
 * Simple SHA-256 hash for logging (doesn't expose content)
 */
async function hashContent(content: string): Promise<string> {
  if (typeof crypto !== "undefined" && crypto.subtle) {
    const encoder = new TextEncoder();
    const data = encoder.encode(content);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray
      .slice(0, 8)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }
  // Fallback: simple hash for environments without crypto.subtle
  let hash = 0;
  for (let i = 0; i < content.length; i++) {
    const char = content.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(16).padStart(8, "0");
}

/**
 * Create a configured sanitizer instance
 */
export function createSanitizer(config: Partial<SanitizerConfig> = {}) {
  const cfg: SanitizerConfig = { ...DEFAULT_CONFIG, ...config };

  /**
   * Sanitize inbound message content
   */
  async function sanitize(
    content: string,
    source: UntrustedSource,
    options: { channel?: string; senderId?: string } = {},
  ): Promise<SanitizationResult> {
    const original = content;

    // If disabled, just wrap without detection
    if (!cfg.enabled) {
      return {
        sanitized: wrapUntrustedInput(content, { source, ...options }),
        original,
        detected: false,
        modified: false,
        detection: null,
        highRisk: false,
      };
    }

    // Step 1: Detect injection patterns
    const detection = detectInjectionPatterns(content);

    // Step 2: Normalize content if configured
    let processedContent = content;
    let modified = false;

    if (cfg.stripUnicode) {
      const stripped = stripDangerousUnicode(content);
      if (stripped !== content) {
        processedContent = stripped;
        modified = true;
      }
    }

    if (cfg.normalizeWhitespace) {
      const normalized = normalizeUntrustedText(processedContent);
      if (normalized !== processedContent) {
        processedContent = normalized;
        modified = true;
      }
    }

    // Step 3: Determine risk level
    const highRisk = detection.riskScore >= cfg.highRiskThreshold;

    // Step 4: Wrap content appropriately
    const wrapOptions: WrapOptions = {
      source,
      channel: options.channel,
      senderId: options.senderId,
      detection,
      includeMetadata: detection.detected,
    };

    let sanitized: string;
    let action: SanitizationEvent["action"];

    if (cfg.strictMode && highRisk) {
      // In strict mode, block high-risk content entirely
      sanitized = `<blocked-content reason="high-risk-injection-detected" risk-score="${detection.riskScore}" />`;
      action = "blocked";
    } else if (highRisk) {
      // Wrap with security warning
      sanitized = wrapHighRiskContent(processedContent, wrapOptions);
      action = "wrapped";
    } else if (detection.detected) {
      // Wrap with metadata
      sanitized = wrapUntrustedInput(processedContent, wrapOptions);
      action = "wrapped";
    } else {
      // Just wrap normally
      sanitized = wrapUntrustedInput(processedContent, wrapOptions);
      action = "passed";
    }

    // Step 5: Log event if configured
    if (cfg.logEvents && (detection.detected || cfg.logger)) {
      const event: SanitizationEvent = {
        timestamp: new Date().toISOString(),
        source,
        channel: options.channel,
        senderId: options.senderId,
        detected: detection.detected,
        riskScore: detection.riskScore,
        categories: [...new Set(detection.matches.map((m) => m.category))],
        highRisk,
        action,
        contentLength: original.length,
        contentHash: await hashContent(original),
      };

      if (cfg.logger) {
        cfg.logger(event);
      } else if (detection.detected) {
        // Default logging to console.warn
        console.warn("[prompt-sanitizer] Injection pattern detected:", JSON.stringify(event));
      }
    }

    return {
      sanitized,
      original,
      detected: detection.detected,
      modified,
      detection,
      highRisk,
    };
  }

  /**
   * Quick check without full sanitization
   */
  function quickCheck(content: string): { safe: boolean; riskScore: number } {
    if (!cfg.enabled) {
      return { safe: true, riskScore: 0 };
    }

    const detection = detectInjectionPatterns(content);
    return {
      safe: detection.riskScore < cfg.highRiskThreshold,
      riskScore: detection.riskScore,
    };
  }

  /**
   * Check if content should be blocked in strict mode
   */
  function shouldBlock(content: string): boolean {
    if (!cfg.enabled || !cfg.strictMode) {
      return false;
    }
    return containsHighSeverityPattern(content);
  }

  return {
    sanitize,
    quickCheck,
    shouldBlock,
    config: cfg,
  };
}

/**
 * Default sanitizer instance
 */
export const defaultSanitizer = createSanitizer();

/**
 * Convenience function to sanitize content with default settings
 */
export async function sanitizeInboundMessage(
  content: string,
  source: UntrustedSource,
  options: { channel?: string; senderId?: string } = {},
): Promise<SanitizationResult> {
  return defaultSanitizer.sanitize(content, source, options);
}

/**
 * Convenience function for quick risk check
 */
export function checkMessageRisk(content: string): { safe: boolean; riskScore: number } {
  return defaultSanitizer.quickCheck(content);
}
