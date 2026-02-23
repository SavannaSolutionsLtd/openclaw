/**
 * Outbound Content Redaction Filter
 *
 * Redacts sensitive information from outbound messages to prevent
 * accidental credential leakage through AI responses.
 *
 * @module security/output-redaction/filter
 */

import { detectHighEntropyStrings, detectBase64Secrets } from "./entropy.js";
import { detectSecrets } from "./patterns.js";

/**
 * Redaction options
 */
export interface RedactionOptions {
  /** Use only high-confidence patterns (fewer false positives) */
  strictPatterns: boolean;
  /** Enable high-entropy string detection */
  detectEntropy: boolean;
  /** Enable base64-encoded secret detection */
  detectBase64: boolean;
  /** Entropy threshold for detection */
  entropyThreshold: number;
  /** Minimum length for entropy detection */
  minEntropyLength: number;
  /** Redaction placeholder template (use {TYPE} for secret type) */
  placeholder: string;
  /** Whether to log redaction events */
  logRedactions: boolean;
  /** Custom logger function */
  logger?: (event: RedactionEvent) => void;
  /** Whitelist patterns that should not be redacted */
  whitelist?: RegExp[];
}

/**
 * Event logged when redaction occurs
 */
export interface RedactionEvent {
  timestamp: string;
  type: string;
  description: string;
  method: "pattern" | "entropy" | "base64";
  originalLength: number;
  redactedPreview: string;
}

/**
 * Result of redaction operation
 */
export interface RedactionResult {
  /** The redacted content */
  redacted: string;
  /** Whether any redactions were made */
  modified: boolean;
  /** Count of redactions by type */
  redactionCounts: Map<string, number>;
  /** Redaction events for logging */
  events: RedactionEvent[];
}

/**
 * Default redaction options
 */
export const DEFAULT_REDACTION_OPTIONS: RedactionOptions = {
  strictPatterns: false,
  detectEntropy: true,
  detectBase64: true,
  entropyThreshold: 4.5,
  minEntropyLength: 20,
  placeholder: "[REDACTED:{TYPE}]",
  logRedactions: true,
  whitelist: [],
};

/**
 * Create a redaction placeholder
 */
function createPlaceholder(template: string, type: string): string {
  return template.replace("{TYPE}", type);
}

/**
 * Check if a match should be whitelisted
 */
function isWhitelisted(match: string, whitelist: RegExp[]): boolean {
  return whitelist.some((pattern) => pattern.test(match));
}

/**
 * Redact secrets from content
 *
 * @param content - Content to redact
 * @param options - Redaction options
 * @returns Redaction result with modified content and metadata
 */
export function redactSecrets(
  content: string,
  options: Partial<RedactionOptions> = {},
): RedactionResult {
  const opts = { ...DEFAULT_REDACTION_OPTIONS, ...options };
  const whitelist = opts.whitelist ?? [];

  let redacted = content;
  const redactionCounts = new Map<string, number>();
  const events: RedactionEvent[] = [];

  // Track what we've already redacted to avoid double-processing
  const alreadyRedacted = new Set<string>();

  // Step 1: Pattern-based detection (highest priority - most accurate)
  const patternDetections = detectSecrets(content, opts.strictPatterns);

  for (const detection of patternDetections) {
    if (alreadyRedacted.has(detection.match)) {
      continue;
    }
    if (isWhitelisted(detection.match, whitelist)) {
      continue;
    }

    const placeholder = createPlaceholder(opts.placeholder, detection.type);
    redacted = redacted.split(detection.match).join(placeholder);
    alreadyRedacted.add(detection.match);

    const count = redactionCounts.get(detection.type) ?? 0;
    redactionCounts.set(detection.type, count + 1);

    if (opts.logRedactions) {
      events.push({
        timestamp: new Date().toISOString(),
        type: detection.type,
        description: detection.description,
        method: "pattern",
        originalLength: detection.match.length,
        redactedPreview: maskForLog(detection.match),
      });
    }
  }

  // Step 2: Base64-encoded secret detection
  if (opts.detectBase64) {
    const base64Secrets = detectBase64Secrets(content);

    for (const encoded of base64Secrets) {
      if (alreadyRedacted.has(encoded)) {
        continue;
      }
      if (isWhitelisted(encoded, whitelist)) {
        continue;
      }

      // Check if this overlaps with already-redacted content
      if (!redacted.includes(encoded)) {
        continue;
      }

      const placeholder = createPlaceholder(opts.placeholder, "BASE64_SECRET");
      redacted = redacted.split(encoded).join(placeholder);
      alreadyRedacted.add(encoded);

      const count = redactionCounts.get("BASE64_SECRET") ?? 0;
      redactionCounts.set("BASE64_SECRET", count + 1);

      if (opts.logRedactions) {
        events.push({
          timestamp: new Date().toISOString(),
          type: "BASE64_SECRET",
          description: "Base64-encoded secret",
          method: "base64",
          originalLength: encoded.length,
          redactedPreview: maskForLog(encoded),
        });
      }
    }
  }

  // Step 3: High-entropy string detection (lowest priority - may have false positives)
  if (opts.detectEntropy) {
    const entropyDetections = detectHighEntropyStrings(redacted, {
      threshold: opts.entropyThreshold,
      minLength: opts.minEntropyLength,
    });

    for (const detection of entropyDetections) {
      if (alreadyRedacted.has(detection.match)) {
        continue;
      }
      if (isWhitelisted(detection.match, whitelist)) {
        continue;
      }

      // Additional validation for entropy-based detection
      if (!looksLikeSecret(detection.match)) {
        continue;
      }

      const placeholder = createPlaceholder(opts.placeholder, "HIGH_ENTROPY");
      redacted = redacted.split(detection.match).join(placeholder);
      alreadyRedacted.add(detection.match);

      const count = redactionCounts.get("HIGH_ENTROPY") ?? 0;
      redactionCounts.set("HIGH_ENTROPY", count + 1);

      if (opts.logRedactions) {
        events.push({
          timestamp: new Date().toISOString(),
          type: "HIGH_ENTROPY",
          description: `High-entropy string (${detection.entropy.toFixed(2)} bits/char)`,
          method: "entropy",
          originalLength: detection.match.length,
          redactedPreview: maskForLog(detection.match),
        });
      }
    }
  }

  // Call custom logger if provided
  if (opts.logger && events.length > 0) {
    for (const event of events) {
      opts.logger(event);
    }
  }

  return {
    redacted,
    modified: redacted !== content,
    redactionCounts,
    events,
  };
}

/**
 * Additional heuristics for entropy-based detection to reduce false positives
 */
function looksLikeSecret(str: string): boolean {
  // Must contain mix of character types
  const hasLower = /[a-z]/.test(str);
  const hasUpper = /[A-Z]/.test(str);
  const hasDigit = /[0-9]/.test(str);
  const hasSpecial = /[+/=_-]/.test(str);

  const typeCount = [hasLower, hasUpper, hasDigit, hasSpecial].filter(Boolean).length;

  // Secrets typically have 3+ character types
  if (typeCount < 2) {
    return false;
  }

  // Check for common secret prefixes/patterns
  const secretIndicators = [
    /^[a-z]{2,4}[-_]/i, // sk-, pk_, etc.
    /key/i,
    /token/i,
    /secret/i,
    /password/i,
    /credential/i,
    /^[A-Z]{4}[0-9A-Z]/, // AKIA..., etc.
  ];

  for (const indicator of secretIndicators) {
    if (indicator.test(str)) {
      return true;
    }
  }

  // If it's long enough and has high character variety, likely a secret
  return str.length >= 24 && typeCount >= 3;
}

/**
 * Mask a secret for logging (show first/last few chars)
 */
function maskForLog(secret: string, visibleChars = 4): string {
  if (secret.length <= visibleChars * 2 + 3) {
    return "*".repeat(secret.length);
  }
  return `${secret.slice(0, visibleChars)}...[${secret.length - visibleChars * 2} chars]...${secret.slice(-visibleChars)}`;
}

/**
 * Quick check if content contains any secrets
 *
 * @param content - Content to check
 * @param options - Detection options
 * @returns True if content contains potential secrets
 */
export function containsSecretsQuick(
  content: string,
  options: Partial<RedactionOptions> = {},
): boolean {
  const opts = { ...DEFAULT_REDACTION_OPTIONS, ...options };

  // Check patterns first (fastest)
  const patternDetections = detectSecrets(content, opts.strictPatterns);
  if (patternDetections.length > 0) {
    return true;
  }

  // Check base64
  if (opts.detectBase64) {
    const base64Secrets = detectBase64Secrets(content);
    if (base64Secrets.length > 0) {
      return true;
    }
  }

  // Check entropy
  if (opts.detectEntropy) {
    const entropyDetections = detectHighEntropyStrings(content, {
      threshold: opts.entropyThreshold,
      minLength: opts.minEntropyLength,
    });
    if (entropyDetections.some((d) => looksLikeSecret(d.match))) {
      return true;
    }
  }

  return false;
}

/**
 * Create a configured redaction filter
 */
export function createRedactionFilter(options: Partial<RedactionOptions> = {}) {
  const opts = { ...DEFAULT_REDACTION_OPTIONS, ...options };

  return {
    /**
     * Redact secrets from content
     */
    redact(content: string): RedactionResult {
      return redactSecrets(content, opts);
    },

    /**
     * Quick check without full redaction
     */
    containsSecrets(content: string): boolean {
      return containsSecretsQuick(content, opts);
    },

    /**
     * Get current configuration
     */
    get config(): RedactionOptions {
      return { ...opts };
    },
  };
}
