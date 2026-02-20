/**
 * Security utilities for sanitizing channel metadata before inclusion in prompts.
 *
 * Channel metadata (group names, topics, participant names) comes from external
 * sources and can be manipulated by attackers to inject malicious instructions.
 *
 * SECURITY: All channel metadata MUST be sanitized before being interpolated
 * into system prompts or any LLM context.
 */

import { detectSuspiciousPatterns } from "./external-content.js";

/**
 * Maximum allowed length for sanitized channel metadata fields.
 * Longer values are truncated to prevent context overflow attacks.
 */
const MAX_GROUP_NAME_LENGTH = 128;
const MAX_PARTICIPANT_NAME_LENGTH = 64;
const MAX_PARTICIPANT_LIST_LENGTH = 1024;

/**
 * Result of sanitization with metadata about what was changed.
 */
export type SanitizeResult = {
  /** Sanitized value, safe to use in prompts */
  value: string;
  /** Whether the original value was modified */
  wasModified: boolean;
  /** Suspicious patterns detected (for logging) */
  suspiciousPatterns: string[];
  /** Whether the value was truncated */
  wasTruncated: boolean;
};

/**
 * Characters that could be used to break out of string contexts in prompts.
 * These are escaped or stripped to prevent injection.
 * Includes: double quotes, newlines, tabs, and control characters (U+0000-U+001F, U+007F)
 */
// oxlint-disable-next-line no-control-regex
const DANGEROUS_CHARS_PATTERN = /["\n\r\t\x00-\x1f\x7f]/g;

/**
 * Patterns that look like prompt structure manipulation attempts.
 */
const STRUCTURE_INJECTION_PATTERNS = [
  /\]\s*\[/g, // Array/section break attempts
  /}\s*{/g, // Object break attempts
  />>>/g, // Boundary marker attempts
  /<<</g, // Boundary marker attempts
  /<\/?system>/gi, // XML tag injection
  /<\/?user>/gi, // XML tag injection
  /<\/?assistant>/gi, // XML tag injection
];

/**
 * Escapes dangerous characters that could break prompt structure.
 */
function escapeDangerousChars(input: string): string {
  return input.replace(DANGEROUS_CHARS_PATTERN, (char) => {
    switch (char) {
      case '"':
        return "'";
      case "\n":
      case "\r":
        return " ";
      case "\t":
        return " ";
      default:
        return "";
    }
  });
}

/**
 * Neutralizes structure injection attempts by adding spaces.
 */
function neutralizeStructureInjection(input: string): string {
  let result = input;
  for (const pattern of STRUCTURE_INJECTION_PATTERNS) {
    result = result.replace(pattern, (match) => match.split("").join(" "));
  }
  return result;
}

/**
 * Truncates string to max length, preserving word boundaries when possible.
 */
function truncateToLength(input: string, maxLength: number): { value: string; truncated: boolean } {
  if (input.length <= maxLength) {
    return { value: input, truncated: false };
  }
  const truncated = input.slice(0, maxLength);
  const lastSpace = truncated.lastIndexOf(" ");
  if (lastSpace > maxLength * 0.7) {
    return { value: truncated.slice(0, lastSpace), truncated: true };
  }
  return { value: truncated, truncated: true };
}

/**
 * Core sanitization logic shared by all field types.
 */
function sanitizeField(input: string, maxLength: number): SanitizeResult {
  const original = input;
  const suspiciousPatterns = detectSuspiciousPatterns(input);
  let sanitized = escapeDangerousChars(input);
  sanitized = neutralizeStructureInjection(sanitized);
  sanitized = sanitized.replace(/\s+/g, " ").trim();
  const { value, truncated } = truncateToLength(sanitized, maxLength);
  return {
    value,
    wasModified: value !== original,
    suspiciousPatterns,
    wasTruncated: truncated,
  };
}

/**
 * Sanitizes a group/channel name for safe inclusion in prompts.
 */
export function sanitizeGroupName(groupName: string | undefined | null): SanitizeResult {
  if (!groupName?.trim()) {
    return { value: "", wasModified: false, suspiciousPatterns: [], wasTruncated: false };
  }
  return sanitizeField(groupName.trim(), MAX_GROUP_NAME_LENGTH);
}

/**
 * Sanitizes a participant/member name for safe inclusion in prompts.
 */
export function sanitizeParticipantName(name: string | undefined | null): SanitizeResult {
  if (!name?.trim()) {
    return { value: "", wasModified: false, suspiciousPatterns: [], wasTruncated: false };
  }
  return sanitizeField(name.trim(), MAX_PARTICIPANT_NAME_LENGTH);
}

/**
 * Sanitizes a list of participant names.
 * Each name is individually sanitized, then joined with commas.
 */
export function sanitizeParticipantList(
  participants: string[] | string | undefined | null,
): SanitizeResult {
  if (!participants) {
    return { value: "", wasModified: false, suspiciousPatterns: [], wasTruncated: false };
  }
  const names = typeof participants === "string" ? participants.split(",") : participants;
  const sanitizedNames: string[] = [];
  const allSuspiciousPatterns: string[] = [];
  let anyModified = false;

  for (const name of names) {
    const result = sanitizeParticipantName(name);
    if (result.value) {
      sanitizedNames.push(result.value);
    }
    if (result.wasModified) {
      anyModified = true;
    }
    allSuspiciousPatterns.push(...result.suspiciousPatterns);
  }

  const joined = sanitizedNames.join(", ");
  const { value, truncated } = truncateToLength(joined, MAX_PARTICIPANT_LIST_LENGTH);
  return {
    value,
    wasModified: anyModified || truncated,
    suspiciousPatterns: [...new Set(allSuspiciousPatterns)],
    wasTruncated: truncated,
  };
}
