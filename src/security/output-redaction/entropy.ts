/**
 * High-Entropy String Detection
 *
 * Detects potentially secret data by measuring Shannon entropy.
 * High-entropy strings are often API keys, passwords, or tokens.
 *
 * @module security/output-redaction/entropy
 */

/**
 * Calculate Shannon entropy of a string
 *
 * Entropy measures randomness/unpredictability. Typical values:
 * - English text: 3.5-4.5 bits/char
 * - Base64 encoded: 5.5-6 bits/char
 * - Hex encoded: 3.5-4 bits/char
 * - Random passwords: 5-6 bits/char
 * - API keys: 5.5-6+ bits/char
 *
 * @param str - String to analyze
 * @returns Shannon entropy in bits per character
 */
export function calculateEntropy(str: string): number {
  if (!str || str.length === 0) {
    return 0;
  }

  // Count character frequencies
  const freq = new Map<string, number>();
  for (const char of str) {
    freq.set(char, (freq.get(char) ?? 0) + 1);
  }

  // Calculate entropy using Shannon's formula: -Σ p(x) * log2(p(x))
  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Check if a string has high entropy (likely a secret)
 *
 * @param str - String to check
 * @param threshold - Entropy threshold (default: 4.5 bits/char)
 * @param minLength - Minimum string length to consider (default: 16)
 * @returns True if the string appears to be a high-entropy secret
 */
export function isHighEntropy(str: string, threshold = 4.5, minLength = 16): boolean {
  // Short strings are not considered secrets
  if (str.length < minLength) {
    return false;
  }

  // Filter to alphanumeric/common secret chars
  const filtered = str.replace(/[^a-zA-Z0-9+/=_-]/g, "");

  // If mostly non-alphanumeric, not a typical secret
  if (filtered.length < str.length * 0.7) {
    return false;
  }

  return calculateEntropy(filtered) >= threshold;
}

/**
 * Configuration for high-entropy string detection
 */
export interface EntropyDetectionConfig {
  /** Entropy threshold in bits per character */
  threshold: number;
  /** Minimum string length to analyze */
  minLength: number;
  /** Maximum string length to analyze (performance) */
  maxLength: number;
  /** Whether to check inside words (vs whole tokens) */
  checkInsideWords: boolean;
}

/**
 * Default entropy detection configuration
 */
export const DEFAULT_ENTROPY_CONFIG: EntropyDetectionConfig = {
  threshold: 4.5,
  minLength: 16,
  maxLength: 512,
  checkInsideWords: false,
};

/**
 * Result of entropy-based secret detection
 */
export interface EntropyDetection {
  /** The matched string */
  match: string;
  /** Calculated entropy value */
  entropy: number;
  /** Start position in original text */
  start: number;
  /** End position in original text */
  end: number;
}

/**
 * Detect high-entropy strings that may be secrets
 *
 * @param content - Text to scan
 * @param config - Detection configuration
 * @returns Array of detected high-entropy strings
 */
export function detectHighEntropyStrings(
  content: string,
  config: Partial<EntropyDetectionConfig> = {},
): EntropyDetection[] {
  const cfg = { ...DEFAULT_ENTROPY_CONFIG, ...config };
  const detections: EntropyDetection[] = [];

  // Match potential secret tokens (alphanumeric with common delimiters)
  // This regex finds continuous strings of secret-like characters
  const tokenPattern = /[a-zA-Z0-9+/=_-]{16,}/g;
  let match: RegExpExecArray | null;

  while ((match = tokenPattern.exec(content)) !== null) {
    const str = match[0];

    // Skip if too long (likely base64 encoded content, not a key)
    if (str.length > cfg.maxLength) {
      continue;
    }

    // Skip common false positives
    if (isLikelyFalsePositive(str)) {
      continue;
    }

    const entropy = calculateEntropy(str);
    if (entropy >= cfg.threshold) {
      detections.push({
        match: str,
        entropy,
        start: match.index,
        end: match.index + str.length,
      });
    }
  }

  return detections;
}

/**
 * Check if a high-entropy string is likely a false positive
 */
function isLikelyFalsePositive(str: string): boolean {
  // All same character
  if (new Set(str).size === 1) {
    return true;
  }

  // Repeating patterns (e.g., "abcabcabc")
  for (let patternLen = 1; patternLen <= 4; patternLen++) {
    const pattern = str.slice(0, patternLen);
    if (str === pattern.repeat(Math.ceil(str.length / patternLen)).slice(0, str.length)) {
      return true;
    }
  }

  // Sequential characters (e.g., "abcdefghijklmnop")
  if (isSequential(str)) {
    return true;
  }

  // Common non-secret patterns
  const lowerStr = str.toLowerCase();
  const falsePositivePatterns = [
    /^[a-f0-9]+$/, // Pure hex could be a hash display, not necessarily secret
    /^[0-9]+$/, // Pure numbers
    /^application\//i, // MIME types
    /^multipart\//i,
    /^text\//i,
    /^image\//i,
    /^(true|false|null|undefined)+$/i, // Repeated boolean-like
  ];

  for (const pattern of falsePositivePatterns) {
    if (pattern.test(lowerStr)) {
      return true;
    }
  }

  return false;
}

/**
 * Check if a string contains sequential characters
 */
function isSequential(str: string): boolean {
  if (str.length < 8) {
    return false;
  }

  let ascending = 0;
  let descending = 0;

  for (let i = 1; i < str.length; i++) {
    const diff = str.charCodeAt(i) - str.charCodeAt(i - 1);
    if (diff === 1) {
      ascending++;
    }
    if (diff === -1) {
      descending++;
    }
  }

  const ratio = Math.max(ascending, descending) / (str.length - 1);
  return ratio > 0.7;
}

/**
 * Detect base64-encoded content that might contain secrets
 *
 * @param content - Text to scan
 * @returns Array of detected base64 segments that decode to high-entropy data
 */
export function detectBase64Secrets(content: string): string[] {
  const secrets: string[] = [];

  // Match potential base64 strings (min 24 chars for meaningful content)
  const base64Pattern = /[A-Za-z0-9+/]{24,}={0,2}/g;
  let match: RegExpExecArray | null;

  while ((match = base64Pattern.exec(content)) !== null) {
    const encoded = match[0];

    try {
      const decoded = Buffer.from(encoded, "base64").toString("utf-8");

      // Check if decoded content is valid UTF-8 text
      if (!/^[\x20-\x7E\n\r\t]+$/.test(decoded)) {
        continue;
      }

      // Check if decoded content has high entropy or matches secret patterns
      if (isHighEntropy(decoded, 4.0, 12)) {
        secrets.push(encoded);
        continue;
      }

      // Check for secret-like prefixes in decoded content
      const secretPrefixes = [
        "sk-",
        "pk-",
        "api_",
        "key_",
        "token_",
        "secret_",
        "ghp_",
        "gho_",
        "glpat-",
        "xoxb-",
        "AKIA",
      ];

      for (const prefix of secretPrefixes) {
        if (decoded.includes(prefix)) {
          secrets.push(encoded);
          break;
        }
      }
    } catch {
      // Not valid base64, skip
    }
  }

  return secrets;
}

/**
 * Combined detection: patterns + entropy + base64
 *
 * @param content - Text to scan
 * @param entropyThreshold - Entropy threshold for detection
 * @returns Object with all detection results
 */
export function detectAllHighEntropyData(
  content: string,
  entropyThreshold = 4.5,
): {
  highEntropyStrings: EntropyDetection[];
  base64Secrets: string[];
} {
  return {
    highEntropyStrings: detectHighEntropyStrings(content, { threshold: entropyThreshold }),
    base64Secrets: detectBase64Secrets(content),
  };
}
