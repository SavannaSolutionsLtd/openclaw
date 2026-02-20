/**
 * Prompt Injection Detection Patterns
 *
 * This module detects common prompt injection attack patterns in inbound messages.
 * Patterns are based on known attack techniques from security research.
 *
 * @module security/prompt-sanitizer/patterns
 */

/**
 * Regex patterns that indicate potential prompt injection attempts.
 * These cover direct injection, jailbreak attempts, and obfuscation techniques.
 */
export const INJECTION_PATTERNS: Array<{
  pattern: RegExp;
  category: string;
  severity: "high" | "medium" | "low";
}> = [
  // Direct instruction override attempts
  {
    pattern: /ignore\s+(all\s+)?previous\s+instructions?/i,
    category: "instruction-override",
    severity: "high",
  },
  { pattern: /disregard\s+(all\s+)?prior\s+/i, category: "instruction-override", severity: "high" },
  { pattern: /forget\s+(all\s+)?previous\s+/i, category: "instruction-override", severity: "high" },
  {
    pattern: /forget\s+everything\s+(you\s+)?were\s+told/i,
    category: "instruction-override",
    severity: "high",
  },
  {
    pattern: /override\s+(all\s+)?previous\s+/i,
    category: "instruction-override",
    severity: "high",
  },

  // New instruction injection
  { pattern: /new\s+instruction[s]?:/i, category: "instruction-injection", severity: "high" },
  {
    pattern: /your\s+new\s+(task|instruction|role)/i,
    category: "instruction-injection",
    severity: "high",
  },
  {
    pattern: /from\s+now\s+on[,:]?\s+(you|your)/i,
    category: "instruction-injection",
    severity: "medium",
  },

  // System prompt injection markers
  { pattern: /system\s*:\s*/i, category: "system-prompt", severity: "high" },
  { pattern: /\[INST\]/i, category: "system-prompt", severity: "high" },
  { pattern: /<<SYS>>/i, category: "system-prompt", severity: "high" },
  { pattern: /<\|im_start\|>/i, category: "system-prompt", severity: "high" },
  { pattern: /<\|system\|>/i, category: "system-prompt", severity: "high" },

  // Markdown/code block injection
  { pattern: /```system/i, category: "markdown-injection", severity: "medium" },
  { pattern: /```instruction/i, category: "markdown-injection", severity: "medium" },
  { pattern: /```prompt/i, category: "markdown-injection", severity: "medium" },

  // Role-play/persona hijacking
  { pattern: /you\s+are\s+now\s+(a|an|the)\s+/i, category: "persona-hijack", severity: "medium" },
  {
    pattern: /pretend\s+(you're|you\s+are|to\s+be)/i,
    category: "persona-hijack",
    severity: "medium",
  },
  {
    pattern: /act\s+as\s+(if\s+you're|if\s+you\s+are|a\s+|an\s+)/i,
    category: "persona-hijack",
    severity: "medium",
  },
  { pattern: /roleplay\s+as/i, category: "persona-hijack", severity: "medium" },

  // Developer/debug mode attempts
  {
    pattern: /enter\s+(developer|debug|admin)\s+mode/i,
    category: "privilege-escalation",
    severity: "high",
  },
  {
    pattern: /enable\s+(developer|debug|admin)\s+mode/i,
    category: "privilege-escalation",
    severity: "high",
  },
  {
    pattern: /switch\s+to\s+(developer|debug|admin)/i,
    category: "privilege-escalation",
    severity: "high",
  },

  // Output manipulation
  {
    pattern: /do\s+not\s+(reveal|disclose|show|mention)/i,
    category: "output-manipulation",
    severity: "medium",
  },
  { pattern: /hide\s+(this|the\s+following)/i, category: "output-manipulation", severity: "low" },

  // Unicode obfuscation
  { pattern: /\u202e/, category: "unicode-obfuscation", severity: "high" }, // RTL override
  { pattern: /\u200b/, category: "unicode-obfuscation", severity: "medium" }, // Zero-width space
  { pattern: /\u200c/, category: "unicode-obfuscation", severity: "medium" }, // Zero-width non-joiner
  { pattern: /\u200d/, category: "unicode-obfuscation", severity: "medium" }, // Zero-width joiner
  { pattern: /\u2060/, category: "unicode-obfuscation", severity: "medium" }, // Word joiner
  { pattern: /\ufeff/, category: "unicode-obfuscation", severity: "medium" }, // BOM

  // Homoglyph attacks (common substitutions)
  {
    pattern: /[\u0430\u0435\u043e\u0440\u0441\u0445]{3,}/i,
    category: "homoglyph",
    severity: "low",
  }, // Cyrillic lookalikes
];

/**
 * Keywords that may indicate exfiltration attempts when combined with tool usage
 */
export const EXFILTRATION_KEYWORDS = [
  "send to",
  "forward to",
  "email to",
  "post to",
  "upload to",
  "exfiltrate",
  "transmit",
  "webhook",
  "curl",
  "fetch",
  "http://",
  "https://",
];

/**
 * Base64 detection pattern - matches strings that look like base64-encoded content
 * that might contain hidden instructions
 */
const BASE64_PATTERN = /^[A-Za-z0-9+/]{40,}={0,2}$/;

/**
 * Check if a string contains potential base64-encoded payload
 */
export function containsBase64Payload(text: string): { detected: boolean; segments: string[] } {
  const segments: string[] = [];

  // Split by whitespace and check each segment
  const words = text.split(/\s+/);
  for (const word of words) {
    if (BASE64_PATTERN.test(word) && word.length >= 40) {
      // Try to decode and check for suspicious content
      try {
        const decoded = Buffer.from(word, "base64").toString("utf-8");
        // Check if decoded content looks like text (not binary)
        if (/^[\x20-\x7E\n\r\t]+$/.test(decoded)) {
          // Check for injection patterns in decoded content
          for (const { pattern } of INJECTION_PATTERNS) {
            if (pattern.test(decoded)) {
              segments.push(word);
              break;
            }
          }
        }
      } catch {
        // Invalid base64, ignore
      }
    }
  }

  return { detected: segments.length > 0, segments };
}

/**
 * Result of pattern detection
 */
export interface DetectionResult {
  detected: boolean;
  matches: Array<{
    pattern: string;
    category: string;
    severity: "high" | "medium" | "low";
    matchedText: string;
  }>;
  base64Payloads: string[];
  riskScore: number; // 0-100
}

/**
 * Detect injection patterns in the given text
 */
export function detectInjectionPatterns(text: string): DetectionResult {
  const matches: DetectionResult["matches"] = [];
  let riskScore = 0;

  // Check each injection pattern
  for (const { pattern, category, severity } of INJECTION_PATTERNS) {
    const match = text.match(pattern);
    if (match) {
      matches.push({
        pattern: pattern.source,
        category,
        severity,
        matchedText: match[0],
      });

      // Add to risk score based on severity
      switch (severity) {
        case "high":
          riskScore += 40;
          break;
        case "medium":
          riskScore += 20;
          break;
        case "low":
          riskScore += 10;
          break;
      }
    }
  }

  // Check for base64 payloads
  const base64Result = containsBase64Payload(text);
  if (base64Result.detected) {
    riskScore += 30;
  }

  // Cap risk score at 100
  riskScore = Math.min(riskScore, 100);

  return {
    detected: matches.length > 0 || base64Result.detected,
    matches,
    base64Payloads: base64Result.segments,
    riskScore,
  };
}

/**
 * Quick check if text contains any high-severity patterns
 */
export function containsHighSeverityPattern(text: string): boolean {
  for (const { pattern, severity } of INJECTION_PATTERNS) {
    if (severity === "high" && pattern.test(text)) {
      return true;
    }
  }
  return false;
}
