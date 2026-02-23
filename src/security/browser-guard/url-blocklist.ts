/**
 * URL Blocklist for Browser CDP Guard
 *
 * Provides pattern-based URL blocking for SSRF prevention, complementing
 * the hostname/IP-level checks in src/infra/net/ssrf.ts with explicit
 * URL-pattern matching and IDN homograph detection.
 *
 * @module security/browser-guard/url-blocklist
 */

/**
 * Result of a URL block check
 */
export interface BlockCheckResult {
  /** Whether the URL is blocked */
  blocked: boolean;
  /** Reason for blocking */
  reason?: string;
  /** Category of the block */
  category?: "cloud-metadata" | "private-network" | "localhost" | "protocol" | "homograph";
}

/**
 * Cloud metadata endpoint patterns
 *
 * These URLs expose instance credentials and sensitive configuration
 * on major cloud platforms. Blocking at the URL level catches cases
 * that hostname-only checks might miss (e.g. DNS rebinding after
 * initial validation).
 */
export const CLOUD_METADATA_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
  // AWS IMDSv1/v2 (link-local)
  { pattern: /^https?:\/\/169\.254\.169\.254/i, description: "AWS instance metadata (IMDSv1/v2)" },
  // GCP metadata server
  { pattern: /^https?:\/\/metadata\.google\.internal/i, description: "GCP metadata server" },
  // Azure IMDS
  { pattern: /^https?:\/\/169\.254\.169\.254/i, description: "Azure instance metadata" },
  // Alibaba Cloud metadata
  { pattern: /^https?:\/\/100\.100\.100\.200/i, description: "Alibaba Cloud metadata" },
  // DigitalOcean metadata
  { pattern: /^https?:\/\/169\.254\.169\.254/i, description: "DigitalOcean metadata" },
  // Oracle Cloud IMDS
  { pattern: /^https?:\/\/169\.254\.169\.254/i, description: "Oracle Cloud IMDS" },
  // Kubernetes API server (common in-cluster address)
  { pattern: /^https?:\/\/kubernetes\.default/i, description: "Kubernetes API server" },
];

/**
 * Link-local and private network URL patterns
 *
 * These patterns block URLs targeting internal/private addresses
 * at the URL string level, providing defense-in-depth alongside
 * the IP-level checks in ssrf.ts.
 */
export const PRIVATE_NETWORK_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
  // Link-local (IPv4)
  { pattern: /^https?:\/\/169\.254\.\d+\.\d+/i, description: "IPv4 link-local address" },
  // Link-local (IPv6)
  { pattern: /^https?:\/\/\[fe80:/i, description: "IPv6 link-local address" },

  // RFC-1918 private ranges
  { pattern: /^https?:\/\/10\.\d+\.\d+\.\d+/i, description: "RFC-1918 Class A private" },
  {
    pattern: /^https?:\/\/172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/i,
    description: "RFC-1918 Class B private",
  },
  { pattern: /^https?:\/\/192\.168\.\d+\.\d+/i, description: "RFC-1918 Class C private" },

  // Localhost variants
  { pattern: /^https?:\/\/localhost([:/]|$)/i, description: "Localhost" },
  { pattern: /^https?:\/\/127\.\d+\.\d+\.\d+/i, description: "Loopback address" },
  { pattern: /^https?:\/\/\[::1\]/i, description: "IPv6 loopback" },
  { pattern: /^https?:\/\/0\.0\.0\.0/i, description: "Unspecified address" },

  // CGN / Shared address space (RFC 6598)
  {
    pattern: /^https?:\/\/100\.(6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\.\d+\.\d+/i,
    description: "CGN shared address",
  },
];

/**
 * Dangerous protocol schemes that should never be used for browser navigation
 */
export const BLOCKED_PROTOCOLS = new Set(["javascript:", "data:", "vbscript:", "file:", "ftp:"]);

/**
 * Allowed protocols for browser navigation
 */
export const ALLOWED_PROTOCOLS = new Set(["http:", "https:", "about:"]);

/**
 * Characters that look visually similar to ASCII characters but are
 * from different Unicode blocks (confusables/homoglyphs)
 */
const HOMOGRAPH_CONFUSABLES: ReadonlyMap<number, string> = new Map([
  // Cyrillic confusables
  [0x0430, "a"], // а → a
  [0x0435, "e"], // е → e
  [0x043e, "o"], // о → o
  [0x0440, "p"], // р → p
  [0x0441, "c"], // с → c
  [0x0445, "x"], // х → x
  [0x0443, "y"], // у → y
  [0x0456, "i"], // і → i
  [0x0458, "j"], // ј → j
  [0x04bb, "h"], // һ → h

  // Greek confusables
  [0x03b1, "a"], // α → a
  [0x03b5, "e"], // ε → e
  [0x03bf, "o"], // ο → o
  [0x03c1, "p"], // ρ → p
  [0x03c4, "t"], // τ → t
  [0x03bd, "v"], // ν → v

  // Latin-like from other blocks
  [0x0261, "g"], // ɡ → g
  [0x026f, "m"], // ɯ → m (turned m)
  [0x0251, "a"], // ɑ → a (script a)
]);

/**
 * Check if a domain name contains IDN homograph characters
 *
 * Detects mixed-script attacks where visually similar Unicode characters
 * from different scripts are used to impersonate legitimate domains
 * (e.g. "gооgle.com" using Cyrillic "о" instead of Latin "o").
 */
export function hasHomographCharacters(hostname: string): boolean {
  for (const char of hostname) {
    const codePoint = char.codePointAt(0);
    if (codePoint !== undefined && HOMOGRAPH_CONFUSABLES.has(codePoint)) {
      return true;
    }
  }
  return false;
}

/**
 * Extract hostname from a raw URL string without Unicode normalization.
 * This preserves IDN homograph characters that the URL constructor
 * would normalize to Punycode.
 */
function extractRawHostname(url: string): string | null {
  const match = /^https?:\/\/([^/:?#]+)/i.exec(url);
  return match ? match[1] : null;
}

/**
 * Check if a URL matches any blocked pattern
 */
export function isBlockedUrl(url: string): BlockCheckResult {
  const trimmedUrl = url.trim();

  if (!trimmedUrl) {
    return { blocked: true, reason: "Empty URL", category: "protocol" };
  }

  // Check protocol
  let parsed: URL;
  try {
    parsed = new URL(trimmedUrl);
  } catch {
    return { blocked: true, reason: `Invalid URL: ${trimmedUrl}`, category: "protocol" };
  }

  // Check blocked protocols
  if (BLOCKED_PROTOCOLS.has(parsed.protocol)) {
    return {
      blocked: true,
      reason: `Blocked protocol: ${parsed.protocol}`,
      category: "protocol",
    };
  }

  // Check allowed protocols
  if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) {
    return {
      blocked: true,
      reason: `Unknown protocol: ${parsed.protocol}`,
      category: "protocol",
    };
  }

  // Allow about: URLs (e.g. about:blank)
  if (parsed.protocol === "about:") {
    return { blocked: false };
  }

  // Check IDN homograph attacks using the raw URL string
  // (the URL constructor normalizes Unicode to Punycode in hostname)
  const rawHostname = extractRawHostname(trimmedUrl);
  if (rawHostname && hasHomographCharacters(rawHostname)) {
    return {
      blocked: true,
      reason: `Possible IDN homograph attack: ${rawHostname}`,
      category: "homograph",
    };
  }

  // Check cloud metadata patterns
  for (const { pattern, description } of CLOUD_METADATA_PATTERNS) {
    if (pattern.test(trimmedUrl)) {
      return {
        blocked: true,
        reason: `Blocked cloud metadata endpoint: ${description}`,
        category: "cloud-metadata",
      };
    }
  }

  // Check private network patterns
  for (const { pattern, description } of PRIVATE_NETWORK_PATTERNS) {
    if (pattern.test(trimmedUrl)) {
      return {
        blocked: true,
        reason: `Blocked private network access: ${description}`,
        category: "private-network",
      };
    }
  }

  return { blocked: false };
}

/**
 * Get all blocked URL patterns for inspection/testing
 */
export function getAllBlockedPatterns(): Array<{
  pattern: RegExp;
  description: string;
  category: string;
}> {
  return [
    ...CLOUD_METADATA_PATTERNS.map((p) => ({ ...p, category: "cloud-metadata" })),
    ...PRIVATE_NETWORK_PATTERNS.map((p) => ({ ...p, category: "private-network" })),
  ];
}
