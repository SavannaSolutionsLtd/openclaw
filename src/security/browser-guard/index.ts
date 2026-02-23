/**
 * Browser CDP Guard
 *
 * Security module for browser navigation protection. Provides URL-level
 * blocking, IDN homograph detection, navigation rate limiting, and
 * domain allowlist/blocklist enforcement.
 *
 * This module complements the hostname/IP-level SSRF protection in
 * src/infra/net/ssrf.ts by adding URL-pattern-based checks that catch
 * additional attack vectors.
 *
 * @module security/browser-guard
 */

export {
  type BlockCheckResult,
  CLOUD_METADATA_PATTERNS,
  PRIVATE_NETWORK_PATTERNS,
  BLOCKED_PROTOCOLS,
  ALLOWED_PROTOCOLS,
  isBlockedUrl,
  hasHomographCharacters,
  getAllBlockedPatterns,
} from "./url-blocklist.js";

export {
  type NavigationPolicyConfig,
  type NavigationCheckResult,
  DEFAULT_NAVIGATION_POLICY,
  NavigationRateLimitError,
  BlockedNavigationError,
  createNavigationPolicy,
} from "./navigation-policy.js";
