/**
 * Navigation Policy for Browser CDP Guard
 *
 * Enforces security policies on browser navigation requests including
 * domain allowlisting, navigation rate limiting, and redirect tracking.
 *
 * @module security/browser-guard/navigation-policy
 */

import { isBlockedUrl, type BlockCheckResult } from "./url-blocklist.js";

/**
 * Navigation policy configuration
 */
export interface NavigationPolicyConfig {
  /** Maximum navigations per minute per session */
  maxNavigationsPerMinute: number;
  /** Maximum navigations per hour per session */
  maxNavigationsPerHour: number;
  /** Maximum redirect chain length */
  maxRedirectChainLength: number;
  /** Enable domain allowlist (if set, only these domains are accessible) */
  domainAllowlist?: string[];
  /** Additional blocked domains (combined with URL blocklist) */
  domainBlocklist?: string[];
  /** Whether to allow data: URIs in navigation */
  allowDataUrls: boolean;
  /** Whether to block IDN homograph attacks */
  blockHomographAttacks: boolean;
}

/**
 * Default navigation policy configuration
 */
export const DEFAULT_NAVIGATION_POLICY: NavigationPolicyConfig = {
  maxNavigationsPerMinute: 30,
  maxNavigationsPerHour: 300,
  maxRedirectChainLength: 10,
  allowDataUrls: false,
  blockHomographAttacks: true,
};

/**
 * Navigation check result
 */
export interface NavigationCheckResult {
  /** Whether the navigation is allowed */
  allowed: boolean;
  /** Reason for the decision */
  reason: string;
  /** Block check details */
  blockDetails?: BlockCheckResult;
  /** Current navigation rate */
  navigationsThisMinute?: number;
  /** Current hourly navigation rate */
  navigationsThisHour?: number;
}

/**
 * Navigation rate exceeded error
 */
export class NavigationRateLimitError extends Error {
  readonly retryAfterMs: number;

  constructor(message: string, retryAfterMs: number) {
    super(message);
    this.name = "NavigationRateLimitError";
    this.retryAfterMs = retryAfterMs;
  }
}

/**
 * Blocked navigation error
 */
export class BlockedNavigationError extends Error {
  readonly category: string;

  constructor(message: string, category: string) {
    super(message);
    this.name = "BlockedNavigationError";
    this.category = category;
  }
}

interface NavigationRecord {
  timestamps: number[];
}

function getNavigationRecord(
  records: Map<string, NavigationRecord>,
  sessionId: string,
): NavigationRecord {
  let record = records.get(sessionId);
  if (!record) {
    record = { timestamps: [] };
    records.set(sessionId, record);
  }
  return record;
}

function cleanupTimestamps(timestamps: number[], windowMs: number): number[] {
  const cutoff = Date.now() - windowMs;
  return timestamps.filter((ts) => ts > cutoff);
}

/**
 * Create a navigation policy enforcer
 */
export function createNavigationPolicy(config: Partial<NavigationPolicyConfig> = {}) {
  const cfg = { ...DEFAULT_NAVIGATION_POLICY, ...config };
  const navigationRecords = new Map<string, NavigationRecord>();

  return {
    /**
     * Check if navigation to a URL is allowed
     *
     * @param sessionId - Session identifier
     * @param url - URL to navigate to
     * @returns Navigation check result
     * @throws NavigationRateLimitError if rate limit exceeded
     * @throws BlockedNavigationError if URL is blocked
     */
    checkNavigation(sessionId: string, url: string): NavigationCheckResult {
      // 1. Check URL blocklist
      const blockResult = isBlockedUrl(url);
      if (blockResult.blocked) {
        throw new BlockedNavigationError(
          blockResult.reason ?? "Navigation blocked",
          blockResult.category ?? "unknown",
        );
      }

      // 2. Check domain allowlist
      if (cfg.domainAllowlist && cfg.domainAllowlist.length > 0) {
        try {
          const parsed = new URL(url);
          const hostname = parsed.hostname.toLowerCase();
          const isAllowed = cfg.domainAllowlist.some((domain) => {
            const normalized = domain.toLowerCase();
            if (normalized.startsWith("*.")) {
              const suffix = normalized.slice(2);
              return hostname === suffix || hostname.endsWith(`.${suffix}`);
            }
            return hostname === normalized;
          });
          if (!isAllowed) {
            throw new BlockedNavigationError(
              `Domain not in allowlist: ${parsed.hostname}`,
              "domain-allowlist",
            );
          }
        } catch (error) {
          if (error instanceof BlockedNavigationError) {
            throw error;
          }
          // URL parse error already caught by isBlockedUrl
        }
      }

      // 3. Check domain blocklist
      if (cfg.domainBlocklist && cfg.domainBlocklist.length > 0) {
        try {
          const parsed = new URL(url);
          const hostname = parsed.hostname.toLowerCase();
          const isBlocked = cfg.domainBlocklist.some((domain) => {
            const normalized = domain.toLowerCase();
            if (normalized.startsWith("*.")) {
              const suffix = normalized.slice(2);
              return hostname === suffix || hostname.endsWith(`.${suffix}`);
            }
            return hostname === normalized;
          });
          if (isBlocked) {
            throw new BlockedNavigationError(
              `Domain is blocklisted: ${parsed.hostname}`,
              "domain-blocklist",
            );
          }
        } catch (error) {
          if (error instanceof BlockedNavigationError) {
            throw error;
          }
        }
      }

      // 4. Check rate limits
      const record = getNavigationRecord(navigationRecords, sessionId);
      record.timestamps = cleanupTimestamps(record.timestamps, 60 * 60 * 1000);

      const now = Date.now();
      const minuteAgo = now - 60 * 1000;
      const navigationsThisMinute = record.timestamps.filter((ts) => ts > minuteAgo).length;
      const navigationsThisHour = record.timestamps.length;

      if (navigationsThisMinute >= cfg.maxNavigationsPerMinute) {
        throw new NavigationRateLimitError(
          `Navigation rate limit exceeded: ${navigationsThisMinute}/${cfg.maxNavigationsPerMinute} per minute`,
          60 * 1000,
        );
      }

      if (navigationsThisHour >= cfg.maxNavigationsPerHour) {
        throw new NavigationRateLimitError(
          `Navigation rate limit exceeded: ${navigationsThisHour}/${cfg.maxNavigationsPerHour} per hour`,
          60 * 60 * 1000,
        );
      }

      return {
        allowed: true,
        reason: "Navigation allowed",
        navigationsThisMinute,
        navigationsThisHour,
      };
    },

    /**
     * Record a successful navigation
     */
    recordNavigation(sessionId: string): void {
      const record = getNavigationRecord(navigationRecords, sessionId);
      record.timestamps.push(Date.now());
    },

    /**
     * Validate a redirect chain length
     */
    checkRedirectChain(chainLength: number): void {
      if (chainLength > cfg.maxRedirectChainLength) {
        throw new BlockedNavigationError(
          `Redirect chain too long: ${chainLength} > ${cfg.maxRedirectChainLength}`,
          "redirect-chain",
        );
      }
    },

    /**
     * Reset navigation records for a session
     */
    resetSession(sessionId: string): void {
      navigationRecords.delete(sessionId);
    },

    /**
     * Get current configuration
     */
    get config(): NavigationPolicyConfig {
      return { ...cfg };
    },
  };
}
