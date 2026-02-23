/**
 * Session Token Store
 *
 * Secure token management with TTL enforcement, IP binding,
 * and invalidation support.
 *
 * @module security/session-security/token-store
 */

import { randomBytes, createHash } from "node:crypto";

/**
 * Token metadata
 */
export interface TokenMetadata {
  /** User identifier */
  userId: string;
  /** Token creation time (epoch ms) */
  createdAt: number;
  /** Token expiration time (epoch ms) */
  expiresAt: number;
  /** Client IP address (optional binding) */
  clientIp?: string;
  /** Session type */
  sessionType?: string;
  /** Custom metadata */
  data?: Record<string, unknown>;
}

/**
 * Token validation result
 */
export interface TokenValidationResult {
  /** Whether the token is valid */
  valid: boolean;
  /** Token metadata if valid */
  metadata?: TokenMetadata;
  /** Reason for invalidity */
  reason?: string;
}

/**
 * Token store configuration
 */
export interface TokenStoreConfig {
  /** Maximum TTL in hours */
  maxTtlHours: number;
  /** Default TTL in hours */
  defaultTtlHours: number;
  /** Bind tokens to client IP */
  bindToClientIp: boolean;
  /** Token byte length (before hex encoding) */
  tokenByteLength: number;
  /** Maximum tokens per user */
  maxTokensPerUser: number;
  /** Cleanup interval in milliseconds */
  cleanupIntervalMs: number;
}

/**
 * Default token store configuration
 */
export const DEFAULT_TOKEN_STORE_CONFIG: TokenStoreConfig = {
  maxTtlHours: 8,
  defaultTtlHours: 4,
  bindToClientIp: false,
  tokenByteLength: 32,
  maxTokensPerUser: 10,
  cleanupIntervalMs: 5 * 60 * 1000, // 5 minutes
};

/**
 * Token error
 */
export class TokenError extends Error {
  readonly code: string;

  constructor(message: string, code: string) {
    super(message);
    this.name = "TokenError";
    this.code = code;
  }
}

/**
 * Hash a token for storage (never store raw tokens)
 */
function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/**
 * Create a token store
 */
export function createTokenStore(config: Partial<TokenStoreConfig> = {}) {
  const cfg = { ...DEFAULT_TOKEN_STORE_CONFIG, ...config };
  const tokens = new Map<string, TokenMetadata>();
  const userTokens = new Map<string, Set<string>>();

  function cleanup(): void {
    const now = Date.now();
    for (const [hash, metadata] of tokens) {
      if (metadata.expiresAt <= now) {
        tokens.delete(hash);
        const userSet = userTokens.get(metadata.userId);
        if (userSet) {
          userSet.delete(hash);
          if (userSet.size === 0) {
            userTokens.delete(metadata.userId);
          }
        }
      }
    }
  }

  return {
    /**
     * Create a new session token
     *
     * @returns The raw token string (only returned once)
     */
    create(
      userId: string,
      options: {
        ttlHours?: number;
        clientIp?: string;
        sessionType?: string;
        data?: Record<string, unknown>;
      } = {},
    ): string {
      cleanup();

      // Enforce per-user token limit
      const userSet = userTokens.get(userId) ?? new Set();
      if (userSet.size >= cfg.maxTokensPerUser) {
        throw new TokenError(
          `Maximum tokens per user exceeded: ${userSet.size}/${cfg.maxTokensPerUser}`,
          "MAX_TOKENS_EXCEEDED",
        );
      }

      // Enforce TTL limits
      const ttlHours = Math.min(options.ttlHours ?? cfg.defaultTtlHours, cfg.maxTtlHours);
      const now = Date.now();

      // Generate cryptographically random token
      const rawToken = randomBytes(cfg.tokenByteLength).toString("hex");
      const tokenHash = hashToken(rawToken);

      const metadata: TokenMetadata = {
        userId,
        createdAt: now,
        expiresAt: now + ttlHours * 60 * 60 * 1000,
        clientIp: options.clientIp,
        sessionType: options.sessionType,
        data: options.data,
      };

      tokens.set(tokenHash, metadata);
      userSet.add(tokenHash);
      userTokens.set(userId, userSet);

      return rawToken;
    },

    /**
     * Validate a token
     */
    validate(token: string, clientIp?: string): TokenValidationResult {
      const tokenHash = hashToken(token);
      const metadata = tokens.get(tokenHash);

      if (!metadata) {
        return { valid: false, reason: "Token not found or already invalidated" };
      }

      const now = Date.now();
      if (metadata.expiresAt <= now) {
        // Clean up expired token
        tokens.delete(tokenHash);
        const userSet = userTokens.get(metadata.userId);
        if (userSet) {
          userSet.delete(tokenHash);
        }
        return { valid: false, reason: "Token expired" };
      }

      if (cfg.bindToClientIp && metadata.clientIp && clientIp && metadata.clientIp !== clientIp) {
        return { valid: false, reason: "Token bound to different IP" };
      }

      return { valid: true, metadata };
    },

    /**
     * Invalidate a specific token
     */
    invalidate(token: string): boolean {
      const tokenHash = hashToken(token);
      const metadata = tokens.get(tokenHash);
      if (!metadata) {
        return false;
      }

      tokens.delete(tokenHash);
      const userSet = userTokens.get(metadata.userId);
      if (userSet) {
        userSet.delete(tokenHash);
        if (userSet.size === 0) {
          userTokens.delete(metadata.userId);
        }
      }
      return true;
    },

    /**
     * Invalidate all tokens for a user
     */
    invalidateAll(userId: string): number {
      const userSet = userTokens.get(userId);
      if (!userSet) {
        return 0;
      }

      let count = 0;
      for (const hash of userSet) {
        tokens.delete(hash);
        count++;
      }
      userTokens.delete(userId);
      return count;
    },

    /**
     * Cleanup expired tokens
     */
    cleanup,

    /**
     * Get active token count for a user
     */
    getActiveTokenCount(userId: string): number {
      cleanup();
      return userTokens.get(userId)?.size ?? 0;
    },

    /**
     * Get total active token count
     */
    getTotalActiveTokens(): number {
      cleanup();
      return tokens.size;
    },

    /**
     * Get configuration
     */
    get config(): TokenStoreConfig {
      return { ...cfg };
    },
  };
}
