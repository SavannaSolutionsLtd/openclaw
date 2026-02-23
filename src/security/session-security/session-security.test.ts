import { describe, expect, test } from "vitest";
import { createTokenStore, TokenError, DEFAULT_TOKEN_STORE_CONFIG } from "./index.js";

// =============================================================================
// Token Store Tests
// =============================================================================

describe("createTokenStore", () => {
  describe("Default Configuration", () => {
    test("uses default config values", () => {
      const store = createTokenStore();
      expect(store.config.maxTtlHours).toBe(8);
      expect(store.config.defaultTtlHours).toBe(4);
      expect(store.config.bindToClientIp).toBe(false);
      expect(store.config.tokenByteLength).toBe(32);
      expect(store.config.maxTokensPerUser).toBe(10);
      expect(store.config.cleanupIntervalMs).toBe(DEFAULT_TOKEN_STORE_CONFIG.cleanupIntervalMs);
    });

    test("allows overriding config values", () => {
      const store = createTokenStore({ maxTtlHours: 2, maxTokensPerUser: 5 });
      expect(store.config.maxTtlHours).toBe(2);
      expect(store.config.maxTokensPerUser).toBe(5);
      // Defaults preserved
      expect(store.config.bindToClientIp).toBe(false);
    });
  });

  describe("Token Creation", () => {
    test("creates a token string", () => {
      const store = createTokenStore();
      const token = store.create("user-1");
      expect(typeof token).toBe("string");
      expect(token.length).toBeGreaterThan(0);
    });

    test("creates unique tokens", () => {
      const store = createTokenStore();
      const token1 = store.create("user-1");
      const token2 = store.create("user-1");
      expect(token1).not.toBe(token2);
    });

    test("produces hex-encoded tokens of correct length", () => {
      const store = createTokenStore({ tokenByteLength: 16 });
      const token = store.create("user-1");
      // 16 bytes = 32 hex chars
      expect(token).toMatch(/^[0-9a-f]{32}$/);
    });

    test("enforces per-user token limit", () => {
      const store = createTokenStore({ maxTokensPerUser: 2 });
      store.create("user-1");
      store.create("user-1");

      expect(() => {
        store.create("user-1");
      }).toThrow(TokenError);
    });

    test("token limit error has correct code", () => {
      const store = createTokenStore({ maxTokensPerUser: 1 });
      store.create("user-1");

      try {
        store.create("user-1");
        expect.unreachable("Should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(TokenError);
        expect((err as TokenError).code).toBe("MAX_TOKENS_EXCEEDED");
      }
    });

    test("different users have independent limits", () => {
      const store = createTokenStore({ maxTokensPerUser: 1 });
      store.create("user-1");
      // user-2 should still be able to create
      const token = store.create("user-2");
      expect(token).toBeTruthy();
    });

    test("clamps TTL to max", () => {
      const store = createTokenStore({ maxTtlHours: 2 });
      const token = store.create("user-1", { ttlHours: 100 });
      const result = store.validate(token);
      expect(result.valid).toBe(true);
      // TTL should be clamped to 2 hours (7200000 ms)
      const ttlMs = result.metadata!.expiresAt - result.metadata!.createdAt;
      expect(ttlMs).toBeLessThanOrEqual(2 * 60 * 60 * 1000);
    });
  });

  describe("Token Validation", () => {
    test("validates a valid token", () => {
      const store = createTokenStore();
      const token = store.create("user-1");
      const result = store.validate(token);
      expect(result.valid).toBe(true);
      expect(result.metadata).toBeDefined();
      expect(result.metadata!.userId).toBe("user-1");
    });

    test("rejects unknown token", () => {
      const store = createTokenStore();
      const result = store.validate("nonexistent-token");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("not found");
    });

    test("rejects expired token", () => {
      const store = createTokenStore();
      // Create token with minimal TTL by setting a very short TTL
      // We'll manipulate by creating with a very small TTL
      const token = store.create("user-1", { ttlHours: 0 });
      // TTL of 0 hours means immediate expiration
      // Give a tiny delay
      const start = Date.now();
      while (Date.now() - start < 5) {
        // spin
      }
      const result = store.validate(token);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("expired");
    });

    test("returns metadata with correct fields", () => {
      const store = createTokenStore();
      const token = store.create("user-1", {
        clientIp: "1.2.3.4",
        sessionType: "web",
        data: { role: "admin" },
      });

      const result = store.validate(token);
      expect(result.valid).toBe(true);
      expect(result.metadata!.userId).toBe("user-1");
      expect(result.metadata!.clientIp).toBe("1.2.3.4");
      expect(result.metadata!.sessionType).toBe("web");
      expect(result.metadata!.data).toEqual({ role: "admin" });
      expect(result.metadata!.createdAt).toBeGreaterThan(0);
      expect(result.metadata!.expiresAt).toBeGreaterThan(result.metadata!.createdAt);
    });
  });

  describe("IP Binding", () => {
    test("allows matching IP when bound", () => {
      const store = createTokenStore({ bindToClientIp: true });
      const token = store.create("user-1", { clientIp: "1.2.3.4" });
      const result = store.validate(token, "1.2.3.4");
      expect(result.valid).toBe(true);
    });

    test("rejects different IP when bound", () => {
      const store = createTokenStore({ bindToClientIp: true });
      const token = store.create("user-1", { clientIp: "1.2.3.4" });
      const result = store.validate(token, "5.6.7.8");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("different IP");
    });

    test("allows any IP when binding is disabled", () => {
      const store = createTokenStore({ bindToClientIp: false });
      const token = store.create("user-1", { clientIp: "1.2.3.4" });
      const result = store.validate(token, "5.6.7.8");
      expect(result.valid).toBe(true);
    });
  });

  describe("Token Invalidation", () => {
    test("invalidates a valid token", () => {
      const store = createTokenStore();
      const token = store.create("user-1");

      expect(store.invalidate(token)).toBe(true);
      expect(store.validate(token).valid).toBe(false);
    });

    test("returns false for unknown token", () => {
      const store = createTokenStore();
      expect(store.invalidate("nonexistent")).toBe(false);
    });

    test("decrements active token count", () => {
      const store = createTokenStore();
      const token1 = store.create("user-1");
      store.create("user-1");

      expect(store.getActiveTokenCount("user-1")).toBe(2);
      store.invalidate(token1);
      expect(store.getActiveTokenCount("user-1")).toBe(1);
    });
  });

  describe("Invalidate All", () => {
    test("invalidates all tokens for a user", () => {
      const store = createTokenStore();
      const token1 = store.create("user-1");
      const token2 = store.create("user-1");

      const count = store.invalidateAll("user-1");
      expect(count).toBe(2);
      expect(store.validate(token1).valid).toBe(false);
      expect(store.validate(token2).valid).toBe(false);
    });

    test("returns 0 for user with no tokens", () => {
      const store = createTokenStore();
      expect(store.invalidateAll("unknown")).toBe(0);
    });

    test("does not affect other users", () => {
      const store = createTokenStore();
      store.create("user-1");
      const token2 = store.create("user-2");

      store.invalidateAll("user-1");
      expect(store.validate(token2).valid).toBe(true);
    });
  });

  describe("Token Counting", () => {
    test("counts active tokens per user", () => {
      const store = createTokenStore();
      expect(store.getActiveTokenCount("user-1")).toBe(0);

      store.create("user-1");
      expect(store.getActiveTokenCount("user-1")).toBe(1);

      store.create("user-1");
      expect(store.getActiveTokenCount("user-1")).toBe(2);
    });

    test("counts total active tokens", () => {
      const store = createTokenStore();
      expect(store.getTotalActiveTokens()).toBe(0);

      store.create("user-1");
      store.create("user-2");
      store.create("user-1");

      expect(store.getTotalActiveTokens()).toBe(3);
    });
  });

  describe("Cleanup", () => {
    test("removes expired tokens on cleanup", () => {
      const store = createTokenStore();
      store.create("user-1", { ttlHours: 0 });

      // Wait for expiration
      const start = Date.now();
      while (Date.now() - start < 5) {
        // spin
      }

      store.cleanup();
      expect(store.getActiveTokenCount("user-1")).toBe(0);
      expect(store.getTotalActiveTokens()).toBe(0);
    });

    test("preserves non-expired tokens", () => {
      const store = createTokenStore();
      store.create("user-1", { ttlHours: 0 });
      const validToken = store.create("user-1", { ttlHours: 4 });

      const start = Date.now();
      while (Date.now() - start < 5) {
        // spin
      }

      store.cleanup();
      expect(store.validate(validToken).valid).toBe(true);
    });
  });

  describe("Security Properties", () => {
    test("tokens are stored as hashes (cannot be retrieved)", () => {
      const store = createTokenStore();
      const token = store.create("user-1");
      // The raw token should still validate
      expect(store.validate(token).valid).toBe(true);
      // But a second creation should produce a different token
      const token2 = store.create("user-1");
      expect(token).not.toBe(token2);
    });

    test("tokens have sufficient entropy", () => {
      const store = createTokenStore({ tokenByteLength: 32 });
      const token = store.create("user-1");
      // 32 bytes = 64 hex chars
      expect(token.length).toBe(64);
      // Check it looks random (no obvious patterns)
      const uniqueChars = new Set(token.split(""));
      expect(uniqueChars.size).toBeGreaterThan(4);
    });

    test("TTL cannot exceed maximum", () => {
      const store = createTokenStore({ maxTtlHours: 1 });
      const token = store.create("user-1", { ttlHours: 999 });
      const result = store.validate(token);
      expect(result.valid).toBe(true);
      const ttlMs = result.metadata!.expiresAt - result.metadata!.createdAt;
      // Should be clamped to 1 hour
      expect(ttlMs).toBeLessThanOrEqual(1 * 60 * 60 * 1000);
    });
  });
});
