import { describe, expect, test } from "vitest";
import {
  isBlockedUrl,
  hasHomographCharacters,
  BLOCKED_PROTOCOLS,
  ALLOWED_PROTOCOLS,
  getAllBlockedPatterns,
  createNavigationPolicy,
  NavigationRateLimitError,
  BlockedNavigationError,
} from "./index.js";

// =============================================================================
// URL Blocklist Tests
// =============================================================================

describe("isBlockedUrl", () => {
  describe("Cloud Metadata Endpoints", () => {
    test("blocks AWS metadata endpoint", () => {
      const result = isBlockedUrl("http://169.254.169.254/latest/meta-data/");
      expect(result.blocked).toBe(true);
      expect(result.category).toBe("cloud-metadata");
    });

    test("blocks AWS metadata with HTTPS", () => {
      const result = isBlockedUrl("https://169.254.169.254/latest/meta-data/");
      expect(result.blocked).toBe(true);
    });

    test("blocks GCP metadata server", () => {
      const result = isBlockedUrl("http://metadata.google.internal/computeMetadata/v1/");
      expect(result.blocked).toBe(true);
      expect(result.category).toBe("cloud-metadata");
    });

    test("blocks Alibaba Cloud metadata", () => {
      const result = isBlockedUrl("http://100.100.100.200/latest/meta-data/");
      expect(result.blocked).toBe(true);
      expect(result.category).toBe("cloud-metadata");
    });

    test("blocks Kubernetes API server", () => {
      const result = isBlockedUrl("https://kubernetes.default/api/v1/");
      expect(result.blocked).toBe(true);
      expect(result.category).toBe("cloud-metadata");
    });
  });

  describe("Private Network Addresses", () => {
    test("blocks 10.x.x.x addresses", () => {
      const result = isBlockedUrl("http://10.0.0.1/admin");
      expect(result.blocked).toBe(true);
      expect(result.category).toBe("private-network");
    });

    test("blocks 172.16-31.x.x addresses", () => {
      expect(isBlockedUrl("http://172.16.0.1/").blocked).toBe(true);
      expect(isBlockedUrl("http://172.24.0.1/").blocked).toBe(true);
      expect(isBlockedUrl("http://172.31.0.1/").blocked).toBe(true);
    });

    test("allows 172.15.x.x (outside private range)", () => {
      const result = isBlockedUrl("http://172.15.0.1/");
      // 172.15 is NOT in RFC-1918 range, should not be blocked by private-network pattern
      expect(result.blocked).toBe(false);
    });

    test("allows 172.32.x.x (outside private range)", () => {
      const result = isBlockedUrl("http://172.32.0.1/");
      expect(result.blocked).toBe(false);
    });

    test("blocks 192.168.x.x addresses", () => {
      const result = isBlockedUrl("http://192.168.1.1/");
      expect(result.blocked).toBe(true);
      expect(result.category).toBe("private-network");
    });

    test("blocks localhost", () => {
      expect(isBlockedUrl("http://localhost/").blocked).toBe(true);
      expect(isBlockedUrl("http://localhost:3000/").blocked).toBe(true);
      expect(isBlockedUrl("http://localhost:8080/api").blocked).toBe(true);
    });

    test("blocks 127.x.x.x loopback", () => {
      expect(isBlockedUrl("http://127.0.0.1/").blocked).toBe(true);
      expect(isBlockedUrl("http://127.0.0.1:8080/").blocked).toBe(true);
      expect(isBlockedUrl("http://127.1.2.3/").blocked).toBe(true);
    });

    test("blocks IPv6 loopback", () => {
      const result = isBlockedUrl("http://[::1]/");
      expect(result.blocked).toBe(true);
    });

    test("blocks 0.0.0.0", () => {
      const result = isBlockedUrl("http://0.0.0.0/");
      expect(result.blocked).toBe(true);
    });

    test("blocks link-local IPv4", () => {
      const result = isBlockedUrl("http://169.254.1.1/");
      expect(result.blocked).toBe(true);
    });

    test("blocks link-local IPv6", () => {
      const result = isBlockedUrl("http://[fe80::1]/");
      expect(result.blocked).toBe(true);
    });
  });

  describe("Protocol Checks", () => {
    test("blocks javascript: URLs", () => {
      const result = isBlockedUrl("javascript:alert(1)");
      expect(result.blocked).toBe(true);
      expect(result.category).toBe("protocol");
    });

    test("blocks data: URLs", () => {
      const result = isBlockedUrl("data:text/html,<h1>XSS</h1>");
      expect(result.blocked).toBe(true);
      expect(result.category).toBe("protocol");
    });

    test("blocks file: URLs", () => {
      const result = isBlockedUrl("file:///etc/passwd");
      expect(result.blocked).toBe(true);
      expect(result.category).toBe("protocol");
    });

    test("blocks ftp: URLs", () => {
      const result = isBlockedUrl("ftp://evil.com/malware");
      expect(result.blocked).toBe(true);
      expect(result.category).toBe("protocol");
    });

    test("allows http: URLs to public sites", () => {
      const result = isBlockedUrl("http://example.com/");
      expect(result.blocked).toBe(false);
    });

    test("allows https: URLs to public sites", () => {
      const result = isBlockedUrl("https://google.com/search?q=test");
      expect(result.blocked).toBe(false);
    });

    test("allows about:blank", () => {
      const result = isBlockedUrl("about:blank");
      expect(result.blocked).toBe(false);
    });

    test("blocks empty URL", () => {
      const result = isBlockedUrl("");
      expect(result.blocked).toBe(true);
    });

    test("blocks invalid URL", () => {
      const result = isBlockedUrl("not-a-url");
      expect(result.blocked).toBe(true);
    });
  });

  describe("Safe URLs", () => {
    test("allows normal HTTPS navigation", () => {
      expect(isBlockedUrl("https://google.com").blocked).toBe(false);
      expect(isBlockedUrl("https://github.com/user/repo").blocked).toBe(false);
      expect(isBlockedUrl("https://docs.python.org/3/").blocked).toBe(false);
    });

    test("allows URLs with ports on public hosts", () => {
      expect(isBlockedUrl("https://example.com:8443/api").blocked).toBe(false);
    });

    test("allows URLs with query parameters", () => {
      expect(isBlockedUrl("https://example.com/search?q=test&page=1").blocked).toBe(false);
    });

    test("allows URLs with fragments", () => {
      expect(isBlockedUrl("https://example.com/docs#section-1").blocked).toBe(false);
    });
  });
});

// =============================================================================
// IDN Homograph Detection Tests
// =============================================================================

describe("hasHomographCharacters", () => {
  test("detects Cyrillic 'a' (U+0430) in hostname", () => {
    // \u0430 is Cyrillic а which looks like Latin a
    expect(hasHomographCharacters("g\u043e\u043egle.com")).toBe(true);
  });

  test("detects Cyrillic 'o' (U+043E) in hostname", () => {
    expect(hasHomographCharacters("g\u043eogle.com")).toBe(true);
  });

  test("detects Cyrillic 'e' (U+0435) in hostname", () => {
    expect(hasHomographCharacters("\u0435xample.com")).toBe(true);
  });

  test("detects Cyrillic 'p' (U+0440) in hostname", () => {
    expect(hasHomographCharacters("\u0440aypal.com")).toBe(true);
  });

  test("detects Greek 'o' (U+03BF) in hostname", () => {
    expect(hasHomographCharacters("g\u03bfogle.com")).toBe(true);
  });

  test("returns false for pure ASCII domains", () => {
    expect(hasHomographCharacters("google.com")).toBe(false);
    expect(hasHomographCharacters("example.org")).toBe(false);
    expect(hasHomographCharacters("sub.domain.co.uk")).toBe(false);
  });

  test("returns false for legitimate non-ASCII domains", () => {
    // Chinese/Japanese characters that don't have confusables
    expect(hasHomographCharacters("xn--example")).toBe(false);
  });

  test("isBlockedUrl catches homograph attacks", () => {
    // Cyrillic 'о' instead of Latin 'o'
    const result = isBlockedUrl("https://g\u043e\u043egle.com");
    expect(result.blocked).toBe(true);
    expect(result.category).toBe("homograph");
  });
});

// =============================================================================
// Blocked Patterns Enumeration
// =============================================================================

describe("getAllBlockedPatterns", () => {
  test("returns non-empty pattern list", () => {
    const patterns = getAllBlockedPatterns();
    expect(patterns.length).toBeGreaterThan(0);
  });

  test("each pattern has required fields", () => {
    const patterns = getAllBlockedPatterns();
    for (const p of patterns) {
      expect(p.pattern).toBeInstanceOf(RegExp);
      expect(p.description).toBeTruthy();
      expect(p.category).toBeTruthy();
    }
  });
});

// =============================================================================
// Constants Tests
// =============================================================================

describe("Protocol Constants", () => {
  test("BLOCKED_PROTOCOLS contains dangerous schemes", () => {
    expect(BLOCKED_PROTOCOLS.has("javascript:")).toBe(true);
    expect(BLOCKED_PROTOCOLS.has("data:")).toBe(true);
    expect(BLOCKED_PROTOCOLS.has("file:")).toBe(true);
  });

  test("ALLOWED_PROTOCOLS contains safe schemes", () => {
    expect(ALLOWED_PROTOCOLS.has("http:")).toBe(true);
    expect(ALLOWED_PROTOCOLS.has("https:")).toBe(true);
    expect(ALLOWED_PROTOCOLS.has("about:")).toBe(true);
  });
});

// =============================================================================
// Navigation Policy Tests
// =============================================================================

describe("createNavigationPolicy", () => {
  let sessionCounter = 0;
  function uniqueSessionId(): string {
    return `test-nav-${Date.now()}-${sessionCounter++}`;
  }

  test("allows navigation to public URLs", () => {
    const policy = createNavigationPolicy();
    const sessionId = uniqueSessionId();
    const result = policy.checkNavigation(sessionId, "https://example.com");
    expect(result.allowed).toBe(true);
  });

  test("blocks navigation to private IPs", () => {
    const policy = createNavigationPolicy();
    const sessionId = uniqueSessionId();
    expect(() => {
      policy.checkNavigation(sessionId, "http://10.0.0.1/admin");
    }).toThrow(BlockedNavigationError);
  });

  test("blocks navigation to cloud metadata", () => {
    const policy = createNavigationPolicy();
    const sessionId = uniqueSessionId();
    expect(() => {
      policy.checkNavigation(sessionId, "http://169.254.169.254/");
    }).toThrow(BlockedNavigationError);
  });

  test("blocks blocked protocols", () => {
    const policy = createNavigationPolicy();
    const sessionId = uniqueSessionId();
    expect(() => {
      policy.checkNavigation(sessionId, "javascript:alert(1)");
    }).toThrow(BlockedNavigationError);
  });

  describe("Rate Limiting", () => {
    test("enforces per-minute navigation limit", () => {
      const policy = createNavigationPolicy({
        maxNavigationsPerMinute: 3,
      });
      const sessionId = uniqueSessionId();

      // Make 3 navigations
      for (let i = 0; i < 3; i++) {
        policy.checkNavigation(sessionId, "https://example.com");
        policy.recordNavigation(sessionId);
      }

      // 4th should be rate limited
      expect(() => {
        policy.checkNavigation(sessionId, "https://example.com");
      }).toThrow(NavigationRateLimitError);
    });

    test("tracks sessions independently", () => {
      const policy = createNavigationPolicy({
        maxNavigationsPerMinute: 2,
      });
      const session1 = uniqueSessionId();
      const session2 = uniqueSessionId();

      // Max out session1
      policy.checkNavigation(session1, "https://example.com");
      policy.recordNavigation(session1);
      policy.checkNavigation(session1, "https://example.com");
      policy.recordNavigation(session1);

      // session2 should still work
      const result = policy.checkNavigation(session2, "https://example.com");
      expect(result.allowed).toBe(true);
    });

    test("resetSession clears rate limit data", () => {
      const policy = createNavigationPolicy({
        maxNavigationsPerMinute: 2,
      });
      const sessionId = uniqueSessionId();

      // Max out
      policy.checkNavigation(sessionId, "https://example.com");
      policy.recordNavigation(sessionId);
      policy.checkNavigation(sessionId, "https://example.com");
      policy.recordNavigation(sessionId);

      // Reset
      policy.resetSession(sessionId);

      // Should work again
      const result = policy.checkNavigation(sessionId, "https://example.com");
      expect(result.allowed).toBe(true);
    });
  });

  describe("Domain Allowlist", () => {
    test("allows domains in allowlist", () => {
      const policy = createNavigationPolicy({
        domainAllowlist: ["example.com", "*.github.com"],
      });
      const sessionId = uniqueSessionId();

      expect(policy.checkNavigation(sessionId, "https://example.com").allowed).toBe(true);
      expect(policy.checkNavigation(sessionId, "https://api.github.com").allowed).toBe(true);
    });

    test("blocks domains not in allowlist", () => {
      const policy = createNavigationPolicy({
        domainAllowlist: ["example.com"],
      });
      const sessionId = uniqueSessionId();

      expect(() => {
        policy.checkNavigation(sessionId, "https://evil.com");
      }).toThrow(BlockedNavigationError);
    });

    test("wildcard allowlist matches subdomains", () => {
      const policy = createNavigationPolicy({
        domainAllowlist: ["*.example.com"],
      });
      const sessionId = uniqueSessionId();

      expect(policy.checkNavigation(sessionId, "https://sub.example.com").allowed).toBe(true);
      expect(policy.checkNavigation(sessionId, "https://deep.sub.example.com").allowed).toBe(true);
    });
  });

  describe("Domain Blocklist", () => {
    test("blocks domains in blocklist", () => {
      const policy = createNavigationPolicy({
        domainBlocklist: ["evil.com", "*.malware.org"],
      });
      const sessionId = uniqueSessionId();

      expect(() => {
        policy.checkNavigation(sessionId, "https://evil.com");
      }).toThrow(BlockedNavigationError);

      expect(() => {
        policy.checkNavigation(sessionId, "https://sub.malware.org");
      }).toThrow(BlockedNavigationError);
    });

    test("allows domains not in blocklist", () => {
      const policy = createNavigationPolicy({
        domainBlocklist: ["evil.com"],
      });
      const sessionId = uniqueSessionId();

      expect(policy.checkNavigation(sessionId, "https://example.com").allowed).toBe(true);
    });
  });

  describe("Redirect Chain", () => {
    test("allows short redirect chains", () => {
      const policy = createNavigationPolicy();
      expect(() => policy.checkRedirectChain(3)).not.toThrow();
    });

    test("blocks excessively long redirect chains", () => {
      const policy = createNavigationPolicy({ maxRedirectChainLength: 5 });
      expect(() => policy.checkRedirectChain(6)).toThrow(BlockedNavigationError);
    });

    test("uses default max redirect chain length", () => {
      const policy = createNavigationPolicy();
      expect(() => policy.checkRedirectChain(10)).not.toThrow();
      expect(() => policy.checkRedirectChain(11)).toThrow(BlockedNavigationError);
    });
  });

  describe("Configuration", () => {
    test("returns config", () => {
      const policy = createNavigationPolicy({
        maxNavigationsPerMinute: 10,
      });
      expect(policy.config.maxNavigationsPerMinute).toBe(10);
    });

    test("uses defaults for unspecified options", () => {
      const policy = createNavigationPolicy();
      expect(policy.config.maxNavigationsPerMinute).toBe(30);
      expect(policy.config.maxNavigationsPerHour).toBe(300);
      expect(policy.config.maxRedirectChainLength).toBe(10);
    });
  });
});
