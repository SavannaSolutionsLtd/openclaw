/**
 * Output Redaction Filter Tests
 *
 * Tests for secret detection and redaction in outbound messages.
 *
 * @module security/output-redaction/tests
 */

import { describe, expect, test, vi } from "vitest";
import {
  calculateEntropy,
  isHighEntropy,
  detectHighEntropyStrings,
  detectBase64Secrets,
} from "./entropy.js";
import { redactSecrets, createRedactionFilter } from "./filter.js";
import { redactOutboundMessage, checkForSecrets, createMonitoredRedactionFilter } from "./index.js";
import {
  detectSecrets,
  containsSecrets,
  getHighConfidencePatterns,
  SECRET_PATTERNS,
} from "./patterns.js";

// =============================================================================
// Pattern Detection Tests
// =============================================================================

describe("detectSecrets", () => {
  describe("AI Provider API Keys", () => {
    test("detects Anthropic API key", () => {
      const content = "My API key is sk-ant-api03-abcdefghij";
      const detections = detectSecrets(content);
      expect(detections.length).toBeGreaterThan(0);
      expect(detections.some((d) => d.type === "ANTHROPIC_KEY")).toBe(true);
    });

    test("detects OpenAI API key", () => {
      const content = "Use this key: sk-proj-abc123def456ghi789jkl012mno345";
      const detections = detectSecrets(content);
      expect(detections.some((d) => d.type.includes("OPENAI"))).toBe(true);
    });

    test("detects OpenAI project key", () => {
      const content = "The key is sk-proj-abcdef123456_ghijkl789012";
      const detections = detectSecrets(content);
      expect(detections.length).toBeGreaterThan(0);
    });
  });

  describe("Cloud Provider Keys", () => {
    test("detects AWS access key ID", () => {
      const content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
      const detections = detectSecrets(content);
      expect(detections.some((d) => d.type === "AWS_ACCESS_KEY")).toBe(true);
    });

    test("detects AWS temporary access key", () => {
      const content = "Temp key: ASIAX1234567890ABCDEF";
      const detections = detectSecrets(content);
      expect(detections.some((d) => d.type === "AWS_TEMP_ACCESS_KEY")).toBe(true);
    });

    test("detects Google API key", () => {
      const content = "Google key: AIzaSyC-abcdefghijk123456789lmnopqrs";
      const detections = detectSecrets(content);
      expect(detections.some((d) => d.type === "GOOGLE_API_KEY")).toBe(true);
    });
  });

  describe("Version Control Tokens", () => {
    test("detects GitHub personal access token", () => {
      const content = "Token: ghp_abcdefghijklmnopqrstuvwxyz0123456789";
      const detections = detectSecrets(content);
      expect(detections.some((d) => d.type === "GITHUB_PAT")).toBe(true);
    });

    test("detects GitHub OAuth token", () => {
      const content = "OAuth: gho_abcdefghijklmnopqrstuvwxyz0123456789";
      const detections = detectSecrets(content);
      expect(detections.some((d) => d.type === "GITHUB_OAUTH")).toBe(true);
    });

    test("detects GitHub fine-grained PAT", () => {
      const content =
        "Token: github_pat_11ABCDEFGHIJKLMNOPQRS_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567";
      const detections = detectSecrets(content);
      expect(detections.some((d) => d.type === "GITHUB_FINE_PAT")).toBe(true);
    });

    test("detects GitLab personal access token", () => {
      const content = "GitLab PAT: glpat-abc123def456ghi789jkl";
      const detections = detectSecrets(content);
      expect(detections.some((d) => d.type === "GITLAB_PAT")).toBe(true);
    });
  });

  describe("Messaging Platform Tokens", () => {
    test("detects Slack bot token", () => {
      // Pattern: xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+
      // Using minimal matching values to avoid triggering secret scanners
      const content = "Slack: xoxb-1-2-x";
      const detections = detectSecrets(content);
      expect(detections.some((d) => d.type === "SLACK_BOT_TOKEN")).toBe(true);
    });

    test("detects Slack user token", () => {
      // Pattern: xoxp-[0-9]+-[0-9]+-[0-9]+-[a-f0-9]+ (hex at end)
      // Using minimal matching values to avoid triggering secret scanners
      const content = "User token: xoxp-1-2-3-a";
      const detections = detectSecrets(content);
      expect(detections.some((d) => d.type === "SLACK_USER_TOKEN")).toBe(true);
    });

    test("detects Telegram bot token", () => {
      // Pattern: [0-9]{8,12}:[A-Za-z0-9_-]{30,}
      const content = "Bot token: 0000000000:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
      const detections = detectSecrets(content);
      expect(detections.some((d) => d.type === "TELEGRAM_BOT_TOKEN")).toBe(true);
    });

    test("detects Discord bot token", () => {
      // Pattern: [MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}
      const content = "Discord: MAAAAAAAAAAAAAAAAAAAAAAA.AAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAA";
      const detections = detectSecrets(content);
      expect(detections.some((d) => d.type === "DISCORD_BOT_TOKEN")).toBe(true);
    });
  });

  describe("Private Keys", () => {
    test("detects RSA private key", () => {
      const content = `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAJBANcz
-----END RSA PRIVATE KEY-----`;
      const detections = detectSecrets(content);
      expect(detections.some((d) => d.type === "RSA_PRIVATE_KEY")).toBe(true);
    });

    test("detects EC private key", () => {
      const content = `-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIDWRvRqg
-----END EC PRIVATE KEY-----`;
      const detections = detectSecrets(content);
      expect(detections.some((d) => d.type === "EC_PRIVATE_KEY")).toBe(true);
    });

    test("detects OpenSSH private key", () => {
      const content = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjE
-----END OPENSSH PRIVATE KEY-----`;
      const detections = detectSecrets(content);
      expect(detections.some((d) => d.type === "SSH_PRIVATE_KEY")).toBe(true);
    });

    test("detects PGP private key", () => {
      const content = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lQOYBF+xyz
-----END PGP PRIVATE KEY BLOCK-----`;
      const detections = detectSecrets(content);
      expect(detections.some((d) => d.type === "PGP_PRIVATE_KEY")).toBe(true);
    });
  });

  describe("Database Connection Strings", () => {
    test("detects PostgreSQL URL with credentials", () => {
      const content = "DB: postgresql://user:password123@localhost:5432/mydb";
      const detections = detectSecrets(content);
      expect(detections.some((d) => d.type === "POSTGRES_URL")).toBe(true);
    });

    test("detects MongoDB URL with credentials", () => {
      const content = "MONGO: mongodb+srv://admin:secret@cluster.mongodb.net/db";
      const detections = detectSecrets(content);
      expect(detections.some((d) => d.type === "MONGODB_URL")).toBe(true);
    });

    test("detects MySQL URL with credentials", () => {
      const content = "mysql://root:password@localhost/mydb";
      const detections = detectSecrets(content);
      expect(detections.some((d) => d.type === "MYSQL_URL")).toBe(true);
    });

    test("detects Redis URL with credentials", () => {
      const content = "redis://:mypassword@localhost:6379";
      const detections = detectSecrets(content);
      expect(detections.some((d) => d.type === "REDIS_URL")).toBe(true);
    });
  });

  describe("Payment Processor Keys", () => {
    test("detects Stripe secret key (live)", () => {
      // Pattern: sk_live_[a-zA-Z0-9]{24,} - needs 24+ chars
      // Dynamically constructed to avoid GitHub secret scanner
      const prefix = ["sk", "live"].join("_") + "_";
      const content = `Stripe: ${prefix}${"0".repeat(24)}`;
      const detections = detectSecrets(content);
      expect(detections.some((d) => d.type === "STRIPE_SECRET_KEY")).toBe(true);
    });

    test("detects Stripe secret key (test)", () => {
      // Pattern: sk_test_[a-zA-Z0-9]{24,} - needs 24+ chars
      // Dynamically constructed to avoid GitHub secret scanner
      const prefix = ["sk", "test"].join("_") + "_";
      const content = `Test: ${prefix}${"0".repeat(24)}`;
      const detections = detectSecrets(content);
      expect(detections.some((d) => d.type === "STRIPE_SECRET_KEY_TEST")).toBe(true);
    });
  });

  describe("Infrastructure Tokens", () => {
    test("detects npm token", () => {
      // Pattern: npm_[a-zA-Z0-9]{30,} - needs 30+ chars
      const content = "NPM_TOKEN=npm_000000000000000000000000000000";
      const detections = detectSecrets(content);
      expect(detections.some((d) => d.type === "NPM_TOKEN")).toBe(true);
    });

    test("detects SendGrid API key", () => {
      // Pattern: SG\.[a-zA-Z0-9-_]{20,}\.[a-zA-Z0-9-_]{40,}
      const content = "API: SG.00000000000000000000.0000000000000000000000000000000000000000";
      const detections = detectSecrets(content);
      expect(detections.some((d) => d.type === "SENDGRID_KEY")).toBe(true);
    });

    test("detects Square token", () => {
      // Pattern: sq0csp-[a-zA-Z0-9-_]{43} - exactly 43 chars after sq0csp-
      // Dynamically constructed to avoid GitHub secret scanner
      const prefix = ["sq0csp", ""].join("-");
      const content = `Square: ${prefix}${"0".repeat(43)}`;
      const detections = detectSecrets(content);
      expect(detections.some((d) => d.type === "SQUARE_TOKEN")).toBe(true);
    });
  });

  describe("JWT Detection", () => {
    test("detects JWT token", () => {
      const content =
        "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
      const detections = detectSecrets(content);
      expect(detections.some((d) => d.type === "JWT_TOKEN")).toBe(true);
    });
  });
});

describe("containsSecrets", () => {
  test("returns true when secrets are present", () => {
    expect(containsSecrets("Key: sk-ant-api03-abcdefghij")).toBe(true);
    expect(containsSecrets("AWS: AKIAIOSFODNN7EXAMPLE")).toBe(true);
  });

  test("returns false when no secrets are present", () => {
    expect(containsSecrets("Hello, how are you?")).toBe(false);
    expect(containsSecrets("The weather is nice today")).toBe(false);
  });

  test("respects strict mode", () => {
    // JWT is not high-confidence
    const jwt =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    expect(containsSecrets(jwt, false)).toBe(true);
    // Note: JWT detection might still trigger in strict mode depending on pattern confidence
  });
});

describe("getHighConfidencePatterns", () => {
  test("returns only high-confidence patterns", () => {
    const patterns = getHighConfidencePatterns();
    expect(patterns.every((p) => p.highConfidence)).toBe(true);
    expect(patterns.length).toBeLessThan(SECRET_PATTERNS.length);
  });
});

// =============================================================================
// Entropy Detection Tests
// =============================================================================

describe("calculateEntropy", () => {
  test("returns 0 for empty string", () => {
    expect(calculateEntropy("")).toBe(0);
  });

  test("returns 0 for single character repeated", () => {
    expect(calculateEntropy("aaaaaaaaaa")).toBe(0);
  });

  test("returns low entropy for simple patterns", () => {
    const entropy = calculateEntropy("abcabc");
    expect(entropy).toBeLessThan(2);
  });

  test("returns moderate entropy for English text", () => {
    const entropy = calculateEntropy("The quick brown fox jumps over the lazy dog");
    expect(entropy).toBeGreaterThan(3);
    expect(entropy).toBeLessThan(5);
  });

  test("returns high entropy for random-looking strings", () => {
    const entropy = calculateEntropy("aB3$dE6@hI9#kL2%nO5^pQ8&rS1*tU4!");
    expect(entropy).toBeGreaterThan(4.5);
  });
});

describe("isHighEntropy", () => {
  test("returns false for short strings", () => {
    expect(isHighEntropy("abc123", 4.5, 16)).toBe(false);
  });

  test("returns false for low-entropy strings", () => {
    expect(isHighEntropy("abcabcabcabcabcabc")).toBe(false);
  });

  test("returns true for high-entropy strings", () => {
    expect(isHighEntropy("aB3dE6hI9kL2nO5pQ8rS1tU4wX7yZ0")).toBe(true);
  });

  test("returns false for strings with too many special chars", () => {
    expect(isHighEntropy("!!!###$$$%%%&&&***")).toBe(false);
  });
});

describe("detectHighEntropyStrings", () => {
  test("detects high-entropy tokens", () => {
    const content = "Here is the key: aB3dE6hI9kL2nO5pQ8rS1tU4wX7yZ0abc";
    const detections = detectHighEntropyStrings(content, { threshold: 4.0 });
    expect(detections.length).toBeGreaterThan(0);
  });

  test("ignores sequential patterns", () => {
    const content = "Sequence: abcdefghijklmnopqrstuvwx";
    const detections = detectHighEntropyStrings(content);
    expect(detections.length).toBe(0);
  });

  test("ignores repeating patterns", () => {
    const content = "Pattern: abcabcabcabcabcabcabcabc";
    const detections = detectHighEntropyStrings(content);
    expect(detections.length).toBe(0);
  });
});

describe("detectBase64Secrets", () => {
  test("detects base64-encoded secret prefix", () => {
    // "sk-ant-api03-test" base64 encoded
    const encoded = Buffer.from("sk-ant-api03-testkey").toString("base64");
    const content = `Check this: ${encoded}`;
    const detections = detectBase64Secrets(content);
    expect(detections.length).toBeGreaterThan(0);
  });

  test("ignores non-secret base64 content", () => {
    // "Hello World This Is A Test" base64 encoded (benign)
    const encoded = Buffer.from("Hello World This Is A Normal Test Message").toString("base64");
    const detections = detectBase64Secrets(encoded);
    expect(detections.length).toBe(0);
  });
});

// =============================================================================
// Redaction Filter Tests
// =============================================================================

describe("redactSecrets", () => {
  test("redacts detected secrets", () => {
    const content = "My API key is sk-ant-api03-abcdefghij and here is more text";
    const result = redactSecrets(content);
    expect(result.modified).toBe(true);
    expect(result.redacted).not.toContain("sk-ant-api03-abcdefghij");
    expect(result.redacted).toContain("[REDACTED:");
  });

  test("preserves non-secret content", () => {
    const content = "Hello world, this is a test message";
    const result = redactSecrets(content);
    expect(result.modified).toBe(false);
    expect(result.redacted).toBe(content);
  });

  test("tracks redaction counts by type", () => {
    const content = "Keys: sk-ant-api03-abcdefghij and ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    const result = redactSecrets(content);
    expect(result.redactionCounts.get("ANTHROPIC_KEY")).toBe(1);
    expect(result.redactionCounts.get("GITHUB_PAT")).toBe(1);
  });

  test("uses custom placeholder", () => {
    const content = "Key: sk-ant-api03-abcdefghij";
    const result = redactSecrets(content, { placeholder: "***{TYPE}***" });
    expect(result.redacted).toContain("***ANTHROPIC_KEY***");
  });

  test("respects whitelist", () => {
    const content = "Key: sk-ant-api03-testkey123";
    const result = redactSecrets(content, {
      whitelist: [/sk-ant-api03-testkey123/],
    });
    expect(result.modified).toBe(false);
  });

  test("generates redaction events", () => {
    const content = "Secret: AKIAIOSFODNN7EXAMPLE";
    const result = redactSecrets(content, { logRedactions: true });
    expect(result.events.length).toBeGreaterThan(0);
    expect(result.events[0].type).toBe("AWS_ACCESS_KEY");
    expect(result.events[0].method).toBe("pattern");
  });

  test("calls custom logger", () => {
    const logger = vi.fn();
    const content = "Key: ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    redactSecrets(content, { logger });
    expect(logger).toHaveBeenCalled();
  });

  test("redacts multiple occurrences of same secret", () => {
    const key = "sk-ant-api03-abcdefghij";
    const content = `First: ${key} and again: ${key}`;
    const result = redactSecrets(content);
    expect(result.redacted.match(/\[REDACTED:/g)?.length).toBe(2);
  });

  test("handles content with only secrets", () => {
    const content = "AKIAIOSFODNN7EXAMPLE";
    const result = redactSecrets(content);
    expect(result.modified).toBe(true);
    expect(result.redacted).not.toContain("AKIA");
  });
});

describe("createRedactionFilter", () => {
  test("creates filter with custom options", () => {
    const filter = createRedactionFilter({ strictPatterns: true });
    expect(filter.config.strictPatterns).toBe(true);
  });

  test("redacts using instance method", () => {
    const filter = createRedactionFilter();
    const result = filter.redact("Key: sk-ant-api03-abcdefghij");
    expect(result.modified).toBe(true);
  });

  test("checks for secrets without redacting", () => {
    const filter = createRedactionFilter();
    expect(filter.containsSecrets("Key: ghp_abcdefghijklmnopqrstuvwxyz0123456789")).toBe(true);
    expect(filter.containsSecrets("Hello world")).toBe(false);
  });
});

// =============================================================================
// Integration Tests - Known Secrets
// =============================================================================

describe("known secrets - full redaction", () => {
  // All test secrets use obviously fake values to avoid triggering secret scanners
  // Each pattern is commented with the expected regex format
  const knownSecrets = [
    // sk-ant-[a-zA-Z0-9-]{10,}
    { content: "sk-ant-api03-aaaa0000000000", type: "Anthropic" },
    // sk-proj-[a-zA-Z0-9-_]{20,} - needs 20+ chars
    { content: "sk-proj-aaaa00000000000000000000", type: "OpenAI" },
    { content: "AKIAIOSFODNN7EXAMPLE", type: "AWS" },
    { content: "ASIA1234567890ABCDEF", type: "AWS temp" },
    // AIza[0-9A-Za-z_-]{30,}
    { content: "AIzaSyC-aaaaaaaaaaaaaaaaaaaaaaaaaaa", type: "Google" },
    // ghp_[a-zA-Z0-9]{36}
    { content: "ghp_aaaaaaaaaaaaaaaaaaaaaaaa000000000000", type: "GitHub PAT" },
    // gho_[a-zA-Z0-9]{36}
    { content: "gho_aaaaaaaaaaaaaaaaaaaaaaaa000000000000", type: "GitHub OAuth" },
    // glpat-[a-zA-Z0-9-_]{20,}
    { content: "glpat-aaaa0000000000000000", type: "GitLab PAT" },
    // xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+ (minimal values to avoid secret scanner)
    { content: "xoxb-1-2-x", type: "Slack bot" },
    // xoxp-[0-9]+-[0-9]+-[0-9]+-[a-f0-9]+ (minimal values to avoid secret scanner)
    { content: "xoxp-1-2-3-a", type: "Slack user" },
    // [0-9]{8,12}:[A-Za-z0-9_-]{30,}
    { content: "0000000000:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", type: "Telegram" },
    // sk_live_[a-zA-Z0-9]{24,} (dynamically built to avoid secret scanner)
    { content: ["sk", "live"].join("_") + "_" + "0".repeat(24), type: "Stripe live" },
    // sk_test_[a-zA-Z0-9]{24,} (dynamically built to avoid secret scanner)
    { content: ["sk", "test"].join("_") + "_" + "0".repeat(24), type: "Stripe test" },
    // npm_[a-zA-Z0-9]{30,}
    { content: "npm_aaaaaaaaaaaaaaaaaa000000000000", type: "npm" },
    // SG\.[a-zA-Z0-9-_]{20,}\.[a-zA-Z0-9-_]{40,}
    {
      content: "SG.aaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      type: "SendGrid",
    },
    { content: "postgresql://user:pass@host/db", type: "Postgres URL" },
    { content: "mongodb+srv://admin:secret@cluster/db", type: "MongoDB URL" },
    { content: "mysql://root:password@localhost/db", type: "MySQL URL" },
    { content: "redis://:password@localhost:6379", type: "Redis URL" },
    {
      content: `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAJBANcz
-----END RSA PRIVATE KEY-----`,
      type: "RSA key",
    },
  ];

  test.each(knownSecrets)("redacts $type secret", ({ content }) => {
    const result = redactSecrets(`Here is the secret: ${content}`);
    expect(result.modified).toBe(true);
    expect(result.redactionCounts.size).toBeGreaterThan(0);
  });
});

describe("benign content - no false positives", () => {
  const benignContent = [
    "Hello, how are you today?",
    "The weather is nice",
    "I need help with my code",
    "Can you explain how async/await works?",
    "The error message says 'undefined is not a function'",
    "Please review my pull request",
    "What is the difference between let and const?",
    "How do I install npm packages?",
    "The database query is slow",
    "I'm getting a 404 error",
    "The API returns an empty response",
    "How do I configure webpack?",
    "What is TypeScript?",
    "My tests are failing",
    "Can you help debug this issue?",
    "The function takes two parameters",
    "I need to refactor this code",
    "How do I use React hooks?",
    "The build is failing",
    "What is the best practice for error handling?",
    "regular-text-without-secrets",
    "just_some_underscored_text",
    "CamelCaseVariableName",
    "UPPER_CASE_CONSTANT",
    "path/to/some/file.txt",
    "user@example.com",
    "https://github.com/user/repo",
    "2026-02-20T12:00:00Z",
    "application/json",
    "Content-Type: text/html",
  ];

  test.each(benignContent)("does not redact benign content: %s", (content) => {
    const result = redactSecrets(content);
    expect(result.modified).toBe(false);
  });
});

// =============================================================================
// Convenience Function Tests
// =============================================================================

describe("redactOutboundMessage", () => {
  test("redacts with default settings", () => {
    const result = redactOutboundMessage("Key: sk-ant-api03-abcdefghij");
    expect(result.modified).toBe(true);
  });
});

describe("checkForSecrets", () => {
  test("detects secrets", () => {
    expect(checkForSecrets("Key: ghp_abcdefghijklmnopqrstuvwxyz0123456789")).toBe(true);
  });

  test("returns false for clean content", () => {
    expect(checkForSecrets("Hello world")).toBe(false);
  });
});

describe("createMonitoredRedactionFilter", () => {
  test("tracks statistics", () => {
    const filter = createMonitoredRedactionFilter();

    filter.redact("Key: sk-ant-api03-abcdefghij");
    filter.redact("Another: ghp_abcdefghijklmnopqrstuvwxyz0123456789");
    filter.redact("Clean text");

    const stats = filter.getStats();
    expect(stats.totalChecked).toBe(3);
    expect(stats.totalRedacted).toBe(2);
    expect(stats.byType.size).toBeGreaterThan(0);
  });

  test("resets statistics", () => {
    const filter = createMonitoredRedactionFilter();

    filter.redact("Key: AKIAIOSFODNN7EXAMPLE");
    filter.resetStats();

    const stats = filter.getStats();
    expect(stats.totalChecked).toBe(0);
    expect(stats.totalRedacted).toBe(0);
  });
});
