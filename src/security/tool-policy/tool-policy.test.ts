/**
 * Tool Execution Policy Tests
 *
 * Tests for capability matrix, rate limiting, schema validation,
 * and confirmation gates.
 *
 * @module security/tool-policy/tests
 */

import { describe, expect, test } from "vitest";
import {
  checkCapability,
  canPerform,
  canPerformWithoutConfirmation,
  getAllowedCapabilities,
  getDeniedCapabilities,
  getConfirmationRequiredCapabilities,
  CAPABILITY_MATRIX,
} from "./capability-matrix.js";
import {
  checkBashCommandConfirmation,
  createConfirmationGate,
  isDestructiveCommand,
} from "./confirmation-gate.js";
import { createToolPolicy } from "./index.js";
import {
  createRateLimiter,
  RateLimitError,
  QuotaExceededError,
  DEFAULT_RATE_LIMITS,
} from "./rate-limiter.js";
import {
  validateToolParams,
  validateToolCall,
  registerToolSchema,
  COMMON_SCHEMAS,
} from "./schema-validator.js";

// Generate unique session IDs for each test
let sessionCounter = 0;
function uniqueSessionId(): string {
  return `test-session-${Date.now()}-${sessionCounter++}`;
}

// =============================================================================
// Capability Matrix Tests
// =============================================================================

describe("capability-matrix", () => {
  describe("checkCapability", () => {
    test("allows unrestricted bash for main-elevated", () => {
      const result = checkCapability("main-elevated", "bash-unrestricted");
      expect(result.allowed).toBe(true);
      expect(result.requiresConfirmation).toBe(false);
    });

    test("requires confirmation for unrestricted bash in main-standard", () => {
      const result = checkCapability("main-standard", "bash-unrestricted");
      expect(result.allowed).toBe(true);
      expect(result.requiresConfirmation).toBe(true);
    });

    test("denies unrestricted bash for sandbox", () => {
      const result = checkCapability("sandbox", "bash-unrestricted");
      expect(result.allowed).toBe(false);
    });

    test("denies all capabilities for guest", () => {
      const result = checkCapability("guest", "bash-unrestricted");
      expect(result.allowed).toBe(false);

      const result2 = checkCapability("guest", "file-read");
      expect(result2.allowed).toBe(false);
    });

    test("allows file-read for most session types", () => {
      expect(checkCapability("main-elevated", "file-read").allowed).toBe(true);
      expect(checkCapability("main-standard", "file-read").allowed).toBe(true);
      expect(checkCapability("sandbox", "file-read").allowed).toBe(true);
      expect(checkCapability("webhook", "file-read").allowed).toBe(true);
    });

    test("returns correct reason in result", () => {
      const allowed = checkCapability("main-elevated", "bash-unrestricted");
      expect(allowed.reason).toContain("allowed");

      const denied = checkCapability("guest", "bash-unrestricted");
      expect(denied.reason).toContain("denied");
    });

    test("handles unknown session type", () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const result = checkCapability("unknown" as any, "bash-unrestricted");
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("Unknown session type");
    });

    test("handles unknown capability", () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const result = checkCapability("main-elevated", "unknown-cap" as any);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("Unknown capability");
    });
  });

  describe("canPerform", () => {
    test("returns true for allowed capabilities", () => {
      expect(canPerform("main-elevated", "bash-unrestricted")).toBe(true);
    });

    test("returns true for confirm capabilities", () => {
      expect(canPerform("main-standard", "bash-unrestricted")).toBe(true);
    });

    test("returns false for denied capabilities", () => {
      expect(canPerform("guest", "bash-unrestricted")).toBe(false);
    });
  });

  describe("canPerformWithoutConfirmation", () => {
    test("returns true only for allow capabilities", () => {
      expect(canPerformWithoutConfirmation("main-elevated", "bash-unrestricted")).toBe(true);
    });

    test("returns false for confirm capabilities", () => {
      expect(canPerformWithoutConfirmation("main-standard", "bash-unrestricted")).toBe(false);
    });

    test("returns false for denied capabilities", () => {
      expect(canPerformWithoutConfirmation("guest", "bash-unrestricted")).toBe(false);
    });
  });

  describe("capability listing", () => {
    test("getAllowedCapabilities returns allow and confirm", () => {
      const allowed = getAllowedCapabilities("main-elevated");
      expect(allowed.length).toBeGreaterThan(0);
      expect(allowed).toContain("bash-unrestricted");
    });

    test("getDeniedCapabilities returns only denied", () => {
      const denied = getDeniedCapabilities("sandbox");
      expect(denied).toContain("bash-unrestricted");
      expect(denied).toContain("browser-cdp");
    });

    test("getConfirmationRequiredCapabilities returns only confirm", () => {
      const confirm = getConfirmationRequiredCapabilities("main-standard");
      expect(confirm).toContain("bash-unrestricted");
      expect(confirm.every((cap) => CAPABILITY_MATRIX["main-standard"][cap] === "confirm")).toBe(
        true,
      );
    });
  });
});

// =============================================================================
// Rate Limiter Tests
// =============================================================================

describe("rate-limiter", () => {
  describe("createRateLimiter", () => {
    test("creates limiter with default config", () => {
      const limiter = createRateLimiter();
      expect(limiter.config.maxToolCallsPerHour).toBe(DEFAULT_RATE_LIMITS.maxToolCallsPerHour);
    });

    test("creates limiter with custom config", () => {
      const limiter = createRateLimiter({ maxToolCallsPerHour: 50 });
      expect(limiter.config.maxToolCallsPerHour).toBe(50);
    });
  });

  describe("tool call limiting", () => {
    test("allows calls within limit", () => {
      const limiter = createRateLimiter({ maxToolCallsPerHour: 100, maxToolCallsPerMinute: 20 });
      const sessionId = uniqueSessionId();
      const result = limiter.checkToolCall(sessionId);
      expect(result.allowed).toBe(true);
      expect(result.remaining.toolCallsThisHour).toBe(100);
    });

    test("throws RateLimitError when minute limit exceeded", () => {
      const limiter = createRateLimiter({ maxToolCallsPerMinute: 3 });
      const sessionId = uniqueSessionId();

      // Make 3 calls (at limit)
      for (let i = 0; i < 3; i++) {
        limiter.checkToolCall(sessionId);
        limiter.recordToolCall(sessionId);
      }

      // 4th call should fail
      expect(() => limiter.checkToolCall(sessionId)).toThrow(RateLimitError);

      try {
        limiter.checkToolCall(sessionId);
      } catch (error) {
        expect(error).toBeInstanceOf(RateLimitError);
        expect((error as RateLimitError).type).toBe("minute");
        expect((error as RateLimitError).limit).toBe(3);
        expect((error as RateLimitError).current).toBe(3);
      }
    });

    test("throws RateLimitError when hourly limit exceeded", () => {
      const limiter = createRateLimiter({
        maxToolCallsPerHour: 5,
        maxToolCallsPerMinute: 100, // High minute limit
      });
      const sessionId = uniqueSessionId();

      // Make 5 calls (at limit)
      for (let i = 0; i < 5; i++) {
        limiter.checkToolCall(sessionId);
        limiter.recordToolCall(sessionId);
      }

      // 6th call should fail
      expect(() => limiter.checkToolCall(sessionId)).toThrow(RateLimitError);

      try {
        limiter.checkToolCall(sessionId);
      } catch (error) {
        expect(error).toBeInstanceOf(RateLimitError);
        expect((error as RateLimitError).type).toBe("hourly");
      }
    });

    test("tracks usage per session independently", () => {
      const limiter = createRateLimiter({ maxToolCallsPerMinute: 2 });
      const sessionId1 = uniqueSessionId();
      const sessionId2 = uniqueSessionId();

      // Session 1 at limit
      limiter.recordToolCall(sessionId1);
      limiter.recordToolCall(sessionId1);

      // Session 2 should still work
      expect(() => limiter.checkToolCall(sessionId2)).not.toThrow();
    });

    test("getUsage returns correct counts", () => {
      const limiter = createRateLimiter();
      const sessionId = uniqueSessionId();

      limiter.recordToolCall(sessionId);
      limiter.recordToolCall(sessionId);
      limiter.recordToolCall(sessionId);

      const usage = limiter.getUsage(sessionId);
      expect(usage.toolCallsLastMinute).toBe(3);
      expect(usage.toolCallsLastHour).toBe(3);
    });

    test("resetUsage clears session data", () => {
      const limiter = createRateLimiter();
      const sessionId = uniqueSessionId();

      limiter.recordToolCall(sessionId);
      limiter.recordToolCall(sessionId);
      limiter.resetUsage(sessionId);

      const usage = limiter.getUsage(sessionId);
      expect(usage.toolCallsLastMinute).toBe(0);
      expect(usage.toolCallsLastHour).toBe(0);
    });
  });

  describe("cron job quota", () => {
    test("allows cron jobs within quota", () => {
      const limiter = createRateLimiter({ maxCronJobsPerSession: 10 });
      const sessionId = uniqueSessionId();
      expect(() => limiter.checkCronJob(sessionId)).not.toThrow();
    });

    test("throws QuotaExceededError when cron quota exceeded", () => {
      const limiter = createRateLimiter({ maxCronJobsPerSession: 2 });
      const sessionId = uniqueSessionId();

      limiter.recordCronJobCreated(sessionId);
      limiter.recordCronJobCreated(sessionId);

      expect(() => limiter.checkCronJob(sessionId)).toThrow(QuotaExceededError);

      try {
        limiter.checkCronJob(sessionId);
      } catch (error) {
        expect(error).toBeInstanceOf(QuotaExceededError);
        expect((error as QuotaExceededError).resource).toBe("cron");
        expect((error as QuotaExceededError).limit).toBe(2);
        expect((error as QuotaExceededError).current).toBe(2);
      }
    });

    test("recordCronJobDeleted decrements count", () => {
      const limiter = createRateLimiter({ maxCronJobsPerSession: 2 });
      const sessionId = uniqueSessionId();

      limiter.recordCronJobCreated(sessionId);
      limiter.recordCronJobCreated(sessionId);
      limiter.recordCronJobDeleted(sessionId);

      // Should work now
      expect(() => limiter.checkCronJob(sessionId)).not.toThrow();
    });
  });

  describe("webhook quota", () => {
    test("throws QuotaExceededError when webhook quota exceeded", () => {
      const limiter = createRateLimiter({ maxWebhooksPerSession: 2 });
      const sessionId = uniqueSessionId();

      limiter.recordWebhookCreated(sessionId);
      limiter.recordWebhookCreated(sessionId);

      expect(() => limiter.checkWebhook(sessionId)).toThrow(QuotaExceededError);
    });
  });

  describe("token budget", () => {
    test("allows spend within budget", () => {
      const limiter = createRateLimiter({ maxDailyTokenBudgetUSD: 5.0 });
      const sessionId = uniqueSessionId();
      expect(() => limiter.checkTokenBudget(sessionId, 1.0)).not.toThrow();
    });

    test("throws QuotaExceededError when budget exceeded", () => {
      const limiter = createRateLimiter({ maxDailyTokenBudgetUSD: 5.0 });
      const sessionId = uniqueSessionId();

      limiter.recordTokenSpend(sessionId, 4.0);

      expect(() => limiter.checkTokenBudget(sessionId, 2.0)).toThrow(QuotaExceededError);
    });

    test("tracks cumulative spend", () => {
      const limiter = createRateLimiter({ maxDailyTokenBudgetUSD: 5.0 });
      const sessionId = uniqueSessionId();

      limiter.recordTokenSpend(sessionId, 1.0);
      limiter.recordTokenSpend(sessionId, 1.5);
      limiter.recordTokenSpend(sessionId, 2.0);

      const usage = limiter.getUsage(sessionId);
      expect(usage.dailySpendUSD).toBe(4.5);
    });
  });

  describe("concurrent executions", () => {
    test("tracks concurrent executions", () => {
      const limiter = createRateLimiter({ maxConcurrentExecutions: 3 });
      const sessionId = uniqueSessionId();

      limiter.startExecution(sessionId);
      limiter.startExecution(sessionId);

      const usage = limiter.getUsage(sessionId);
      expect(usage.concurrentExecutions).toBe(2);
    });

    test("throws when concurrent limit exceeded", () => {
      const limiter = createRateLimiter({ maxConcurrentExecutions: 2 });
      const sessionId = uniqueSessionId();

      limiter.startExecution(sessionId);
      limiter.startExecution(sessionId);

      expect(() => limiter.checkToolCall(sessionId)).toThrow(RateLimitError);
    });

    test("endExecution decrements count", () => {
      const limiter = createRateLimiter({ maxConcurrentExecutions: 2 });
      const sessionId = uniqueSessionId();

      limiter.startExecution(sessionId);
      limiter.startExecution(sessionId);
      limiter.endExecution(sessionId);

      expect(() => limiter.checkToolCall(sessionId)).not.toThrow();
    });
  });
});

// =============================================================================
// Schema Validator Tests
// =============================================================================

describe("schema-validator", () => {
  describe("validateToolParams", () => {
    test("validates required properties", () => {
      const schema = {
        name: "test",
        properties: {
          required_prop: { type: "string" as const, required: true },
        },
        required: ["required_prop"],
      };

      const result = validateToolParams("test", {}, schema);
      expect(result.valid).toBe(false);
      expect(result.errors[0]?.path).toBe("required_prop");
    });

    test("validates string type", () => {
      const schema = {
        name: "test",
        properties: {
          str: { type: "string" as const },
        },
      };

      const valid = validateToolParams("test", { str: "hello" }, schema);
      expect(valid.valid).toBe(true);

      const invalid = validateToolParams("test", { str: 123 }, schema);
      expect(invalid.valid).toBe(false);
    });

    test("validates string minLength/maxLength", () => {
      const schema = {
        name: "test",
        properties: {
          str: { type: "string" as const, minLength: 2, maxLength: 5 },
        },
      };

      const tooShort = validateToolParams("test", { str: "a" }, schema);
      expect(tooShort.valid).toBe(false);

      const tooLong = validateToolParams("test", { str: "abcdef" }, schema);
      expect(tooLong.valid).toBe(false);

      const justRight = validateToolParams("test", { str: "abc" }, schema);
      expect(justRight.valid).toBe(true);
    });

    test("validates string pattern", () => {
      const schema = {
        name: "test",
        properties: {
          url: { type: "string" as const, pattern: /^https?:\/\// },
        },
      };

      const valid = validateToolParams("test", { url: "https://example.com" }, schema);
      expect(valid.valid).toBe(true);

      const invalid = validateToolParams("test", { url: "not-a-url" }, schema);
      expect(invalid.valid).toBe(false);
    });

    test("validates enum values", () => {
      const schema = {
        name: "test",
        properties: {
          color: { type: "string" as const, enum: ["red", "green", "blue"] },
        },
      };

      const valid = validateToolParams("test", { color: "red" }, schema);
      expect(valid.valid).toBe(true);

      const invalid = validateToolParams("test", { color: "yellow" }, schema);
      expect(invalid.valid).toBe(false);
    });

    test("validates number range", () => {
      const schema = {
        name: "test",
        properties: {
          num: { type: "number" as const, minimum: 0, maximum: 100 },
        },
      };

      const valid = validateToolParams("test", { num: 50 }, schema);
      expect(valid.valid).toBe(true);

      const tooLow = validateToolParams("test", { num: -1 }, schema);
      expect(tooLow.valid).toBe(false);

      const tooHigh = validateToolParams("test", { num: 101 }, schema);
      expect(tooHigh.valid).toBe(false);
    });

    test("rejects unexpected properties when additionalProperties is false", () => {
      const schema = {
        name: "test",
        properties: {
          allowed: { type: "string" as const },
        },
        additionalProperties: false,
      };

      const result = validateToolParams("test", { allowed: "ok", extra: "bad" }, schema);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.path === "extra")).toBe(true);
    });

    test("allows unexpected properties when additionalProperties is true", () => {
      const schema = {
        name: "test",
        properties: {
          allowed: { type: "string" as const },
        },
        additionalProperties: true,
      };

      const result = validateToolParams("test", { allowed: "ok", extra: "fine" }, schema);
      expect(result.valid).toBe(true);
      expect(result.warnings.some((w) => w.includes("extra"))).toBe(true);
    });

    test("validates nested objects", () => {
      const schema = {
        name: "test",
        properties: {
          nested: {
            type: "object" as const,
            properties: {
              inner: { type: "string" as const, required: true },
            },
          },
        },
      };

      const valid = validateToolParams("test", { nested: { inner: "value" } }, schema);
      expect(valid.valid).toBe(true);
    });

    test("validates array items", () => {
      const schema = {
        name: "test",
        properties: {
          items: {
            type: "array" as const,
            items: { type: "number" as const },
          },
        },
      };

      const valid = validateToolParams("test", { items: [1, 2, 3] }, schema);
      expect(valid.valid).toBe(true);

      const invalid = validateToolParams("test", { items: [1, "two", 3] }, schema);
      expect(invalid.valid).toBe(false);
    });
  });

  describe("common schemas", () => {
    test("bash schema validates correctly", () => {
      const result = validateToolParams("bash", { command: "ls -la" }, COMMON_SCHEMAS.bash);
      expect(result.valid).toBe(true);
    });

    test("bash schema rejects empty command", () => {
      const result = validateToolParams("bash", { command: "" }, COMMON_SCHEMAS.bash);
      expect(result.valid).toBe(false);
    });

    test("bash schema rejects extra properties", () => {
      const result = validateToolParams(
        "bash",
        { command: "ls", malicious: "inject" },
        COMMON_SCHEMAS.bash,
      );
      expect(result.valid).toBe(false);
    });

    test("browserNavigate schema validates URL pattern", () => {
      const valid = validateToolParams(
        "browserNavigate",
        { url: "https://example.com" },
        COMMON_SCHEMAS.browserNavigate,
      );
      expect(valid.valid).toBe(true);

      const invalid = validateToolParams(
        "browserNavigate",
        { url: "not-a-url" },
        COMMON_SCHEMAS.browserNavigate,
      );
      expect(invalid.valid).toBe(false);
    });
  });

  describe("validateToolCall", () => {
    test("validates against registered schema", () => {
      registerToolSchema({
        name: "customTool",
        properties: {
          param: { type: "string" as const, required: true },
        },
        required: ["param"],
      });

      const valid = validateToolCall("customTool", { param: "value" });
      expect(valid.valid).toBe(true);

      const invalid = validateToolCall("customTool", {});
      expect(invalid.valid).toBe(false);
    });

    test("allows unregistered tools with warning", () => {
      const result = validateToolCall("unregisteredTool", { anything: "goes" });
      expect(result.valid).toBe(true);
      expect(result.warnings.length).toBeGreaterThan(0);
    });
  });
});

// =============================================================================
// Confirmation Gate Tests
// =============================================================================

describe("confirmation-gate", () => {
  describe("checkBashCommandConfirmation", () => {
    describe("destructive file operations", () => {
      test("requires confirmation for rm", () => {
        const result = checkBashCommandConfirmation("rm -rf /tmp/test");
        expect(result.required).toBe(true);
        expect(result.category).toBe("destructive");
      });

      test("requires confirmation for rmdir", () => {
        const result = checkBashCommandConfirmation("rmdir /tmp/test");
        expect(result.required).toBe(true);
      });

      test("requires confirmation for unlink", () => {
        const result = checkBashCommandConfirmation("unlink /tmp/file");
        expect(result.required).toBe(true);
      });
    });

    describe("git operations", () => {
      test("requires confirmation for git push --force", () => {
        const result = checkBashCommandConfirmation("git push --force origin main");
        expect(result.required).toBe(true);
        expect(result.category).toBe("destructive");
      });

      test("requires confirmation for git reset --hard", () => {
        const result = checkBashCommandConfirmation("git reset --hard HEAD~1");
        expect(result.required).toBe(true);
      });

      test("requires confirmation for git clean -f", () => {
        const result = checkBashCommandConfirmation("git clean -f");
        expect(result.required).toBe(true);
      });

      test("requires confirmation for git checkout .", () => {
        const result = checkBashCommandConfirmation("git checkout .");
        expect(result.required).toBe(true);
      });

      test("requires confirmation for git branch -D", () => {
        const result = checkBashCommandConfirmation("git branch -D feature");
        expect(result.required).toBe(true);
      });
    });

    describe("database operations", () => {
      test("requires confirmation for DROP TABLE", () => {
        const result = checkBashCommandConfirmation("mysql -e 'DROP TABLE users'");
        expect(result.required).toBe(true);
      });

      test("requires confirmation for TRUNCATE TABLE", () => {
        const result = checkBashCommandConfirmation("psql -c 'TRUNCATE TABLE logs'");
        expect(result.required).toBe(true);
      });

      test("requires confirmation for DELETE FROM without WHERE", () => {
        const result = checkBashCommandConfirmation("DELETE FROM users;");
        expect(result.required).toBe(true);
      });
    });

    describe("system operations", () => {
      test("requires confirmation for sudo", () => {
        const result = checkBashCommandConfirmation("sudo apt-get install package");
        expect(result.required).toBe(true);
        expect(result.category).toBe("privileged");
      });

      test("requires confirmation for chmod", () => {
        const result = checkBashCommandConfirmation("chmod 777 /tmp/script.sh");
        expect(result.required).toBe(true);
        expect(result.category).toBe("security");
      });

      test("requires confirmation for kill", () => {
        const result = checkBashCommandConfirmation("kill -9 1234");
        expect(result.required).toBe(true);
      });

      test("requires confirmation for killall", () => {
        const result = checkBashCommandConfirmation("killall node");
        expect(result.required).toBe(true);
      });
    });

    describe("safe commands", () => {
      test("does not require confirmation for ls", () => {
        const result = checkBashCommandConfirmation("ls -la");
        expect(result.required).toBe(false);
      });

      test("does not require confirmation for cat", () => {
        const result = checkBashCommandConfirmation("cat /tmp/file.txt");
        expect(result.required).toBe(false);
      });

      test("does not require confirmation for echo", () => {
        const result = checkBashCommandConfirmation("echo 'hello world'");
        expect(result.required).toBe(false);
      });

      test("does not require confirmation for git status", () => {
        const result = checkBashCommandConfirmation("git status");
        expect(result.required).toBe(false);
      });

      test("does not require confirmation for npm install", () => {
        const result = checkBashCommandConfirmation("npm install lodash");
        expect(result.required).toBe(false);
      });
    });
  });

  describe("isDestructiveCommand", () => {
    test("returns true for destructive commands", () => {
      expect(isDestructiveCommand("rm -rf /tmp")).toBe(true);
      expect(isDestructiveCommand("git push --force")).toBe(true);
    });

    test("returns false for safe commands", () => {
      expect(isDestructiveCommand("ls -la")).toBe(false);
      expect(isDestructiveCommand("git status")).toBe(false);
    });
  });

  describe("createConfirmationGate", () => {
    test("creates gate with default config", () => {
      const gate = createConfirmationGate();
      expect(gate.config.requireHighSeverity).toBe(true);
      expect(gate.config.requireMediumSeverity).toBe(true);
      expect(gate.config.requireLowSeverity).toBe(false);
    });

    test("creates gate with custom config", () => {
      const gate = createConfirmationGate({ requireLowSeverity: true });
      expect(gate.config.requireLowSeverity).toBe(true);
    });

    test("requiresConfirmation checks bash commands", () => {
      const gate = createConfirmationGate();
      const result = gate.requiresConfirmation("bash", { command: "rm -rf /tmp" });
      expect(result.required).toBe(true);
    });

    test("requestConfirmation creates pending confirmation", () => {
      const gate = createConfirmationGate();
      const sessionId = uniqueSessionId();
      const pending = gate.requestConfirmation(
        sessionId,
        "bash",
        { command: "rm -rf /tmp" },
        "File deletion",
        "destructive",
        "high",
      );

      expect(pending.id).toBeTruthy();
      expect(pending.sessionId).toBe(sessionId);
      expect(pending.action).toBe("bash");
    });

    test("confirm validates and removes pending confirmation", () => {
      const gate = createConfirmationGate();
      const sessionId = uniqueSessionId();
      const pending = gate.requestConfirmation(
        sessionId,
        "bash",
        { command: "rm -rf /tmp" },
        "File deletion",
        "destructive",
        "high",
      );

      const result = gate.confirm(pending.id, sessionId);
      expect(result.confirmed).toBe(true);

      // Should not be able to confirm again
      const result2 = gate.confirm(pending.id, sessionId);
      expect(result2.confirmed).toBe(false);
    });

    test("confirm rejects wrong session", () => {
      const gate = createConfirmationGate();
      const sessionId1 = uniqueSessionId();
      const sessionId2 = uniqueSessionId();
      const pending = gate.requestConfirmation(
        sessionId1,
        "bash",
        { command: "rm -rf /tmp" },
        "File deletion",
        "destructive",
        "high",
      );

      const result = gate.confirm(pending.id, sessionId2);
      expect(result.confirmed).toBe(false);
      expect(result.reason).toContain("different session");
    });

    test("getPending returns pending confirmations for session", () => {
      const gate = createConfirmationGate();
      const sessionId1 = uniqueSessionId();
      const sessionId2 = uniqueSessionId();

      gate.requestConfirmation(sessionId1, "bash", {}, "Test1", "destructive", "high");
      gate.requestConfirmation(sessionId1, "bash", {}, "Test2", "destructive", "high");
      gate.requestConfirmation(sessionId2, "bash", {}, "Test3", "destructive", "high");

      const pending = gate.getPending(sessionId1);
      expect(pending.length).toBe(2);
    });

    test("cancel removes pending confirmation", () => {
      const gate = createConfirmationGate();
      const sessionId = uniqueSessionId();
      const pending = gate.requestConfirmation(
        sessionId,
        "bash",
        {},
        "Test",
        "destructive",
        "high",
      );

      expect(gate.cancel(pending.id)).toBe(true);
      expect(gate.getPending(sessionId).length).toBe(0);
    });
  });
});

// =============================================================================
// Tool Policy Integration Tests
// =============================================================================

describe("tool-policy integration", () => {
  describe("createToolPolicy", () => {
    test("creates policy with default config", () => {
      const policy = createToolPolicy();
      expect(policy.config.enableCapabilityChecks).toBe(true);
      expect(policy.config.enableRateLimiting).toBe(true);
    });

    test("check validates all policies", () => {
      // Disable schema validation to test policy logic
      const policy = createToolPolicy({ enableSchemaValidation: false });
      const sessionId = uniqueSessionId();
      const result = policy.check(sessionId, "main-standard", "bash", "bash-sandboxed", {
        command: "ls -la",
      });

      expect(result.allowed).toBe(true);
    });

    test("check blocks denied capabilities", () => {
      const policy = createToolPolicy({ enableSchemaValidation: false });
      const sessionId = uniqueSessionId();
      const result = policy.check(sessionId, "guest", "bash", "bash-unrestricted", {
        command: "ls -la",
      });

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("denied");
    });

    test("check requires confirmation for destructive commands", () => {
      const policy = createToolPolicy({ enableSchemaValidation: false });
      const sessionId = uniqueSessionId();
      const result = policy.check(sessionId, "main-elevated", "bash", "bash-unrestricted", {
        command: "rm -rf /tmp/test",
      });

      expect(result.allowed).toBe(true);
      expect(result.requiresConfirmation).toBe(true);
      expect(result.confirmationDetails?.category).toBe("destructive");
    });

    test("check enforces rate limits", () => {
      const policy = createToolPolicy({
        enableSchemaValidation: false,
        rateLimits: { maxToolCallsPerMinute: 2 },
      });
      const sessionId = uniqueSessionId();

      // Make 2 calls (at limit)
      policy.check(sessionId, "main-standard", "bash", "bash-sandboxed", { command: "ls" });
      policy.recordExecution(sessionId);
      policy.check(sessionId, "main-standard", "bash", "bash-sandboxed", { command: "ls" });
      policy.recordExecution(sessionId);

      // 3rd call should be blocked (policy.check returns allowed=false, doesn't throw)
      const result = policy.check(sessionId, "main-standard", "bash", "bash-sandboxed", {
        command: "ls",
      });
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("Rate limit exceeded");
    });

    test("check can be disabled selectively", () => {
      const policy = createToolPolicy({
        enableCapabilityChecks: false,
        enableSchemaValidation: false,
      });
      const sessionId = uniqueSessionId();

      // Should allow even denied capabilities
      const result = policy.check(sessionId, "guest", "bash", "bash-unrestricted", {
        command: "ls",
      });

      expect(result.allowed).toBe(true);
    });
  });
});
