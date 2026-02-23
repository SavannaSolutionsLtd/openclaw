import { describe, expect, test, vi } from "vitest";
import {
  createAuditEvent,
  sha256,
  hashArgs,
  hashEvent,
  inferSeverity,
  createHashChain,
  createAuditLogger,
  type AuditEvent,
  type LogShipper,
} from "./index.js";

// =============================================================================
// Structured Event Tests
// =============================================================================

describe("createAuditEvent", () => {
  test("creates event with required fields", () => {
    const event = createAuditEvent({
      sessionId: "sess-1",
      channel: "main",
      toolName: "bash",
      outcome: "success",
    });

    expect(event.timestamp).toBeTruthy();
    expect(event.eventId).toMatch(/^[0-9a-f-]{36}$/);
    expect(event.sessionId).toBe("sess-1");
    expect(event.channel).toBe("main");
    expect(event.toolName).toBe("bash");
    expect(event.outcome).toBe("success");
    expect(event.argsHash).toBeTruthy();
  });

  test("includes optional fields when provided", () => {
    const event = createAuditEvent({
      sessionId: "sess-1",
      channel: "main",
      toolName: "bash",
      outcome: "error",
      userId: "user-1",
      previousHash: "abc123",
      metadata: { key: "value" },
      durationMs: 150,
      errorMessage: "command failed",
    });

    expect(event.userId).toBe("user-1");
    expect(event.previousHash).toBe("abc123");
    expect(event.metadata).toEqual({ key: "value" });
    expect(event.durationMs).toBe(150);
    expect(event.errorMessage).toBe("command failed");
  });

  test("auto-infers error severity for error outcome", () => {
    const event = createAuditEvent({
      sessionId: "sess-1",
      channel: "main",
      toolName: "bash",
      outcome: "error",
    });
    expect(event.severity).toBe("error");
  });

  test("uses info severity for success outcome", () => {
    const event = createAuditEvent({
      sessionId: "sess-1",
      channel: "main",
      toolName: "bash",
      outcome: "success",
    });
    expect(event.severity).toBe("info");
  });

  test("respects explicit severity override", () => {
    const event = createAuditEvent({
      sessionId: "sess-1",
      channel: "main",
      toolName: "bash",
      outcome: "success",
      severity: "critical",
    });
    expect(event.severity).toBe("critical");
  });
});

describe("sha256", () => {
  test("produces consistent hashes", () => {
    const hash1 = sha256("hello");
    const hash2 = sha256("hello");
    expect(hash1).toBe(hash2);
  });

  test("produces different hashes for different inputs", () => {
    const hash1 = sha256("hello");
    const hash2 = sha256("world");
    expect(hash1).not.toBe(hash2);
  });

  test("produces 64-character hex string", () => {
    const hash = sha256("test");
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("hashArgs", () => {
  test("hashes empty args", () => {
    const hash = hashArgs();
    expect(hash).toBeTruthy();
    expect(hash).toBe(hashArgs({}));
  });

  test("produces consistent hashes for same args", () => {
    const args = { command: "ls", timeout: 1000 };
    expect(hashArgs(args)).toBe(hashArgs(args));
  });

  test("produces same hash regardless of key order", () => {
    const args1 = { a: 1, b: 2 };
    const args2 = { b: 2, a: 1 };
    expect(hashArgs(args1)).toBe(hashArgs(args2));
  });

  test("produces different hashes for different args", () => {
    expect(hashArgs({ a: 1 })).not.toBe(hashArgs({ a: 2 }));
  });
});

describe("hashEvent", () => {
  test("produces consistent hashes", () => {
    const event = createAuditEvent({
      sessionId: "sess-1",
      channel: "main",
      toolName: "bash",
      outcome: "success",
    });
    expect(hashEvent(event)).toBe(hashEvent(event));
  });

  test("produces different hashes for different events", () => {
    const event1 = createAuditEvent({
      sessionId: "sess-1",
      channel: "main",
      toolName: "bash",
      outcome: "success",
    });
    const event2 = createAuditEvent({
      sessionId: "sess-2",
      channel: "main",
      toolName: "bash",
      outcome: "success",
    });
    expect(hashEvent(event1)).not.toBe(hashEvent(event2));
  });
});

describe("inferSeverity", () => {
  test("returns error for error outcome", () => {
    expect(inferSeverity("error", "bash")).toBe("error");
  });

  test("returns warning for blocked outcome", () => {
    expect(inferSeverity("blocked", "bash")).toBe("warning");
  });

  test("returns warning for high-risk tools", () => {
    expect(inferSeverity("success", "bash")).toBe("warning");
    expect(inferSeverity("success", "write")).toBe("warning");
    expect(inferSeverity("success", "delete")).toBe("warning");
  });

  test("returns info for low-risk tools", () => {
    expect(inferSeverity("success", "read")).toBe("info");
    expect(inferSeverity("success", "glob")).toBe("info");
  });
});

// =============================================================================
// Hash Chain Tests
// =============================================================================

describe("createHashChain", () => {
  test("starts with no last hash", () => {
    const chain = createHashChain();
    expect(chain.getLastHash()).toBeUndefined();
    expect(chain.getLength()).toBe(0);
  });

  test("appends events and tracks hashes", () => {
    const chain = createHashChain();
    const event = createAuditEvent({
      sessionId: "sess-1",
      channel: "main",
      toolName: "bash",
      outcome: "success",
    });

    const hash = chain.append(event);
    expect(hash).toBeTruthy();
    expect(chain.getLastHash()).toBe(hash);
    expect(chain.getLength()).toBe(1);
  });

  test("links events via previousHash", () => {
    const chain = createHashChain();

    const event1 = createAuditEvent({
      sessionId: "sess-1",
      channel: "main",
      toolName: "bash",
      outcome: "success",
    });
    chain.append(event1);
    const firstHash = chain.getLastHash();

    const event2 = createAuditEvent({
      sessionId: "sess-1",
      channel: "main",
      toolName: "read",
      outcome: "success",
    });
    chain.append(event2);

    expect(event2.previousHash).toBe(firstHash);
    expect(chain.getLength()).toBe(2);
  });

  test("verifies valid chain", () => {
    const chain = createHashChain();
    const events: AuditEvent[] = [];

    for (let i = 0; i < 5; i++) {
      const event = createAuditEvent({
        sessionId: "sess-1",
        channel: "main",
        toolName: `tool-${i}`,
        outcome: "success",
      });
      chain.append(event);
      events.push(event);
    }

    const result = chain.verify(events);
    expect(result.valid).toBe(true);
    expect(result.eventsVerified).toBe(5);
    expect(result.brokenAtIndex).toBe(-1);
  });

  test("detects tampered event", () => {
    const chain = createHashChain();
    const events: AuditEvent[] = [];

    for (let i = 0; i < 3; i++) {
      const event = createAuditEvent({
        sessionId: "sess-1",
        channel: "main",
        toolName: `tool-${i}`,
        outcome: "success",
      });
      chain.append(event);
      events.push(event);
    }

    // Tamper with the second event
    events[1].previousHash = "tampered-hash";

    const result = chain.verify(events);
    expect(result.valid).toBe(false);
    expect(result.brokenAtIndex).toBe(1);
  });

  test("verifies empty chain", () => {
    const chain = createHashChain();
    const result = chain.verify([]);
    expect(result.valid).toBe(true);
    expect(result.eventsVerified).toBe(0);
  });

  test("reset clears chain state", () => {
    const chain = createHashChain();
    const event = createAuditEvent({
      sessionId: "sess-1",
      channel: "main",
      toolName: "bash",
      outcome: "success",
    });
    chain.append(event);
    expect(chain.getLength()).toBe(1);

    chain.reset();
    expect(chain.getLength()).toBe(0);
    expect(chain.getLastHash()).toBeUndefined();
  });
});

// =============================================================================
// Audit Logger Integration Tests
// =============================================================================

describe("createAuditLogger", () => {
  function createMockShipper(): LogShipper & { events: AuditEvent[] } {
    const events: AuditEvent[] = [];
    return {
      events,
      async ship(event: AuditEvent): Promise<void> {
        events.push(event);
      },
    };
  }

  test("logs events to shipper", async () => {
    const shipper = createMockShipper();
    const logger = createAuditLogger({ customShipper: shipper });

    await logger.log({
      sessionId: "sess-1",
      channel: "main",
      toolName: "bash",
      outcome: "success",
    });

    expect(shipper.events).toHaveLength(1);
    expect(shipper.events[0].toolName).toBe("bash");
  });

  test("returns event ID", async () => {
    const shipper = createMockShipper();
    const logger = createAuditLogger({ customShipper: shipper });

    const eventId = await logger.log({
      sessionId: "sess-1",
      channel: "main",
      toolName: "bash",
      outcome: "success",
    });

    expect(eventId).toMatch(/^[0-9a-f-]{36}$/);
  });

  test("maintains hash chain", async () => {
    const shipper = createMockShipper();
    const logger = createAuditLogger({ customShipper: shipper, hashChain: true });

    await logger.log({
      sessionId: "sess-1",
      channel: "main",
      toolName: "bash",
      outcome: "success",
    });
    await logger.log({
      sessionId: "sess-1",
      channel: "main",
      toolName: "read",
      outcome: "success",
    });

    expect(logger.getChainLength()).toBe(2);
    const verification = logger.verifyChain();
    expect(verification.valid).toBe(true);
  });

  test("does not log when disabled", async () => {
    const shipper = createMockShipper();
    const logger = createAuditLogger({ customShipper: shipper, enabled: false });

    const eventId = await logger.log({
      sessionId: "sess-1",
      channel: "main",
      toolName: "bash",
      outcome: "success",
    });

    expect(eventId).toBe("");
    expect(shipper.events).toHaveLength(0);
  });

  test("logToolCall convenience method", async () => {
    const shipper = createMockShipper();
    const logger = createAuditLogger({ customShipper: shipper });

    await logger.logToolCall({
      sessionId: "sess-1",
      toolName: "bash",
      args: { command: "ls" },
      outcome: "success",
      durationMs: 50,
    });

    expect(shipper.events).toHaveLength(1);
    expect(shipper.events[0].toolName).toBe("bash");
    expect(shipper.events[0].durationMs).toBe(50);
  });

  test("logSecurityEvent convenience method", async () => {
    const shipper = createMockShipper();
    const logger = createAuditLogger({ customShipper: shipper });

    await logger.logSecurityEvent({
      sessionId: "sess-1",
      toolName: "bash",
      reason: "Rate limit exceeded",
    });

    expect(shipper.events).toHaveLength(1);
    expect(shipper.events[0].outcome).toBe("blocked");
    expect(shipper.events[0].severity).toBe("warning");
    expect(shipper.events[0].channel).toBe("security");
  });

  test("getEvents returns all logged events", async () => {
    const shipper = createMockShipper();
    const logger = createAuditLogger({ customShipper: shipper });

    await logger.log({ sessionId: "s1", channel: "main", toolName: "a", outcome: "success" });
    await logger.log({ sessionId: "s1", channel: "main", toolName: "b", outcome: "success" });
    await logger.log({ sessionId: "s1", channel: "main", toolName: "c", outcome: "error" });

    const events = logger.getEvents();
    expect(events).toHaveLength(3);
  });

  test("flush delegates to shipper", async () => {
    const flushFn = vi.fn();
    const shipper: LogShipper = {
      async ship() {},
      flush: flushFn,
    };
    const logger = createAuditLogger({ customShipper: shipper });

    await logger.flush();
    expect(flushFn).toHaveBeenCalled();
  });

  test("close delegates to shipper", async () => {
    const closeFn = vi.fn();
    const shipper: LogShipper = {
      async ship() {},
      close: closeFn,
    };
    const logger = createAuditLogger({ customShipper: shipper });

    await logger.close();
    expect(closeFn).toHaveBeenCalled();
  });
});
