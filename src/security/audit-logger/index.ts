/**
 * Audit Logger
 *
 * Provides structured, tamper-evident audit logging for all tool
 * invocations and security events. Events are linked via hash chain
 * for integrity verification.
 *
 * @module security/audit-logger
 */

export {
  type AuditOutcome,
  type AuditSeverity,
  type AuditEvent,
  type CreateAuditEventParams,
  createAuditEvent,
  sha256,
  hashArgs,
  hashEvent,
  inferSeverity,
} from "./structured-event.js";

export { type ChainVerificationResult, createHashChain } from "./hash-chain.js";

export {
  type LogShipper,
  type ShipperConfig,
  DEFAULT_SHIPPER_CONFIG,
  createFileShipper,
  createConsoleShipper,
  createBufferedShipper,
  createShipper,
} from "./external-shipper.js";

import { createShipper, type LogShipper, type ShipperConfig } from "./external-shipper.js";
import { createHashChain } from "./hash-chain.js";
import { createAuditEvent, hashEvent, type CreateAuditEventParams } from "./structured-event.js";

/**
 * Audit logger configuration
 */
export interface AuditLoggerConfig {
  /** Enable audit logging */
  enabled: boolean;
  /** Enable hash chain integrity */
  hashChain: boolean;
  /** Log shipper configuration */
  shipper: Partial<ShipperConfig>;
  /** Custom shipper instance (overrides shipper config) */
  customShipper?: LogShipper;
}

/**
 * Default audit logger configuration
 */
export const DEFAULT_AUDIT_CONFIG: AuditLoggerConfig = {
  enabled: true,
  hashChain: true,
  shipper: { type: "console" },
};

/**
 * Create an audit logger
 */
export function createAuditLogger(config: Partial<AuditLoggerConfig> = {}) {
  const cfg = { ...DEFAULT_AUDIT_CONFIG, ...config };
  const chain = createHashChain();
  const shipper = cfg.customShipper ?? createShipper(cfg.shipper);
  const events: Array<{ event: import("./structured-event.js").AuditEvent; hash: string }> = [];

  return {
    /**
     * Log an audit event
     */
    async log(params: CreateAuditEventParams): Promise<string> {
      if (!cfg.enabled) {
        return "";
      }

      const event = createAuditEvent({
        ...params,
        previousHash: cfg.hashChain ? chain.getLastHash() : undefined,
      });

      let eventHash = "";
      if (cfg.hashChain) {
        eventHash = chain.append(event);
      } else {
        eventHash = hashEvent(event);
      }

      events.push({ event, hash: eventHash });

      await shipper.ship(event);

      return event.eventId;
    },

    /**
     * Log a tool invocation
     */
    async logToolCall(params: {
      sessionId: string;
      toolName: string;
      args?: Record<string, unknown>;
      outcome: import("./structured-event.js").AuditOutcome;
      channel?: string;
      userId?: string;
      durationMs?: number;
      errorMessage?: string;
    }): Promise<string> {
      return this.log({
        sessionId: params.sessionId,
        channel: params.channel ?? "main",
        toolName: params.toolName,
        args: params.args,
        outcome: params.outcome,
        userId: params.userId,
        durationMs: params.durationMs,
        errorMessage: params.errorMessage,
      });
    },

    /**
     * Log a security event (blocked action)
     */
    async logSecurityEvent(params: {
      sessionId: string;
      toolName: string;
      reason: string;
      channel?: string;
      userId?: string;
      metadata?: Record<string, unknown>;
    }): Promise<string> {
      return this.log({
        sessionId: params.sessionId,
        channel: params.channel ?? "security",
        toolName: params.toolName,
        outcome: "blocked",
        severity: "warning",
        userId: params.userId,
        errorMessage: params.reason,
        metadata: params.metadata,
      });
    },

    /**
     * Get recorded events (for inspection/testing)
     */
    getEvents(): Array<{ event: import("./structured-event.js").AuditEvent; hash: string }> {
      return [...events];
    },

    /**
     * Verify the hash chain integrity
     */
    verifyChain(): import("./hash-chain.js").ChainVerificationResult {
      return chain.verify(events.map((e) => e.event));
    },

    /**
     * Get chain length
     */
    getChainLength(): number {
      return chain.getLength();
    },

    /**
     * Flush any buffered events
     */
    async flush(): Promise<void> {
      if (shipper.flush) {
        await shipper.flush();
      }
    },

    /**
     * Close the logger and release resources
     */
    async close(): Promise<void> {
      if (shipper.close) {
        await shipper.close();
      }
    },
  };
}
