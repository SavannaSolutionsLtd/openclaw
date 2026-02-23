/**
 * External Log Shipper
 *
 * Provides pluggable log shipping to external services for
 * durable, append-only audit trail storage.
 *
 * @module security/audit-logger/external-shipper
 */

import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import type { AuditEvent } from "./structured-event.js";

/**
 * Log shipper interface
 */
export interface LogShipper {
  /** Ship an audit event to the external service */
  ship(event: AuditEvent): Promise<void>;
  /** Flush any buffered events */
  flush?(): Promise<void>;
  /** Close the shipper and release resources */
  close?(): Promise<void>;
}

/**
 * Shipper configuration
 */
export interface ShipperConfig {
  /** Shipper type */
  type: "file" | "console" | "custom";
  /** File path for file shipper */
  filePath?: string;
  /** Batch size for buffered shipping */
  batchSize?: number;
  /** Flush interval in milliseconds */
  flushIntervalMs?: number;
}

/**
 * Default shipper configuration
 */
export const DEFAULT_SHIPPER_CONFIG: ShipperConfig = {
  type: "file",
  filePath: "audit.log",
  batchSize: 10,
  flushIntervalMs: 5000,
};

/**
 * File-based log shipper (append-only)
 *
 * Writes audit events as newline-delimited JSON to a file.
 * Suitable as a fallback when external services are unavailable.
 */
export function createFileShipper(filePath: string): LogShipper {
  let initialized = false;

  async function ensureDirectory(): Promise<void> {
    if (initialized) {
      return;
    }
    const dir = dirname(filePath);
    await mkdir(dir, { recursive: true });
    initialized = true;
  }

  return {
    async ship(event: AuditEvent): Promise<void> {
      await ensureDirectory();
      const line = JSON.stringify(event) + "\n";
      await appendFile(filePath, line, "utf-8");
    },
  };
}

/**
 * Console log shipper (for development/debugging)
 */
export function createConsoleShipper(): LogShipper {
  return {
    async ship(event: AuditEvent): Promise<void> {
      const prefix =
        event.outcome === "error"
          ? "[AUDIT:ERROR]"
          : event.outcome === "blocked"
            ? "[AUDIT:BLOCKED]"
            : "[AUDIT]";
      // eslint-disable-next-line no-console
      console.log(
        `${prefix} ${event.timestamp} ${event.toolName} ${event.outcome} session=${event.sessionId}`,
      );
    },
  };
}

/**
 * Buffered shipper wrapper
 *
 * Batches events and ships them periodically or when the buffer
 * reaches a configured size.
 */
export function createBufferedShipper(
  inner: LogShipper,
  config: { batchSize?: number; flushIntervalMs?: number } = {},
): LogShipper & { flush(): Promise<void>; close(): Promise<void> } {
  const batchSize = config.batchSize ?? 10;
  const flushIntervalMs = config.flushIntervalMs ?? 5000;
  const buffer: AuditEvent[] = [];
  let timer: ReturnType<typeof setInterval> | undefined;

  async function flushBuffer(): Promise<void> {
    if (buffer.length === 0) {
      return;
    }
    const batch = buffer.splice(0, buffer.length);
    for (const event of batch) {
      await inner.ship(event);
    }
  }

  // Start periodic flush
  if (flushIntervalMs > 0) {
    timer = setInterval(() => {
      void flushBuffer();
    }, flushIntervalMs);
    // Unref to not prevent process exit
    if (typeof timer === "object" && "unref" in timer) {
      timer.unref();
    }
  }

  return {
    async ship(event: AuditEvent): Promise<void> {
      buffer.push(event);
      if (buffer.length >= batchSize) {
        await flushBuffer();
      }
    },

    async flush(): Promise<void> {
      await flushBuffer();
    },

    async close(): Promise<void> {
      if (timer) {
        clearInterval(timer);
        timer = undefined;
      }
      await flushBuffer();
      if (inner.close) {
        await inner.close();
      }
    },
  };
}

/**
 * Create a log shipper from configuration
 */
export function createShipper(config: Partial<ShipperConfig> = {}): LogShipper {
  const cfg = { ...DEFAULT_SHIPPER_CONFIG, ...config };

  switch (cfg.type) {
    case "file":
      return createFileShipper(cfg.filePath ?? "audit.log");
    case "console":
      return createConsoleShipper();
    default:
      return createConsoleShipper();
  }
}
