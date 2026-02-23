/**
 * Structured Audit Event
 *
 * Defines the schema for audit log events with tamper-evident
 * hash chaining for integrity verification.
 *
 * @module security/audit-logger/structured-event
 */

import { randomUUID } from "node:crypto";
import { createHash } from "node:crypto";

/**
 * Audit event outcome types
 */
export type AuditOutcome = "success" | "blocked" | "error";

/**
 * Audit event severity levels
 */
export type AuditSeverity = "info" | "warning" | "error" | "critical";

/**
 * Structured audit event
 */
export interface AuditEvent {
  /** ISO 8601 timestamp */
  timestamp: string;
  /** UUID v4 event identifier */
  eventId: string;
  /** Session identifier */
  sessionId: string;
  /** Channel or context (e.g. "main", "webhook", "cron") */
  channel: string;
  /** Tool or action name */
  toolName: string;
  /** SHA-256 hash of sanitized arguments */
  argsHash: string;
  /** Outcome of the action */
  outcome: AuditOutcome;
  /** Severity level */
  severity: AuditSeverity;
  /** User identifier (optional) */
  userId?: string;
  /** Previous event hash for chain integrity */
  previousHash?: string;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
  /** Duration in milliseconds (optional) */
  durationMs?: number;
  /** Error message if outcome is "error" or "blocked" */
  errorMessage?: string;
}

/**
 * Parameters for creating an audit event
 */
export interface CreateAuditEventParams {
  sessionId: string;
  channel: string;
  toolName: string;
  args?: Record<string, unknown>;
  outcome: AuditOutcome;
  severity?: AuditSeverity;
  userId?: string;
  previousHash?: string;
  metadata?: Record<string, unknown>;
  durationMs?: number;
  errorMessage?: string;
}

/**
 * Compute SHA-256 hash of a string
 */
export function sha256(data: string): string {
  return createHash("sha256").update(data).digest("hex");
}

/**
 * Hash tool arguments for audit logging (strips sensitive values)
 */
export function hashArgs(args?: Record<string, unknown>): string {
  if (!args || Object.keys(args).length === 0) {
    return sha256("{}");
  }
  // Serialize with sorted keys for deterministic hashing
  const sorted = JSON.stringify(args, Object.keys(args).toSorted());
  return sha256(sorted);
}

/**
 * Compute the hash of an audit event for chain integrity
 */
export function hashEvent(event: AuditEvent): string {
  const payload = [
    event.timestamp,
    event.eventId,
    event.sessionId,
    event.channel,
    event.toolName,
    event.argsHash,
    event.outcome,
    event.previousHash ?? "",
  ].join("|");
  return sha256(payload);
}

/**
 * Create a structured audit event
 */
export function createAuditEvent(params: CreateAuditEventParams): AuditEvent {
  return {
    timestamp: new Date().toISOString(),
    eventId: randomUUID(),
    sessionId: params.sessionId,
    channel: params.channel,
    toolName: params.toolName,
    argsHash: hashArgs(params.args),
    outcome: params.outcome,
    severity: params.severity ?? (params.outcome === "error" ? "error" : "info"),
    userId: params.userId,
    previousHash: params.previousHash,
    metadata: params.metadata,
    durationMs: params.durationMs,
    errorMessage: params.errorMessage,
  };
}

/**
 * Determine severity based on outcome and tool name
 */
export function inferSeverity(outcome: AuditOutcome, toolName: string): AuditSeverity {
  if (outcome === "error") {
    return "error";
  }
  if (outcome === "blocked") {
    return "warning";
  }
  // Elevated severity for destructive tools
  const highRiskTools = new Set(["bash", "write", "edit", "delete"]);
  if (highRiskTools.has(toolName)) {
    return "warning";
  }
  return "info";
}
