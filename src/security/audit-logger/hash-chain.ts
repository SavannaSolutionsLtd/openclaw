/**
 * Hash Chain for Audit Log Integrity
 *
 * Implements an append-only hash chain that links audit events
 * together, making it possible to detect tampering or deletion
 * of log entries.
 *
 * @module security/audit-logger/hash-chain
 */

import { hashEvent, type AuditEvent } from "./structured-event.js";

/**
 * Hash chain verification result
 */
export interface ChainVerificationResult {
  /** Whether the chain is valid */
  valid: boolean;
  /** Number of events verified */
  eventsVerified: number;
  /** Index of first broken link (-1 if valid) */
  brokenAtIndex: number;
  /** Error message if invalid */
  error?: string;
}

/**
 * Create a hash chain tracker
 *
 * Maintains the chain state and provides methods for
 * appending events and verifying chain integrity.
 */
export function createHashChain() {
  let lastHash: string | undefined;
  let chainLength = 0;

  return {
    /**
     * Get the hash of the last event in the chain
     */
    getLastHash(): string | undefined {
      return lastHash;
    },

    /**
     * Get the current chain length
     */
    getLength(): number {
      return chainLength;
    },

    /**
     * Append an event to the chain and return its hash
     *
     * Sets the event's previousHash to the last hash in the chain,
     * then computes and records the new hash.
     */
    append(event: AuditEvent): string {
      event.previousHash = lastHash;
      const eventHash = hashEvent(event);
      lastHash = eventHash;
      chainLength++;
      return eventHash;
    },

    /**
     * Verify a sequence of events forms a valid chain
     *
     * Checks that each event's previousHash matches the hash
     * of the preceding event.
     */
    verify(events: AuditEvent[]): ChainVerificationResult {
      if (events.length === 0) {
        return { valid: true, eventsVerified: 0, brokenAtIndex: -1 };
      }

      let previousHash: string | undefined;

      for (let i = 0; i < events.length; i++) {
        const event = events[i];

        // First event should have no previous hash (or match the chain start)
        if (i === 0) {
          // First event's previousHash is the chain anchor
          previousHash = hashEvent(event);
          continue;
        }

        // Verify the chain link
        if (event.previousHash !== previousHash) {
          return {
            valid: false,
            eventsVerified: i,
            brokenAtIndex: i,
            error: `Chain broken at index ${i}: expected previousHash ${previousHash}, got ${event.previousHash}`,
          };
        }

        previousHash = hashEvent(event);
      }

      return {
        valid: true,
        eventsVerified: events.length,
        brokenAtIndex: -1,
      };
    },

    /**
     * Reset the chain (for testing only)
     */
    reset(): void {
      lastHash = undefined;
      chainLength = 0;
    },
  };
}
