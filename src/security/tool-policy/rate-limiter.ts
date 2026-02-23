/**
 * Rate Limiter for Tool Execution
 *
 * Implements per-session rate limiting to prevent abuse and
 * enforce resource usage quotas.
 *
 * @module security/tool-policy/rate-limiter
 */

/**
 * Rate limit configuration
 */
export interface RateLimitConfig {
  /** Maximum tool calls per hour */
  maxToolCallsPerHour: number;
  /** Maximum tool calls per minute (burst protection) */
  maxToolCallsPerMinute: number;
  /** Maximum cron jobs per session */
  maxCronJobsPerSession: number;
  /** Maximum webhooks per session */
  maxWebhooksPerSession: number;
  /** Maximum daily token budget in USD */
  maxDailyTokenBudgetUSD: number;
  /** Maximum concurrent tool executions */
  maxConcurrentExecutions: number;
  /** Window size in milliseconds for sliding window */
  windowSizeMs: number;
}

/**
 * Default rate limit configuration
 */
export const DEFAULT_RATE_LIMITS: RateLimitConfig = {
  maxToolCallsPerHour: 100,
  maxToolCallsPerMinute: 20,
  maxCronJobsPerSession: 10,
  maxWebhooksPerSession: 5,
  maxDailyTokenBudgetUSD: 5.0,
  maxConcurrentExecutions: 5,
  windowSizeMs: 60 * 60 * 1000, // 1 hour
};

/**
 * Rate limit error types
 */
export class RateLimitError extends Error {
  public readonly type: "hourly" | "minute" | "daily" | "concurrent" | "quota";
  public readonly limit: number;
  public readonly current: number;
  public readonly retryAfterMs: number;

  constructor(
    message: string,
    type: RateLimitError["type"],
    limit: number,
    current: number,
    retryAfterMs: number,
  ) {
    super(message);
    this.name = "RateLimitError";
    this.type = type;
    this.limit = limit;
    this.current = current;
    this.retryAfterMs = retryAfterMs;
  }
}

/**
 * Quota exceeded error for resource limits
 */
export class QuotaExceededError extends Error {
  public readonly resource: "cron" | "webhook" | "budget";
  public readonly limit: number;
  public readonly current: number;

  constructor(
    message: string,
    resource: QuotaExceededError["resource"],
    limit: number,
    current: number,
  ) {
    super(message);
    this.name = "QuotaExceededError";
    this.resource = resource;
    this.limit = limit;
    this.current = current;
  }
}

/**
 * Usage record for tracking rate limits
 */
interface UsageRecord {
  /** Timestamps of tool calls (for sliding window) */
  toolCallTimestamps: number[];
  /** Number of active cron jobs */
  cronJobCount: number;
  /** Number of active webhooks */
  webhookCount: number;
  /** Daily token spend in USD */
  dailyTokenSpendUSD: number;
  /** Date of last reset (YYYY-MM-DD) */
  lastResetDate: string;
  /** Currently executing tools */
  concurrentExecutions: number;
}

/**
 * Get current date string for daily reset
 */
function getCurrentDateString(): string {
  return new Date().toISOString().split("T")[0];
}

/**
 * Get or create usage record for a session
 */
function getUsageRecord(sessionUsage: Map<string, UsageRecord>, sessionId: string): UsageRecord {
  let record = sessionUsage.get(sessionId);
  const today = getCurrentDateString();

  if (!record) {
    record = {
      toolCallTimestamps: [],
      cronJobCount: 0,
      webhookCount: 0,
      dailyTokenSpendUSD: 0,
      lastResetDate: today,
      concurrentExecutions: 0,
    };
    sessionUsage.set(sessionId, record);
  }

  // Reset daily counters if needed
  if (record.lastResetDate !== today) {
    record.dailyTokenSpendUSD = 0;
    record.lastResetDate = today;
  }

  return record;
}

/**
 * Clean up old timestamps from the sliding window
 */
function cleanupOldTimestamps(record: UsageRecord, windowMs: number): void {
  const cutoff = Date.now() - windowMs;
  record.toolCallTimestamps = record.toolCallTimestamps.filter((ts) => ts > cutoff);
}

/**
 * Rate limiter result
 */
export interface RateLimitResult {
  /** Whether the request is allowed */
  allowed: boolean;
  /** Current usage counts */
  usage: {
    toolCallsLastHour: number;
    toolCallsLastMinute: number;
    cronJobs: number;
    webhooks: number;
    dailySpendUSD: number;
    concurrentExecutions: number;
  };
  /** Remaining quota */
  remaining: {
    toolCallsThisHour: number;
    toolCallsThisMinute: number;
    cronJobs: number;
    webhooks: number;
    dailyBudgetUSD: number;
  };
  /** Time until limit resets (ms) */
  resetInMs: number;
}

/**
 * Create a rate limiter for a session
 */
export function createRateLimiter(config: Partial<RateLimitConfig> = {}) {
  const cfg = { ...DEFAULT_RATE_LIMITS, ...config };
  // Each rate limiter instance has its own storage
  const sessionUsage = new Map<string, UsageRecord>();

  return {
    /**
     * Check if a tool call is allowed
     *
     * @param sessionId - Session identifier
     * @throws RateLimitError if rate limit exceeded
     */
    checkToolCall(sessionId: string): RateLimitResult {
      const record = getUsageRecord(sessionUsage, sessionId);
      const now = Date.now();

      // Cleanup old timestamps
      cleanupOldTimestamps(record, cfg.windowSizeMs);

      // Count calls in last minute
      const minuteAgo = now - 60 * 1000;
      const callsLastMinute = record.toolCallTimestamps.filter((ts) => ts > minuteAgo).length;

      // Count calls in last hour
      const hourAgo = now - 60 * 60 * 1000;
      const callsLastHour = record.toolCallTimestamps.filter((ts) => ts > hourAgo).length;

      // Calculate oldest timestamp to determine reset time
      const oldestInWindow =
        record.toolCallTimestamps.length > 0 ? Math.min(...record.toolCallTimestamps) : now;
      const resetInMs = Math.max(0, oldestInWindow + cfg.windowSizeMs - now);

      const result: RateLimitResult = {
        allowed: true,
        usage: {
          toolCallsLastHour: callsLastHour,
          toolCallsLastMinute: callsLastMinute,
          cronJobs: record.cronJobCount,
          webhooks: record.webhookCount,
          dailySpendUSD: record.dailyTokenSpendUSD,
          concurrentExecutions: record.concurrentExecutions,
        },
        remaining: {
          toolCallsThisHour: Math.max(0, cfg.maxToolCallsPerHour - callsLastHour),
          toolCallsThisMinute: Math.max(0, cfg.maxToolCallsPerMinute - callsLastMinute),
          cronJobs: Math.max(0, cfg.maxCronJobsPerSession - record.cronJobCount),
          webhooks: Math.max(0, cfg.maxWebhooksPerSession - record.webhookCount),
          dailyBudgetUSD: Math.max(0, cfg.maxDailyTokenBudgetUSD - record.dailyTokenSpendUSD),
        },
        resetInMs,
      };

      // Check minute limit (burst protection)
      if (callsLastMinute >= cfg.maxToolCallsPerMinute) {
        result.allowed = false;
        throw new RateLimitError(
          `Rate limit exceeded: ${callsLastMinute}/${cfg.maxToolCallsPerMinute} calls per minute`,
          "minute",
          cfg.maxToolCallsPerMinute,
          callsLastMinute,
          60 * 1000, // Wait 1 minute
        );
      }

      // Check hourly limit
      if (callsLastHour >= cfg.maxToolCallsPerHour) {
        result.allowed = false;
        throw new RateLimitError(
          `Rate limit exceeded: ${callsLastHour}/${cfg.maxToolCallsPerHour} calls per hour`,
          "hourly",
          cfg.maxToolCallsPerHour,
          callsLastHour,
          resetInMs,
        );
      }

      // Check concurrent executions
      if (record.concurrentExecutions >= cfg.maxConcurrentExecutions) {
        result.allowed = false;
        throw new RateLimitError(
          `Too many concurrent executions: ${record.concurrentExecutions}/${cfg.maxConcurrentExecutions}`,
          "concurrent",
          cfg.maxConcurrentExecutions,
          record.concurrentExecutions,
          1000, // Wait 1 second
        );
      }

      return result;
    },

    /**
     * Record a tool call
     */
    recordToolCall(sessionId: string): void {
      const record = getUsageRecord(sessionUsage, sessionId);
      record.toolCallTimestamps.push(Date.now());
    },

    /**
     * Start a concurrent execution
     */
    startExecution(sessionId: string): void {
      const record = getUsageRecord(sessionUsage, sessionId);
      record.concurrentExecutions++;
    },

    /**
     * End a concurrent execution
     */
    endExecution(sessionId: string): void {
      const record = getUsageRecord(sessionUsage, sessionId);
      record.concurrentExecutions = Math.max(0, record.concurrentExecutions - 1);
    },

    /**
     * Check if a cron job can be created
     *
     * @throws QuotaExceededError if quota exceeded
     */
    checkCronJob(sessionId: string): void {
      const record = getUsageRecord(sessionUsage, sessionId);
      if (record.cronJobCount >= cfg.maxCronJobsPerSession) {
        throw new QuotaExceededError(
          `Cron job quota exceeded: ${record.cronJobCount}/${cfg.maxCronJobsPerSession}`,
          "cron",
          cfg.maxCronJobsPerSession,
          record.cronJobCount,
        );
      }
    },

    /**
     * Record a cron job creation
     */
    recordCronJobCreated(sessionId: string): void {
      const record = getUsageRecord(sessionUsage, sessionId);
      record.cronJobCount++;
    },

    /**
     * Record a cron job deletion
     */
    recordCronJobDeleted(sessionId: string): void {
      const record = getUsageRecord(sessionUsage, sessionId);
      record.cronJobCount = Math.max(0, record.cronJobCount - 1);
    },

    /**
     * Check if a webhook can be created
     *
     * @throws QuotaExceededError if quota exceeded
     */
    checkWebhook(sessionId: string): void {
      const record = getUsageRecord(sessionUsage, sessionId);
      if (record.webhookCount >= cfg.maxWebhooksPerSession) {
        throw new QuotaExceededError(
          `Webhook quota exceeded: ${record.webhookCount}/${cfg.maxWebhooksPerSession}`,
          "webhook",
          cfg.maxWebhooksPerSession,
          record.webhookCount,
        );
      }
    },

    /**
     * Record a webhook creation
     */
    recordWebhookCreated(sessionId: string): void {
      const record = getUsageRecord(sessionUsage, sessionId);
      record.webhookCount++;
    },

    /**
     * Record a webhook deletion
     */
    recordWebhookDeleted(sessionId: string): void {
      const record = getUsageRecord(sessionUsage, sessionId);
      record.webhookCount = Math.max(0, record.webhookCount - 1);
    },

    /**
     * Check if token spend is within budget
     *
     * @param costUSD - Cost of the operation in USD
     * @throws QuotaExceededError if budget exceeded
     */
    checkTokenBudget(sessionId: string, costUSD: number): void {
      const record = getUsageRecord(sessionUsage, sessionId);
      if (record.dailyTokenSpendUSD + costUSD > cfg.maxDailyTokenBudgetUSD) {
        throw new QuotaExceededError(
          `Daily token budget exceeded: $${record.dailyTokenSpendUSD.toFixed(2)} + $${costUSD.toFixed(2)} > $${cfg.maxDailyTokenBudgetUSD.toFixed(2)}`,
          "budget",
          cfg.maxDailyTokenBudgetUSD,
          record.dailyTokenSpendUSD,
        );
      }
    },

    /**
     * Record token spend
     */
    recordTokenSpend(sessionId: string, costUSD: number): void {
      const record = getUsageRecord(sessionUsage, sessionId);
      record.dailyTokenSpendUSD += costUSD;
    },

    /**
     * Get current usage for a session
     */
    getUsage(sessionId: string): RateLimitResult["usage"] {
      const record = getUsageRecord(sessionUsage, sessionId);
      const now = Date.now();

      cleanupOldTimestamps(record, cfg.windowSizeMs);

      const minuteAgo = now - 60 * 1000;
      const hourAgo = now - 60 * 60 * 1000;

      return {
        toolCallsLastHour: record.toolCallTimestamps.filter((ts) => ts > hourAgo).length,
        toolCallsLastMinute: record.toolCallTimestamps.filter((ts) => ts > minuteAgo).length,
        cronJobs: record.cronJobCount,
        webhooks: record.webhookCount,
        dailySpendUSD: record.dailyTokenSpendUSD,
        concurrentExecutions: record.concurrentExecutions,
      };
    },

    /**
     * Reset usage for a session
     */
    resetUsage(sessionId: string): void {
      sessionUsage.delete(sessionId);
    },

    /**
     * Get configuration
     */
    get config(): RateLimitConfig {
      return { ...cfg };
    },
  };
}

/**
 * Default rate limiter instance
 */
export const defaultRateLimiter = createRateLimiter();

/**
 * Convenience function to check and record a tool call
 */
export function checkAndRecordToolCall(sessionId: string): RateLimitResult {
  const result = defaultRateLimiter.checkToolCall(sessionId);
  defaultRateLimiter.recordToolCall(sessionId);
  return result;
}
