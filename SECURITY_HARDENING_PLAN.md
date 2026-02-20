# OpenClaw Security Hardening Implementation Plan

**Based on:** Security Hardening & Threat Assessment Report v1.0 (Feb 19, 2026)
**Branch:** `claude/agent-security-analysis-8yTJ3`
**Status:** Planning Phase

---

## Executive Summary

This plan implements the security hardening recommendations from the 43-page threat assessment report. The implementation is organized into **8 independent modules** designed for:

1. **Minimal upstream conflict** - Most code lives in `src/security/`
2. **Easy rebasing** - Changes to existing files are surgical and well-documented
3. **Incremental deployment** - Each module can be enabled/disabled independently
4. **Testable isolation** - Each module has dedicated test coverage

### Risk Summary (Current State)

| Finding                                          | Risk         | Status                            |
| ------------------------------------------------ | ------------ | --------------------------------- |
| F-01: Unrestricted Shell on Main Session         | 5 - Critical | OPEN                              |
| F-02: Cloudflare Tunnel Auth Gap                 | 5 - Critical | OPEN                              |
| F-03: Prompt Injection via All Channels          | 4 - High     | **PARTIAL** (channel-sanitize.ts) |
| F-04: Secrets Exposure via Environment Variables | 4 - High     | **PARTIAL** (safe-env.ts)         |
| F-05: Browser CDP Attack Surface                 | 4 - High     | OPEN                              |
| F-06: ClawHub Supply Chain Risk                  | 3 - Medium   | OPEN                              |
| F-07: Audit Logging Not Immutable                | 3 - Medium   | OPEN                              |
| F-08: Agent-to-Agent Lateral Movement            | 3 - Medium   | OPEN                              |

---

## Module Architecture

```
src/security/
├── index.ts                    # Central exports
├── channel-sanitize.ts         # [DONE] Prompt injection sanitization
├── safe-env.ts                 # [DONE] Environment variable filtering
├── prompt-sanitizer/           # Module 1: Inbound message sanitization
│   ├── index.ts
│   ├── patterns.ts             # Injection pattern detection
│   ├── wrapper.ts              # XML untrusted-input framing
│   └── middleware.ts           # Express/WS middleware
├── output-redaction/           # Module 2: Outbound secret redaction
│   ├── index.ts
│   ├── patterns.ts             # API key/token patterns
│   ├── entropy.ts              # High-entropy string detection
│   └── filter.ts               # Redaction filter
├── tool-policy/                # Module 3: Tool execution policy
│   ├── index.ts
│   ├── schema-validator.ts     # JSON schema enforcement
│   ├── rate-limiter.ts         # Per-session rate limiting
│   ├── capability-matrix.ts    # RBAC by session type
│   └── confirmation-gate.ts    # Destructive action confirmation
├── browser-guard/              # Module 4: Browser CDP protection
│   ├── index.ts
│   ├── url-blocklist.ts        # SSRF prevention
│   └── navigation-policy.ts    # Link-local/RFC-1918 blocking
├── audit-logger/               # Module 5: Immutable audit logging
│   ├── index.ts
│   ├── structured-event.ts     # Event schema
│   ├── external-shipper.ts     # CloudWatch/Datadog/Loki
│   └── hash-chain.ts           # Tamper-evident chaining
├── skill-gate/                 # Module 6: ClawHub security
│   ├── index.ts
│   ├── approval-flow.ts        # Owner approval requirement
│   └── hash-verify.ts          # SHA-256 verification
├── session-security/           # Module 7: Session/token security
│   ├── index.ts
│   ├── token-store.ts          # In-memory + Redis token store
│   ├── invalidation.ts         # Logout invalidation
│   └── ttl-enforcement.ts      # 8-hour max TTL
└── webhook-auth/               # Module 8: Webhook HMAC
    ├── index.ts
    ├── hmac-verify.ts          # HMAC-SHA256 verification
    └── ip-allowlist.ts         # Source IP validation
```

---

## Module 1: Prompt Injection Sanitizer (CRITICAL)

**Priority:** Phase 1 (Days 0-7)
**Risk Reduction:** 5 - Critical
**Requirements:** REQ-04, CH-01
**Addresses:** F-03, AC-01, AC-04, AC-11, LLM01

### Files to Create

```
src/security/prompt-sanitizer/
├── index.ts
├── patterns.ts
├── wrapper.ts
└── middleware.ts
```

### Integration Points (Minimal Changes)

| File                             | Change Type         | Description                    |
| -------------------------------- | ------------------- | ------------------------------ |
| `src/auto-reply/reply/groups.ts` | Import + call       | Wrap inbound messages          |
| `src/gateway/server-http.ts`     | Import + middleware | Add sanitizer to WS handler    |
| Channel handlers (5 files)       | Import + call       | Apply before context injection |

### Detection Patterns

````typescript
// patterns.ts - Injection signatures to detect
export const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?previous\s+instructions?/i,
  /disregard\s+(all\s+)?prior\s+/i,
  /new\s+instruction[s]?:/i,
  /system\s*:\s*/i,
  /\[INST\]/i, // Llama-style injection
  /<<SYS>>/i, // System prompt injection
  /```system/i, // Markdown system block
  /\u202e/, // RTL override (unicode obfuscation)
  /\u200b/, // Zero-width space
];

// Base64 payload detection
export function containsBase64Payload(text: string): boolean;
````

### Wrapper Format

```typescript
// wrapper.ts - Untrusted content framing
export function wrapUntrustedInput(content: string, source: string): string {
  return `<untrusted-input source="${source}" timestamp="${Date.now()}">
${escapeXml(content)}
</untrusted-input>`;
}
```

### Tests

```
test/security/prompt-sanitizer.test.ts
- 20 known injection payloads → all flagged
- 10 benign messages → 0 false positives
- Base64-encoded injections → detected
- Unicode obfuscation → detected
```

---

## Module 2: Output Redaction Filter (CRITICAL)

**Priority:** Phase 1 (Days 0-7)
**Risk Reduction:** 4 - High
**Requirements:** REQ-12, CH-04
**Addresses:** F-04, AC-02, AC-06, AC-24, LLM06

### Files to Create

```
src/security/output-redaction/
├── index.ts
├── patterns.ts
├── entropy.ts
└── filter.ts
```

### Secret Patterns

```typescript
// patterns.ts
export const SECRET_PATTERNS = [
  { pattern: /sk-ant-[a-zA-Z0-9-]{10,}/g, type: "ANTHROPIC_KEY" },
  { pattern: /sk-[a-zA-Z0-9-]{20,}/g, type: "OPENAI_KEY" },
  { pattern: /xoxb-[0-9-]+/g, type: "SLACK_TOKEN" },
  { pattern: /ghp_[a-zA-Z0-9]{36}/g, type: "GITHUB_PAT" },
  { pattern: /glpat-[a-zA-Z0-9-_]{20}/g, type: "GITLAB_PAT" },
  { pattern: /(Bearer|bot)\s+[a-zA-Z0-9._-]{20,}/gi, type: "BEARER_TOKEN" },
  { pattern: /AKIA[0-9A-Z]{16}/g, type: "AWS_ACCESS_KEY" },
  { pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/g, type: "PRIVATE_KEY" },
];

// entropy.ts - High-entropy string detection
export function isHighEntropy(str: string, threshold = 4.5): boolean;
export function detectBase64Secrets(content: string): string[];
```

### Integration Points

| File                            | Change Type   | Description                    |
| ------------------------------- | ------------- | ------------------------------ |
| `src/channels/*/send.ts`        | Import + wrap | Filter before channel delivery |
| `src/auto-reply/reply/index.ts` | Import + wrap | Central reply filtering        |

### Tests

```
test/security/output-redaction.test.ts
- 30 strings with embedded keys → all redacted
- 30 clean strings → 0 false positives
- Base64-encoded keys → detected and redacted
- Mixed content → only secrets redacted
```

---

## Module 3: Tool Execution Policy (CRITICAL)

**Priority:** Phase 1-2 (Days 0-30)
**Risk Reduction:** 5 - Critical
**Requirements:** REQ-01, REQ-02, REQ-06, REQ-10, CH-02, CH-05, CH-09
**Addresses:** F-01, AC-01, AC-02, AC-03, AC-10, LLM08

### Files to Create

```
src/security/tool-policy/
├── index.ts
├── schema-validator.ts
├── rate-limiter.ts
├── capability-matrix.ts
└── confirmation-gate.ts
```

### Capability Matrix (from Report Section 7.2)

```typescript
// capability-matrix.ts
export type SessionType = "main-elevated" | "main-standard" | "sandbox" | "webhook" | "cron";

export type Capability =
  | "bash-unrestricted"
  | "bash-sandboxed"
  | "browser-cdp"
  | "canvas-eval"
  | "file-read"
  | "file-write"
  | "cron-create"
  | "sessions-send"
  | "sessions-history-own"
  | "sessions-history-other"
  | "node-invoke"
  | "webhook-register"
  | "skill-install"
  | "config-write";

export const CAPABILITY_MATRIX: Record<
  SessionType,
  Record<Capability, "allow" | "confirm" | "deny">
> = {
  "main-elevated": {
    "bash-unrestricted": "allow",
    "bash-sandboxed": "allow",
    "browser-cdp": "allow",
    // ... full matrix from report
  },
  // ... other session types
};
```

### Rate Limiter Config

```typescript
// rate-limiter.ts
export interface RateLimitConfig {
  maxToolCallsPerHour: number; // default: 100
  maxCronJobsPerSession: number; // default: 10
  maxDailyTokenBudgetUSD: number; // default: 5.00
}
```

### Integration Points

| File                            | Change Type    | Description              |
| ------------------------------- | -------------- | ------------------------ |
| `src/agents/pi-tools.ts`        | Import + wrap  | Tool dispatch validation |
| `src/agents/bash-tools.exec.ts` | Import + gate  | Sandbox enforcement      |
| `src/agents/cron-tools.ts`      | Import + limit | Cron job cap             |

### Tests

```
test/security/tool-policy.test.ts
- Tool call with extra properties → rejected
- 101st tool call in 1 hour → RateLimitError
- 11th cron job → QuotaExceededError
- Destructive command without confirmation → blocked
- Capability check per session type → correct ACL
```

---

## Module 4: Browser CDP Guard (HIGH)

**Priority:** Phase 2 (Days 7-30)
**Risk Reduction:** 4 - High
**Requirements:** REQ-11, CH-06
**Addresses:** F-05, AC-05, LLM01

### Files to Create

```
src/security/browser-guard/
├── index.ts
├── url-blocklist.ts
└── navigation-policy.ts
```

### URL Blocklist

```typescript
// url-blocklist.ts
export const BLOCKED_URL_PATTERNS = [
  // Link-local (cloud metadata)
  /^https?:\/\/169\.254\.\d+\.\d+/,
  /^https?:\/\/\[fe80:/i,

  // RFC-1918 private ranges
  /^https?:\/\/10\.\d+\.\d+\.\d+/,
  /^https?:\/\/172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/,
  /^https?:\/\/192\.168\.\d+\.\d+/,

  // Localhost variants
  /^https?:\/\/localhost/i,
  /^https?:\/\/127\.\d+\.\d+\.\d+/,
  /^https?:\/\/\[::1\]/,
  /^https?:\/\/0\.0\.0\.0/,

  // Cloud metadata endpoints
  /^https?:\/\/metadata\.google\.internal/i,
  /^https?:\/\/100\.100\.100\.200/, // Alibaba
];

export function isBlockedUrl(url: string): { blocked: boolean; reason?: string };
```

### Integration Points

| File                          | Change Type       | Description                    |
| ----------------------------- | ----------------- | ------------------------------ |
| `src/agents/browser-tools.ts` | Import + validate | URL validation before navigate |

### Tests

```
test/security/browser-guard.test.ts
- navigate('http://169.254.169.254/') → BlockedURLError
- navigate('http://10.0.0.1/') → BlockedURLError
- navigate('https://google.com') → allowed
- IDN homograph attack URLs → blocked
```

---

## Module 5: Audit Logger (HIGH)

**Priority:** Phase 2-3 (Days 7-90)
**Risk Reduction:** 4 - High
**Requirements:** REQ-05, CH-07
**Addresses:** F-07, AC-14

### Files to Create

```
src/security/audit-logger/
├── index.ts
├── structured-event.ts
├── external-shipper.ts
└── hash-chain.ts
```

### Event Schema

```typescript
// structured-event.ts
export interface AuditEvent {
  timestamp: string; // ISO 8601
  eventId: string; // UUID v4
  sessionId: string;
  channel: string;
  toolName: string;
  argsHash: string; // SHA-256 of sanitized args
  outcome: "success" | "blocked" | "error";
  userId?: string;
  previousHash?: string; // Hash chain link
}

export function createAuditEvent(params: Partial<AuditEvent>): AuditEvent;
```

### External Shipper Support

```typescript
// external-shipper.ts
export interface LogShipper {
  ship(event: AuditEvent): Promise<void>;
}

export class CloudWatchShipper implements LogShipper { ... }
export class DatadogShipper implements LogShipper { ... }
export class LokiShipper implements LogShipper { ... }
export class FileShipper implements LogShipper { ... }  // Fallback
```

### Integration Points

| File                         | Change Type  | Description              |
| ---------------------------- | ------------ | ------------------------ |
| `src/agents/pi-tools.ts`     | Import + log | Log all tool invocations |
| `src/gateway/server-http.ts` | Import + log | Log auth events          |

---

## Module 6: ClawHub Skill Gate (HIGH)

**Priority:** Phase 2 (Days 7-30)
**Risk Reduction:** 4 - High
**Requirements:** REQ-07, CH-11
**Addresses:** F-06, AC-08, AC-16, LLM05

### Files to Create

```
src/security/skill-gate/
├── index.ts
├── approval-flow.ts
└── hash-verify.ts
```

### Approval Flow

```typescript
// approval-flow.ts
export interface SkillApprovalRequest {
  skillId: string;
  name: string;
  author: string;
  description: string;
  manifestHash: string; // SHA-256 from ClawHub manifest
}

export async function requestSkillApproval(
  request: SkillApprovalRequest,
  ownerChannel: string,
): Promise<boolean>;

export async function verifySkillHash(skillPath: string, expectedHash: string): Promise<boolean>;
```

### Config Addition

```typescript
// In openclaw.json schema
{
  "clawhub": {
    "autoInstall": false,        // MUST be false by default
    "requireOwnerApproval": true,
    "verifyHashes": true
  }
}
```

---

## Module 7: Session Security (MEDIUM)

**Priority:** Phase 2 (Days 7-30)
**Risk Reduction:** 3 - Medium
**Requirements:** REQ-15, CH-10
**Addresses:** AC-25

### Files to Create

```
src/security/session-security/
├── index.ts
├── token-store.ts
├── invalidation.ts
└── ttl-enforcement.ts
```

### Token Store

```typescript
// token-store.ts
export interface TokenStore {
  create(userId: string, metadata: TokenMetadata): string;
  validate(token: string): TokenMetadata | null;
  invalidate(token: string): void;
  invalidateAll(userId: string): void;
  cleanup(): void; // Remove expired tokens
}

export interface TokenMetadata {
  userId: string;
  createdAt: number;
  expiresAt: number; // Max 8 hours from creation
  clientIp?: string;
}
```

---

## Module 8: Webhook Authentication (MEDIUM)

**Priority:** Phase 2 (Days 7-30)
**Risk Reduction:** 3 - Medium
**Requirements:** REQ-13, CH-08
**Addresses:** AC-07, AC-17

### Files to Create

```
src/security/webhook-auth/
├── index.ts
├── hmac-verify.ts
└── ip-allowlist.ts
```

### HMAC Verification

```typescript
// hmac-verify.ts
import { timingSafeEqual, createHmac } from "crypto";

export function verifyWebhookSignature(
  payload: Buffer,
  signature: string,
  secret: string,
  algorithm = "sha256",
): boolean {
  const expected = createHmac(algorithm, secret).update(payload).digest("hex");

  const sigBuffer = Buffer.from(signature, "hex");
  const expBuffer = Buffer.from(expected, "hex");

  if (sigBuffer.length !== expBuffer.length) return false;
  return timingSafeEqual(sigBuffer, expBuffer);
}
```

---

## Rebase Strategy for Upstream Updates

### Design Principles for Rebase-Friendly Code

1. **Isolation**: Security modules live in `src/security/` - upstream rarely touches this
2. **Minimal Footprint**: Changes to existing files are < 10 lines each
3. **Import-Only Integration**: Most integrations are just adding imports and calls
4. **Configuration Separation**: Security config in dedicated section of `openclaw.json`

### Expected Conflict Points

| File                             | Likelihood | Resolution Strategy                        |
| -------------------------------- | ---------- | ------------------------------------------ |
| `src/agents/bash-tools.exec.ts`  | HIGH       | Document exact line numbers; easy re-apply |
| `src/auto-reply/reply/groups.ts` | MEDIUM     | Import + single function wrap              |
| `src/gateway/server-http.ts`     | MEDIUM     | Middleware addition is additive            |
| Channel handlers (5 files)       | LOW        | Isolated sanitization calls                |
| `package.json`                   | LOW        | No new dependencies in security modules    |

### Rebase Workflow

```bash
# 1. Fetch upstream
git fetch upstream main

# 2. Create rebase branch
git checkout -b rebase-security-$(date +%Y%m%d) claude/agent-security-analysis-8yTJ3

# 3. Rebase onto upstream
git rebase upstream/main

# 4. Resolve conflicts (usually in bash-tools.exec.ts, groups.ts)
#    - Keep our security imports
#    - Keep our function wrappers
#    - Accept upstream changes to everything else

# 5. Run security tests to verify
pnpm vitest run test/security/

# 6. Force-push rebased branch
git push -f origin rebase-security-$(date +%Y%m%d)
```

### Conflict Resolution Guide

**bash-tools.exec.ts conflicts:**

```typescript
// KEEP: Our safe-env import
import { buildSafeProcessEnv } from "../security/safe-env.js";

// KEEP: Our baseEnv replacement
const baseEnv = buildSafeProcessEnv(process.env);

// ACCEPT: Any upstream changes to sandbox logic, error handling, etc.
```

**Channel handler conflicts:**

```typescript
// KEEP: Our sanitization import
import { sanitizeGroupName, sanitizeParticipantList } from "../../security/channel-sanitize.js";

// KEEP: Our sanitization calls
GroupSubject: isGroup ? (sanitizeGroupName(msg.chat.title).value || undefined) : undefined,

// ACCEPT: Any upstream changes to message processing, context building, etc.
```

### Automated Conflict Detection

Add to CI:

```yaml
# .github/workflows/security-rebase-check.yml
name: Security Rebase Check
on:
  schedule:
    - cron: "0 6 * * 1" # Weekly Monday 6am
  workflow_dispatch:

jobs:
  check-rebase:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Check rebase viability
        run: |
          git fetch origin main
          git checkout ${{ github.ref }}

          # Attempt dry-run rebase
          if git rebase --dry-run origin/main 2>/dev/null; then
            echo "Clean rebase possible"
          else
            echo "::warning::Conflicts expected in rebase"
            git diff --name-only origin/main..HEAD | grep -E "^src/(agents|auto-reply|gateway|telegram|imessage|signal|web)/" || true
          fi
```

---

## Implementation Timeline

### Phase 1: Kill Critical Paths (Days 0-7)

| ID    | Module   | Action                                 | Owner | Status |
| ----- | -------- | -------------------------------------- | ----- | ------ |
| P1-01 | M3       | Enable Docker sandbox for ALL sessions | -     | TODO   |
| P1-02 | Infra    | Add Cloudflare Access + MFA            | -     | TODO   |
| P1-03 | Existing | Migrate secrets to Docker Secrets      | -     | TODO   |
| P1-04 | M2       | Deploy output redaction filter         | -     | TODO   |
| P1-05 | M1       | Add prompt injection sanitizer         | -     | TODO   |
| P1-06 | M7       | Implement /killswitch command          | -     | TODO   |

### Phase 2: Systematic Hardening (Days 7-30)

| ID    | Module | Action                                  | Owner | Status |
| ----- | ------ | --------------------------------------- | ----- | ------ |
| P2-01 | M3     | Tool argument JSON schema validation    | -     | TODO   |
| P2-02 | M4     | Browser URL blocklist (SSRF prevention) | -     | TODO   |
| P2-03 | M8     | Webhook HMAC signature verification     | -     | TODO   |
| P2-04 | M3     | Tool call rate limiter + cron job cap   | -     | TODO   |
| P2-05 | Infra  | Network egress allowlist                | -     | TODO   |
| P2-06 | M6     | ClawHub manual approval gate            | -     | TODO   |
| P2-07 | M1     | Cross-session trust policy              | -     | TODO   |
| P2-08 | M7     | Session token invalidation on logout    | -     | TODO   |
| P2-09 | Config | Startup security validator              | -     | TODO   |
| P2-10 | Test   | Red-team tests RT-01 through RT-10      | -     | TODO   |

### Phase 3: Operational Security (Days 30-90)

| ID    | Module  | Action                             | Owner | Status |
| ----- | ------- | ---------------------------------- | ----- | ------ |
| P3-01 | M5      | External append-only audit log     | -     | TODO   |
| P3-02 | M5      | Anomaly detection alerts           | -     | TODO   |
| P3-03 | CI      | Dependency audit in CI             | -     | TODO   |
| P3-04 | Infra   | Seccomp + AppArmor Docker profiles | -     | TODO   |
| P3-05 | M4      | Canvas CSP enforcement             | -     | TODO   |
| P3-06 | Process | Monthly red-team schedule          | -     | TODO   |

---

## Already Completed

The following items from the report have already been implemented:

1. **channel-sanitize.ts** (F-03 partial)
   - `sanitizeGroupName()`, `sanitizeParticipantList()`, `sanitizeParticipantName()`
   - Applied to: groups.ts, Telegram, iMessage, WhatsApp, Signal handlers

2. **safe-env.ts** (F-04 partial)
   - `buildSafeProcessEnv()` with allowlist/blocklist
   - Applied to: bash-tools.exec.ts

3. **secret-equal.ts** (upstream)
   - `safeEqualSecret()` using SHA-256 + timingSafeEqual
   - Applied to: hooks token comparison

---

## Test Commands

```bash
# Security test suite (when implemented)
pnpm vitest run test/security/ --reporter=verbose

# Individual module tests
pnpm vitest run test/security/prompt-sanitizer.test.ts
pnpm vitest run test/security/output-redaction.test.ts
pnpm vitest run test/security/tool-policy.test.ts
pnpm vitest run test/security/browser-guard.test.ts

# Dependency audit
pnpm audit --audit-level=high

# Secret scan
npx trufflehog filesystem ~/.openclaw/ --only-verified

# Red-team test suite
pnpm vitest run test/security/red-team/ --reporter=verbose
```

---

## Configuration Schema Additions

```typescript
// openclaw.json security section
{
  "security": {
    "promptSanitizer": {
      "enabled": true,
      "logSanitizationEvents": true,
      "strictMode": false  // true = block instead of wrap
    },
    "outputRedaction": {
      "enabled": true,
      "patterns": "default",  // or path to custom patterns
      "entropyThreshold": 4.5
    },
    "toolPolicy": {
      "maxToolCallsPerHour": 100,
      "maxCronJobsPerSession": 10,
      "maxDailyTokenBudgetUSD": 5.00,
      "requireConfirmationFor": ["bash", "file-write", "cron-create"]
    },
    "browserGuard": {
      "blockPrivateNetworks": true,
      "blockCloudMetadata": true,
      "customBlocklist": []
    },
    "auditLog": {
      "enabled": true,
      "shipper": "file",  // "cloudwatch" | "datadog" | "loki" | "file"
      "shipperConfig": {},
      "hashChain": true
    },
    "clawhub": {
      "autoInstall": false,
      "requireOwnerApproval": true,
      "verifyHashes": true
    },
    "session": {
      "maxTokenTTLHours": 8,
      "bindToClientIp": false,
      "invalidateOnLogout": true
    },
    "webhook": {
      "requireHmacSignature": true,
      "ipAllowlist": []
    }
  }
}
```

---

## Success Metrics

| Metric                 | Current | Phase 1 Target | Phase 2 Target | Phase 3 Target |
| ---------------------- | ------- | -------------- | -------------- | -------------- |
| CRITICAL findings      | 2       | 0              | 0              | 0              |
| HIGH findings          | 6       | 2              | 0              | 0              |
| MEDIUM findings        | 3       | 3              | 1              | 0              |
| Red-team tests passing | 0/10    | 3/10           | 10/10          | 10/10          |
| Audit log coverage     | 0%      | 50%            | 90%            | 100%           |
| Security test coverage | 0%      | 40%            | 80%            | 95%            |

---

## References

- Security Hardening Report: `openclaw-security-hardening-report.pdf`
- OWASP LLM Top 10 (2025): https://owasp.org/www-project-top-10-for-large-language-model-applications/
- STRIDE Threat Model: https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
