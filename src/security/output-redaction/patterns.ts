/**
 * Secret Detection Patterns
 *
 * Patterns for detecting API keys, tokens, and other sensitive data
 * in outbound messages to prevent accidental credential leakage.
 *
 * @module security/output-redaction/patterns
 */

/**
 * Pattern definition for secret detection
 */
export interface SecretPattern {
  /** Regex pattern for detection */
  pattern: RegExp;
  /** Type identifier for the secret */
  type: string;
  /** Description for logging/reporting */
  description: string;
  /** Whether this is a high-confidence pattern (low false positives) */
  highConfidence: boolean;
}

/**
 * Known secret patterns for major API providers and services
 */
export const SECRET_PATTERNS: SecretPattern[] = [
  // AI Provider API Keys
  {
    pattern: /sk-ant-[a-zA-Z0-9-]{10,}/g,
    type: "ANTHROPIC_KEY",
    description: "Anthropic API key",
    highConfidence: true,
  },
  {
    pattern: /sk-[a-zA-Z0-9]{20,}/g,
    type: "OPENAI_KEY",
    description: "OpenAI API key",
    highConfidence: true,
  },
  {
    pattern: /sk-proj-[a-zA-Z0-9-_]{20,}/g,
    type: "OPENAI_PROJECT_KEY",
    description: "OpenAI project API key",
    highConfidence: true,
  },

  // Cloud Provider Keys
  {
    pattern: /AKIA[0-9A-Z]{16}/g,
    type: "AWS_ACCESS_KEY",
    description: "AWS Access Key ID",
    highConfidence: true,
  },
  {
    pattern: /ASIA[0-9A-Z]{16}/g,
    type: "AWS_TEMP_ACCESS_KEY",
    description: "AWS Temporary Access Key ID",
    highConfidence: true,
  },
  {
    pattern: /AIza[0-9A-Za-z_-]{30,}/g,
    type: "GOOGLE_API_KEY",
    description: "Google API key",
    highConfidence: true,
  },
  {
    pattern: /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,
    type: "AZURE_CLIENT_SECRET",
    description: "Azure client secret (UUID format)",
    highConfidence: false, // UUIDs can be non-sensitive
  },

  // Version Control Tokens
  {
    pattern: /ghp_[a-zA-Z0-9]{36}/g,
    type: "GITHUB_PAT",
    description: "GitHub personal access token",
    highConfidence: true,
  },
  {
    pattern: /gho_[a-zA-Z0-9]{36}/g,
    type: "GITHUB_OAUTH",
    description: "GitHub OAuth access token",
    highConfidence: true,
  },
  {
    pattern: /ghu_[a-zA-Z0-9]{36}/g,
    type: "GITHUB_USER_TOKEN",
    description: "GitHub user-to-server token",
    highConfidence: true,
  },
  {
    pattern: /ghs_[a-zA-Z0-9]{36}/g,
    type: "GITHUB_SERVER_TOKEN",
    description: "GitHub server-to-server token",
    highConfidence: true,
  },
  {
    pattern: /github_pat_[a-zA-Z0-9]{20,}_[a-zA-Z0-9]{50,}/g,
    type: "GITHUB_FINE_PAT",
    description: "GitHub fine-grained personal access token",
    highConfidence: true,
  },
  {
    pattern: /glpat-[a-zA-Z0-9-_]{20,}/g,
    type: "GITLAB_PAT",
    description: "GitLab personal access token",
    highConfidence: true,
  },
  {
    pattern: /glcbt-[a-zA-Z0-9-_]{20,}/g,
    type: "GITLAB_CI_TOKEN",
    description: "GitLab CI build token",
    highConfidence: true,
  },

  // Messaging Platforms
  {
    pattern: /xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+/g,
    type: "SLACK_BOT_TOKEN",
    description: "Slack bot token",
    highConfidence: true,
  },
  {
    pattern: /xoxp-[0-9]+-[0-9]+-[0-9]+-[a-f0-9]+/g,
    type: "SLACK_USER_TOKEN",
    description: "Slack user token",
    highConfidence: true,
  },
  {
    pattern: /xoxa-[0-9]+-[a-zA-Z0-9-]+/g,
    type: "SLACK_APP_TOKEN",
    description: "Slack app token",
    highConfidence: true,
  },
  {
    pattern: /xoxr-[0-9]+-[a-zA-Z0-9-]+/g,
    type: "SLACK_REFRESH_TOKEN",
    description: "Slack refresh token",
    highConfidence: true,
  },
  {
    pattern: /[0-9]{8,12}:[A-Za-z0-9_-]{30,}/g,
    type: "TELEGRAM_BOT_TOKEN",
    description: "Telegram bot token",
    highConfidence: true,
  },
  {
    pattern: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}/g,
    type: "DISCORD_BOT_TOKEN",
    description: "Discord bot token",
    highConfidence: true,
  },

  // Private Keys and Certificates
  {
    pattern:
      /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(RSA\s+)?PRIVATE\s+KEY-----/g,
    type: "RSA_PRIVATE_KEY",
    description: "RSA private key",
    highConfidence: true,
  },
  {
    pattern: /-----BEGIN\s+EC\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+EC\s+PRIVATE\s+KEY-----/g,
    type: "EC_PRIVATE_KEY",
    description: "EC private key",
    highConfidence: true,
  },
  {
    pattern:
      /-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+OPENSSH\s+PRIVATE\s+KEY-----/g,
    type: "SSH_PRIVATE_KEY",
    description: "OpenSSH private key",
    highConfidence: true,
  },
  {
    pattern:
      /-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----[\s\S]*?-----END\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----/g,
    type: "PGP_PRIVATE_KEY",
    description: "PGP private key",
    highConfidence: true,
  },

  // Database Connection Strings
  {
    pattern: /postgres(ql)?:\/\/[^:]+:[^@]+@[^/]+\/[^\s"']+/gi,
    type: "POSTGRES_URL",
    description: "PostgreSQL connection string with credentials",
    highConfidence: true,
  },
  {
    pattern: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@[^/]+/gi,
    type: "MONGODB_URL",
    description: "MongoDB connection string with credentials",
    highConfidence: true,
  },
  {
    pattern: /mysql:\/\/[^:]+:[^@]+@[^/]+/gi,
    type: "MYSQL_URL",
    description: "MySQL connection string with credentials",
    highConfidence: true,
  },
  {
    pattern: /redis:\/\/[^:]*:[^@]+@[^/]+/gi,
    type: "REDIS_URL",
    description: "Redis connection string with credentials",
    highConfidence: true,
  },

  // Bearer/Auth Tokens
  {
    pattern: /Bearer\s+[a-zA-Z0-9._-]{20,}/gi,
    type: "BEARER_TOKEN",
    description: "Bearer authentication token",
    highConfidence: false, // Could be example/placeholder
  },
  {
    pattern: /Authorization:\s*Bearer\s+[a-zA-Z0-9._-]{20,}/gi,
    type: "AUTH_HEADER",
    description: "Authorization header with Bearer token",
    highConfidence: true,
  },

  // Payment Processors
  {
    pattern: /sk_live_[a-zA-Z0-9]{24,}/g,
    type: "STRIPE_SECRET_KEY",
    description: "Stripe secret key (live)",
    highConfidence: true,
  },
  {
    pattern: /sk_test_[a-zA-Z0-9]{24,}/g,
    type: "STRIPE_SECRET_KEY_TEST",
    description: "Stripe secret key (test)",
    highConfidence: true,
  },
  {
    pattern: /rk_live_[a-zA-Z0-9]{24,}/g,
    type: "STRIPE_RESTRICTED_KEY",
    description: "Stripe restricted key (live)",
    highConfidence: true,
  },
  {
    pattern: /pk_live_[a-zA-Z0-9]{24,}/g,
    type: "STRIPE_PUBLISHABLE_KEY",
    description: "Stripe publishable key (live)",
    highConfidence: false, // Publishable keys are meant to be public
  },

  // Infrastructure/DevOps
  {
    pattern: /npm_[a-zA-Z0-9]{30,}/g,
    type: "NPM_TOKEN",
    description: "npm access token",
    highConfidence: true,
  },
  {
    pattern: /pypi-[a-zA-Z0-9-_]{150,}/g,
    type: "PYPI_TOKEN",
    description: "PyPI API token",
    highConfidence: true,
  },
  {
    pattern: /SG\.[a-zA-Z0-9-_]{15,}\.[a-zA-Z0-9-_]{30,}/g,
    type: "SENDGRID_KEY",
    description: "SendGrid API key",
    highConfidence: true,
  },
  {
    pattern: /key-[a-f0-9]{32}/g,
    type: "MAILGUN_KEY",
    description: "Mailgun API key",
    highConfidence: true,
  },
  {
    pattern: /EAACEdEose0cBA[0-9A-Za-z]+/g,
    type: "FACEBOOK_ACCESS_TOKEN",
    description: "Facebook access token",
    highConfidence: true,
  },
  {
    pattern: /sq0csp-[a-zA-Z0-9-_]{43}/g,
    type: "SQUARE_TOKEN",
    description: "Square access token",
    highConfidence: true,
  },

  // JWT Detection (may contain sensitive claims)
  {
    pattern: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]*/g,
    type: "JWT_TOKEN",
    description: "JSON Web Token",
    highConfidence: false, // JWTs vary in sensitivity
  },
];

/**
 * Get all high-confidence patterns (for strict mode)
 */
export function getHighConfidencePatterns(): SecretPattern[] {
  return SECRET_PATTERNS.filter((p) => p.highConfidence);
}

/**
 * Detect secrets in content using all patterns
 *
 * @param content - Text content to scan
 * @param strictMode - Only use high-confidence patterns
 * @returns Array of detected secrets with metadata
 */
export function detectSecrets(
  content: string,
  strictMode = false,
): Array<{ type: string; match: string; description: string }> {
  const patterns = strictMode ? getHighConfidencePatterns() : SECRET_PATTERNS;
  const detections: Array<{ type: string; match: string; description: string }> = [];
  const seen = new Set<string>();

  for (const { pattern, type, description } of patterns) {
    // Reset regex state for each scan
    const regex = new RegExp(pattern.source, pattern.flags);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(content)) !== null) {
      const matchedText = match[0];
      // Deduplicate
      if (!seen.has(matchedText)) {
        seen.add(matchedText);
        detections.push({ type, match: matchedText, description });
      }
    }
  }

  return detections;
}

/**
 * Check if content contains any secrets
 */
export function containsSecrets(content: string, strictMode = false): boolean {
  return detectSecrets(content, strictMode).length > 0;
}
