/**
 * Security utilities for building safe environment variable sets.
 *
 * When spawning child processes (especially from AI-controlled tool calls),
 * we must not leak sensitive environment variables like API keys, tokens,
 * and credentials.
 *
 * SECURITY: Child processes should only receive an allowlisted set of safe
 * environment variables, not the full process.env which may contain secrets.
 */

/**
 * Environment variables that are safe to pass to child processes.
 */
const SAFE_ENV_ALLOWLIST = new Set([
  "PATH",
  "HOME",
  "USER",
  "LOGNAME",
  "USERNAME",
  "SHELL",
  "TERM",
  "COLORTERM",
  "LANG",
  "LANGUAGE",
  "LC_ALL",
  "LC_CTYPE",
  "LC_MESSAGES",
  "LC_COLLATE",
  "LC_NUMERIC",
  "LC_TIME",
  "TZ",
  "TMPDIR",
  "TEMP",
  "TMP",
  "XDG_RUNTIME_DIR",
  "XDG_DATA_HOME",
  "XDG_CONFIG_HOME",
  "XDG_CACHE_HOME",
  "XDG_STATE_HOME",
  "DISPLAY",
  "__CF_USER_TEXT_ENCODING",
  "NODE_ENV",
  "NODE_OPTIONS",
  "NODE_PATH",
  "NODE_NO_WARNINGS",
  "NO_COLOR",
  "FORCE_COLOR",
  "EDITOR",
  "VISUAL",
  "PAGER",
  "GIT_AUTHOR_NAME",
  "GIT_AUTHOR_EMAIL",
  "GIT_COMMITTER_NAME",
  "GIT_COMMITTER_EMAIL",
  "GIT_EDITOR",
  "GIT_PAGER",
  "COLUMNS",
  "LINES",
  "PWD",
  "OLDPWD",
  "SSH_CLIENT",
  "SSH_CONNECTION",
  "SSH_TTY",
  "PNPM_HOME",
  "NPM_CONFIG_PREFIX",
]);

/**
 * Patterns for environment variable names that should NEVER be passed.
 */
const BLOCKED_PATTERNS = [
  /^ANTHROPIC_/i,
  /^OPENAI_/i,
  /^AZURE_/i,
  /^AWS_/i,
  /^GOOGLE_/i,
  /^GCP_/i,
  /^GITHUB_TOKEN$/i,
  /^GH_TOKEN$/i,
  /^GITLAB_/i,
  /^HUGGING_?FACE/i,
  /^HF_/i,
  /^REPLICATE_/i,
  /^COHERE_/i,
  /^MISTRAL_/i,
  /^GROQ_/i,
  /^PERPLEXITY_/i,
  /^TOGETHER_/i,
  /^FIREWORKS_/i,
  /^OPENROUTER_/i,
  /^ELEVEN_?LABS/i,
  /^BRAVE_/i,
  /^TELEGRAM_/i,
  /^DISCORD_/i,
  /^SLACK_/i,
  /^TWILIO_/i,
  /^STRIPE_/i,
  /^DATABASE_/i,
  /^DB_/i,
  /^POSTGRES/i,
  /^MYSQL/i,
  /^MONGO/i,
  /^REDIS_/i,
  /^SENTRY_/i,
  /SECRET/i,
  /TOKEN/i,
  /PASSWORD/i,
  /CREDENTIAL/i,
  /API_?KEY/i,
  /PRIVATE_?KEY/i,
  /AUTH/i,
  /BEARER/i,
  /ENCRYPTION/i,
  /SIGNING/i,
  /^NPM_TOKEN$/i,
  /^DOCKER_/i,
  /^KUBECONFIG$/i,
  /^VAULT_/i,
  /^CHUTES_/i,
  /^OPENCLAW_.*(?:TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL)/i,
];

function isBlockedEnvVar(name: string): boolean {
  for (const pattern of BLOCKED_PATTERNS) {
    if (pattern.test(name)) {
      return true;
    }
  }
  return false;
}

/**
 * Build a safe environment object for child process execution.
 *
 * Only includes allowlisted environment variables, filtering out any
 * that could contain sensitive credentials or API keys.
 *
 * @param processEnv The source environment (usually process.env)
 * @param additionalEnv Additional environment variables to include (NOT filtered,
 *   as these are explicitly set by trusted code)
 */
export function buildSafeProcessEnv(
  processEnv: NodeJS.ProcessEnv,
  additionalEnv?: Record<string, string | undefined>,
): Record<string, string> {
  const safe: Record<string, string> = {};

  for (const [key, value] of Object.entries(processEnv)) {
    if (value === undefined) {
      continue;
    }
    if (isBlockedEnvVar(key)) {
      continue;
    }
    if (SAFE_ENV_ALLOWLIST.has(key)) {
      safe[key] = value;
    }
  }

  if (additionalEnv) {
    for (const [key, value] of Object.entries(additionalEnv)) {
      if (value !== undefined) {
        safe[key] = value;
      }
    }
  }

  return safe;
}
