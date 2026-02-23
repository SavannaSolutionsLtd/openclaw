/**
 * Webhook Authentication
 *
 * Security module for authenticating incoming webhook requests
 * using HMAC signatures and IP allowlists.
 *
 * @module security/webhook-auth
 */

export {
  type HmacAlgorithm,
  type HmacVerifyResult,
  verifyWebhookSignature,
  computeHmacSignature,
  parseSignatureHeader,
} from "./hmac-verify.js";

export { type IpCheckResult, ipMatchesCidr, createIpAllowlist } from "./ip-allowlist.js";
