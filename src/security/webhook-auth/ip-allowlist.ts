/**
 * IP Allowlist for Webhook Authentication
 *
 * Validates that webhook requests originate from known IP addresses.
 *
 * @module security/webhook-auth/ip-allowlist
 */

/**
 * IP allowlist check result
 */
export interface IpCheckResult {
  /** Whether the IP is allowed */
  allowed: boolean;
  /** Matching rule if allowed */
  matchedRule?: string;
  /** Reason for denial */
  reason?: string;
}

/**
 * Parse a CIDR notation into base IP and mask bits
 */
function parseCidr(cidr: string): { ip: number[]; maskBits: number } | null {
  const parts = cidr.split("/");
  const ipStr = parts[0];
  const maskBits = parts.length === 2 ? parseInt(parts[1], 10) : 32;

  if (isNaN(maskBits) || maskBits < 0 || maskBits > 32) {
    return null;
  }

  const octets = ipStr.split(".");
  if (octets.length !== 4) {
    return null;
  }

  const ip: number[] = [];
  for (const octet of octets) {
    const value = parseInt(octet, 10);
    if (isNaN(value) || value < 0 || value > 255) {
      return null;
    }
    ip.push(value);
  }

  return { ip, maskBits };
}

/**
 * Convert IP octets to a 32-bit integer
 */
function ipToInt(ip: number[]): number {
  return ((ip[0] << 24) | (ip[1] << 16) | (ip[2] << 8) | ip[3]) >>> 0;
}

/**
 * Check if an IP address matches a CIDR range
 */
export function ipMatchesCidr(ip: string, cidr: string): boolean {
  const ipParts = ip.split(".");
  if (ipParts.length !== 4) {
    return false;
  }

  const ipOctets = ipParts.map((p) => parseInt(p, 10));
  if (ipOctets.some((o) => isNaN(o) || o < 0 || o > 255)) {
    return false;
  }

  const parsed = parseCidr(cidr);
  if (!parsed) {
    return false;
  }

  const ipInt = ipToInt(ipOctets);
  const baseInt = ipToInt(parsed.ip);
  const mask = parsed.maskBits === 0 ? 0 : (~0 << (32 - parsed.maskBits)) >>> 0;

  return (ipInt & mask) === (baseInt & mask);
}

/**
 * Create an IP allowlist checker
 */
export function createIpAllowlist(rules: string[]) {
  // Normalize rules: support single IPs and CIDR
  const normalizedRules = rules.map((rule) => {
    if (!rule.includes("/")) {
      return `${rule}/32`;
    }
    return rule;
  });

  return {
    /**
     * Check if an IP address is in the allowlist
     */
    check(ip: string): IpCheckResult {
      if (normalizedRules.length === 0) {
        // Empty allowlist means allow all
        return { allowed: true, reason: "No allowlist configured" };
      }

      for (const rule of normalizedRules) {
        if (ipMatchesCidr(ip, rule)) {
          return { allowed: true, matchedRule: rule };
        }
      }

      return {
        allowed: false,
        reason: `IP ${ip} not in allowlist`,
      };
    },

    /**
     * Get the list of rules
     */
    getRules(): string[] {
      return [...normalizedRules];
    },
  };
}
