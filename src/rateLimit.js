// Fixed-window request rate limiter (REQ-016), in-process and zero-dependency.
// State is per process: with N replicas the effective limit is N × the configured one. That is
// acceptable for the MVP single-instance deployment; a shared store would be needed to scale out.

/** Hard cap on tracked keys so a flood of distinct keys cannot exhaust memory. */
export const DEFAULT_MAX_KEYS = 100_000;

export class RateLimiter {
  /**
   * @param {{ limit: number, windowSeconds: number, clock: { now: () => Date }, maxKeys?: number }} opts
   */
  constructor({ limit, windowSeconds, clock, maxKeys = DEFAULT_MAX_KEYS }) {
    if (!Number.isInteger(limit) || limit < 1) throw new TypeError('limit must be a positive integer');
    if (!Number.isInteger(windowSeconds) || windowSeconds < 1) throw new TypeError('windowSeconds must be a positive integer');
    this.limit = limit;
    this.windowMs = windowSeconds * 1000;
    this.clock = clock;
    this.maxKeys = maxKeys;
    this.buckets = new Map();
  }

  /**
   * Counts one hit for `key`. Returns whether it is allowed, the remaining budget and the number of
   * whole seconds until the window resets (for `Retry-After`).
   */
  hit(key) {
    const now = this.clock.now().getTime();
    let b = this.buckets.get(key);
    if (!b || now >= b.resetAt) {
      if (b) this.buckets.delete(key);
      else if (this.buckets.size >= this.maxKeys) this.#evict(now);
      b = { count: 0, resetAt: now + this.windowMs };
      this.buckets.set(key, b);
    }
    b.count += 1;
    const retryAfter = Math.max(1, Math.ceil((b.resetAt - now) / 1000));
    return { allowed: b.count <= this.limit, remaining: Math.max(0, this.limit - b.count), retryAfter, limit: this.limit };
  }

  #evict(now) {
    for (const [k, b] of this.buckets) if (now >= b.resetAt) this.buckets.delete(k);
    // Still full: drop the oldest entries (Map preserves insertion order).
    const excess = this.buckets.size - this.maxKeys + 1;
    if (excess > 0) {
      let n = 0;
      for (const k of this.buckets.keys()) {
        if (n++ >= excess) break;
        this.buckets.delete(k);
      }
    }
  }
}

/**
 * Limiter set used by the HTTP layer. Each rate-limited route has a `rateLimit` class:
 *  - every request is counted per client IP *before* authentication (bounds unauthenticated
 *    floods and API-key guessing), and
 *  - authenticated requests are counted per tenant (owner, or API key for admins) so one caller
 *    cannot starve others behind the same NAT or exhaust the service with many keys.
 */
export function createRateLimits(config, clock) {
  const rl = config.rateLimit;
  const mk = (limit) => new RateLimiter({ limit, windowSeconds: rl.windowSeconds, clock });
  return {
    enabled: rl.enabled,
    ip: mk(rl.ipPerWindow),
    verify: mk(rl.verifyPerWindow),
    register: mk(rl.registerPerWindow),
  };
}

export function principalKey(p) {
  return p.operatorId ?? p.businessId ?? `key:${p.apiKeyId}`;
}
