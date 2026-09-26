// Action matching and constraint evaluation (ARCHITECTURE §3).
import { ACTION_PATTERN_RE, ACTION_RE } from '../contracts.js';

/** `orders:*` matches `orders:create` and `orders:refund:partial`, not `orders`. Bare `*` never matches. */
export function actionMatches(pattern, action) {
  if (typeof pattern !== 'string' || typeof action !== 'string') return false;
  if (!ACTION_PATTERN_RE.test(pattern) || !ACTION_RE.test(action)) return false;
  if (pattern.endsWith(':*')) return action.startsWith(pattern.slice(0, -1));
  return pattern === action;
}

export const anyActionMatches = (patterns, action) => Array.isArray(patterns) && patterns.some((p) => actionMatches(p, action));

/** All present constraints must hold; a missing context value is a violation. */
export function constraintsSatisfied(constraints, resource, context) {
  const c = constraints ?? {};
  const ctx = context ?? {};
  if (c.maxAmount !== undefined) {
    // Amounts are non-negative integer minor units; negative values are denied.
    if (!Number.isSafeInteger(ctx.amount) || ctx.amount < 0 || ctx.amount > c.maxAmount) return false;
  }
  if (c.currency !== undefined && ctx.currency !== c.currency) return false;
  if (c.resources !== undefined) {
    if (!Array.isArray(c.resources) || !resource || !c.resources.includes(resource)) return false;
  }
  return true;
}
