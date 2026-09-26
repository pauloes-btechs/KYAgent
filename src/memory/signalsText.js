import { canonicalJson } from '../crypto/canonical.js';
import { sha256hex } from '../crypto/ed25519.js';

/** Closed signal set (docs/contracts/types.ts SIGNALS, investigation-pipeline.md §4 stage 4). */
export const SIGNALS = Object.freeze([
  'NEW_WALLET',
  'NEW_COUNTERPARTY',
  'SIGNING_KEY_CHANGED',
  'AMOUNT_ANOMALY',
  'VELOCITY',
  'NEAR_CEILING',
]);

export const SIGNALS_TEXT_VERSION = 1;

export class SignalsTextError extends Error {}

/**
 * Normalise a signal set: validate against the closed set, de-duplicate, sort.
 * Accepts `Signal[]` or `{ signals: Signal[] }`.
 */
export function normalizeSignals(input) {
  const signals = Array.isArray(input) ? input : input?.signals;
  if (!Array.isArray(signals)) throw new SignalsTextError('signals must be an array');
  for (const s of signals) {
    if (typeof s !== 'string' || !SIGNALS.includes(s)) {
      throw new SignalsTextError(`unknown signal ${JSON.stringify(s)}`);
    }
  }
  return [...new Set(signals)].sort();
}

/**
 * Deterministic text for a signal set: canonical JSON (sorted keys, sorted unique signals), so
 * the same set in any order yields byte-identical text and therefore the same sha256 fixture key.
 */
export function signalsText(input) {
  return canonicalJson({ kind: 'kya.signals', signals: normalizeSignals(input), v: SIGNALS_TEXT_VERSION });
}

export function textSha256(text) {
  if (typeof text !== 'string') throw new SignalsTextError('text must be a string');
  return sha256hex(Buffer.from(text, 'utf8'));
}
