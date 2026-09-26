import { createHash } from 'node:crypto';
import { SIGNALS, normalizeSignals } from './signalsText.js';

/**
 * Deterministic fixture embeddings (EMBEDDINGS_MODE=fixture). These are NOT Voyage outputs; they
 * are a documented, reproducible construction over the closed signal set so that vector
 * similarity reflects signal overlap:
 *
 *   1. One axis per signal plus a NO_SIGNALS axis. Each axis is a 1024-d vector whose components
 *      come from sha256(`${FIXTURE_SEED}|${axis}|${counter}`) (counter mode, uint32 -> [-1, 1)),
 *      then Gram-Schmidt orthonormalised in the fixed AXES order, so all axes are exactly
 *      orthogonal unit vectors.
 *   2. embedding(S) = normalise( sum_{s in S} WEIGHTS[s] * axis[s] ); the empty set maps to the
 *      NO_SIGNALS axis. Cosine(S, T) = sum_{s in S∩T} w_s^2 / (|w_S| * |w_T|).
 *   3. SIGNING_KEY_CHANGED has weight 2 (the defining account-takeover indicator, INV-1042);
 *      every other signal has weight 1.
 *   4. Components are rounded to 1e-7 when written to fixtures/embeddings.json.
 *
 * Consequences (cosine / Atlas vectorSearchScore = (1 + cosine) / 2):
 *   takeover {AMOUNT_ANOMALY, NEAR_CEILING, NEW_COUNTERPARTY, SIGNING_KEY_CHANGED} vs
 *   - itself                                   1.000 / 1.000
 *   - same minus NEAR_CEILING                  0.926 / 0.963
 *   - NEAR_CEILING swapped for VELOCITY        0.857 / 0.929
 *   - {VELOCITY} (INV-0977, irrelevant)        0.000 / 0.500
 *   - {} (clean case)                          0.000 / 0.500
 */
export const FIXTURE_MODEL = 'kya-fixture-signals-v1';
export const FIXTURE_SEED = 'kya-fixture-embedding-v1';
export const NO_SIGNALS_AXIS = 'NO_SIGNALS';
export const AXES = Object.freeze([...SIGNALS, NO_SIGNALS_AXIS]);
export const WEIGHTS = Object.freeze({
  NEW_WALLET: 1,
  NEW_COUNTERPARTY: 1,
  SIGNING_KEY_CHANGED: 2,
  AMOUNT_ANOMALY: 1,
  VELOCITY: 1,
  NEAR_CEILING: 1,
});
export const ROUND = 1e7;

function rawAxis(name, dims) {
  const out = new Array(dims);
  let i = 0;
  for (let counter = 0; i < dims; counter += 1) {
    const block = createHash('sha256').update(`${FIXTURE_SEED}|${name}|${counter}`).digest();
    for (let off = 0; off + 4 <= block.length && i < dims; off += 4) {
      out[i++] = block.readUInt32BE(off) / 2 ** 31 - 1;
    }
  }
  return out;
}

const dot = (a, b) => a.reduce((acc, x, i) => acc + x * b[i], 0);
const normalize = (v) => {
  const n = Math.sqrt(dot(v, v));
  return v.map((x) => x / n);
};

const axesCache = new Map();
export function orthonormalAxes(dims) {
  if (axesCache.has(dims)) return axesCache.get(dims);
  const basis = {};
  const done = [];
  for (const name of AXES) {
    let v = rawAxis(name, dims);
    for (const u of done) {
      const p = dot(v, u);
      v = v.map((x, i) => x - p * u[i]);
    }
    v = normalize(v);
    done.push(v);
    basis[name] = v;
  }
  axesCache.set(dims, basis);
  return basis;
}

/** Fixture embedding for a signal set (unrounded unit vector). */
export function fixtureVector(signals, dims) {
  const set = normalizeSignals(signals);
  const axes = orthonormalAxes(dims);
  if (set.length === 0) return [...axes[NO_SIGNALS_AXIS]];
  const v = new Array(dims).fill(0);
  for (const s of set) {
    const w = WEIGHTS[s];
    const a = axes[s];
    for (let i = 0; i < dims; i += 1) v[i] += w * a[i];
  }
  return normalize(v);
}

export const roundVector = (v) => v.map((x) => Math.round(x * ROUND) / ROUND);

/** Every subset of the closed signal set (2^6 = 64), so any signals stage output has a fixture. */
export function allSignalSets() {
  const sets = [];
  for (let mask = 0; mask < 1 << SIGNALS.length; mask += 1) {
    sets.push(SIGNALS.filter((_, i) => mask & (1 << i)));
  }
  return sets;
}
