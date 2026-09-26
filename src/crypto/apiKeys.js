import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { ID_PREFIX } from '../contracts.js';
import { newId } from '../ids.js';

const KEY_ID_RE = /^key_[0-9A-HJKMNP-TV-Z]{26}$/;
const SECRET_RE = /^[A-Za-z0-9_-]{43}$/;
export const API_KEY_LENGTH = 78;

/** Generate a fresh API key. The plaintext must be shown once and never stored. */
export function generateApiKey() {
  const keyId = newId(ID_PREFIX.apiKey);
  const secret = randomBytes(32).toString('base64url');
  return { keyId, secret, plaintext: `kya_${keyId}_${secret}` };
}

/** Parse `kya_<keyId>_<secret>` by fixed offsets (crypto-and-signing.md §5). */
export function parseApiKey(plaintext) {
  if (typeof plaintext !== 'string' || plaintext.length !== API_KEY_LENGTH) return null;
  if (!plaintext.startsWith('kya_') || plaintext[34] !== '_') return null;
  const keyId = plaintext.slice(4, 34);
  const secret = plaintext.slice(35);
  if (!KEY_ID_RE.test(keyId) || !SECRET_RE.test(secret)) return null;
  return { keyId, secret };
}

export function hashApiKeySecret(pepper, secret) {
  return createHmac('sha256', pepper).update(secret, 'utf8').digest('hex');
}

/** Constant-time comparison of a presented secret against a stored hex hash. */
export function secretMatches(pepper, secret, storedHash) {
  const a = Buffer.from(hashApiKeySecret(pepper, secret), 'hex');
  const b = Buffer.from(typeof storedHash === 'string' ? storedHash : '', 'hex');
  if (a.length !== b.length) {
    timingSafeEqual(a, a);
    return false;
  }
  return timingSafeEqual(a, b);
}
