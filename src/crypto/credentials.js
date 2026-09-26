import { sign, verify } from 'node:crypto';
import { CREDENTIAL_TYP } from '../contracts.js';
import { b64u, b64uDecodeStrict, publicKeyB64u } from './ed25519.js';

const SEGMENT_RE = /^[A-Za-z0-9_-]+$/;

const encodeJson = (obj) => b64u(Buffer.from(JSON.stringify(obj), 'utf8'));

/** Sign credential claims as a compact JWS (alg EdDSA, typ kya-credential+jwt). */
export function signCredential(claims, { privateKey, kid }) {
  const header = { alg: 'EdDSA', typ: CREDENTIAL_TYP, kid };
  const signingInput = `${encodeJson(header)}.${encodeJson(claims)}`;
  const signature = b64u(sign(null, Buffer.from(signingInput, 'ascii'), privateKey));
  return `${signingInput}.${signature}`;
}

function decodeJsonSegment(segment) {
  const buf = b64uDecodeStrict(segment);
  if (!buf) return null;
  try {
    const value = JSON.parse(buf.toString('utf8'));
    return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
  } catch {
    return null;
  }
}

const isStr = (v) => typeof v === 'string' && v.length > 0 && v.length <= 256;
const isInt = (v) => Number.isSafeInteger(v);

function claimsWellFormed(c) {
  return (
    isStr(c.iss) && isStr(c.sub) && isStr(c.aud) && isStr(c.jti) &&
    isStr(c.kya_operator) && isStr(c.kya_grant) &&
    isInt(c.iat) && isInt(c.nbf) && isInt(c.exp) &&
    Array.isArray(c.kya_actions) && c.kya_actions.length > 0 && c.kya_actions.every(isStr) &&
    c.kya_constraints !== null && typeof c.kya_constraints === 'object' && !Array.isArray(c.kya_constraints) &&
    c.cnf !== null && typeof c.cnf === 'object' && isStr(c.cnf.jkt)
  );
}

/**
 * Verify a compact JWS credential signature and header (ARCHITECTURE §3 step 9a).
 * Returns the claims, or null for any problem. Time/audience/subject checks are
 * done by the caller so each maps to its own reason code. Never throws.
 */
export function verifyCredentialJws(jws, { publicKey, kid, issuer }) {
  if (typeof jws !== 'string' || jws.length > 8192) return null;
  const parts = jws.split('.');
  if (parts.length !== 3 || !parts.every((p) => SEGMENT_RE.test(p))) return null;
  const header = decodeJsonSegment(parts[0]);
  if (!header) return null;
  // Algorithm allow-list is exactly ["EdDSA"]; no other header params accepted.
  const headerKeys = Object.keys(header).sort().join(',');
  if (headerKeys !== 'alg,kid,typ') return null;
  if (header.alg !== 'EdDSA' || header.typ !== CREDENTIAL_TYP || header.kid !== kid) return null;
  const sig = b64uDecodeStrict(parts[2], 64);
  if (!sig) return null;
  let ok = false;
  try {
    ok = verify(null, Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii'), publicKey, sig);
  } catch {
    ok = false;
  }
  if (!ok) return null;
  const claims = decodeJsonSegment(parts[1]);
  if (!claims || !claimsWellFormed(claims) || claims.iss !== issuer) return null;
  return claims;
}

export function jwks({ publicKey, kid }) {
  return { keys: [{ kty: 'OKP', crv: 'Ed25519', x: publicKeyB64u(publicKey), kid, alg: 'EdDSA', use: 'sig' }] };
}
