import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';

const B64U_RE = /^[A-Za-z0-9_-]*$/;
// PKCS#8 DER prefix for a raw 32-byte Ed25519 seed (RFC 8410).
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

export const b64u = (buf) => Buffer.from(buf).toString('base64url');

/**
 * Strict base64url (no padding) decode. Returns null unless the input is the
 * canonical encoding of exactly `expectedLength` bytes. Rejecting non-canonical
 * encodings stops one key being registered twice under different strings.
 */
export function b64uDecodeStrict(str, expectedLength) {
  if (typeof str !== 'string' || !B64U_RE.test(str)) return null;
  const buf = Buffer.from(str, 'base64url');
  if (expectedLength !== undefined && buf.length !== expectedLength) return null;
  if (buf.toString('base64url') !== str) return null;
  return buf;
}

export const sha256hex = (data) => createHash('sha256').update(data).digest('hex');

/** RFC 7638 thumbprint of an Ed25519 OKP JWK with x = publicKey (b64u). */
export function keyThumbprint(publicKey) {
  const jwk = `{"crv":"Ed25519","kty":"OKP","x":"${publicKey}"}`;
  return b64u(createHash('sha256').update(jwk, 'utf8').digest());
}

/** Parse a b64u raw Ed25519 public key into a KeyObject, or null if invalid. */
export function parsePublicKey(publicKey) {
  if (!b64uDecodeStrict(publicKey, 32)) return null;
  try {
    return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: publicKey }, format: 'jwk' });
  } catch {
    return null;
  }
}

/** Verify a b64u Ed25519 signature over a UTF-8 message. Never throws. */
export function verifySignature(publicKeyObject, message, signatureB64u) {
  const sig = b64uDecodeStrict(signatureB64u, 64);
  if (!sig || !publicKeyObject) return false;
  try {
    return verify(null, Buffer.from(message, 'utf8'), publicKeyObject, sig);
  } catch {
    return false;
  }
}

export function signMessage(privateKeyObject, message) {
  return b64u(sign(null, Buffer.from(message, 'utf8'), privateKeyObject));
}

export function privateKeyFromSeed(seed) {
  const buf = Buffer.isBuffer(seed) ? seed : Buffer.from(seed, 'hex');
  if (buf.length !== 32) throw new Error('Ed25519 seed must be 32 bytes');
  return createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, buf]), format: 'der', type: 'pkcs8' });
}

/** b64u raw public key for a private (or public) Ed25519 KeyObject. */
export function publicKeyB64u(keyObject) {
  const pub = keyObject.type === 'private' ? createPublicKey(keyObject) : keyObject;
  return pub.export({ format: 'jwk' }).x;
}

export function generateEd25519() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return { privateKey, publicKey: publicKeyB64u(publicKey) };
}
