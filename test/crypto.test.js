import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { generateApiKey, hashApiKeySecret, parseApiKey, secretMatches } from '../src/crypto/apiKeys.js';
import { buildRegisterMessage, buildSigningString, canonicalJson, contextSha256 } from '../src/crypto/canonical.js';
import { signCredential, verifyCredentialJws } from '../src/crypto/credentials.js';
import { b64uDecodeStrict, keyThumbprint, parsePublicKey, privateKeyFromSeed, publicKeyB64u, signMessage, verifySignature } from '../src/crypto/ed25519.js';
import { ulid } from '../src/ids.js';
import { agentKeyFromSeed, signRequest } from '../src/sdk/agentSigner.js';
import { actionMatches, constraintsSatisfied } from '../src/services/authz.js';

const vector = JSON.parse(readFileSync(new URL('./vectors/sig-v1.json', import.meta.url), 'utf8'));

test('Ed25519 primitives reproduce RFC 8032 TEST 1', () => {
  const priv = privateKeyFromSeed(vector.seedHex);
  const pub = publicKeyB64u(priv);
  assert.equal(Buffer.from(pub, 'base64url').toString('hex'), vector.publicKeyHex);
  assert.equal(Buffer.from(signMessage(priv, ''), 'base64url').toString('hex'), vector.rfc8032.signatureHex);
});

test('KYA-SIG-V1 vector: SDK and server build identical bytes', () => {
  const r = vector.request;
  assert.equal(contextSha256(r.context), vector.contextSha256);
  const serverString = buildSigningString({ ...r, contextSha256: vector.contextSha256 });
  assert.equal(serverString, vector.signingString);

  const { privateKey, publicKey } = agentKeyFromSeed(vector.seedHex);
  const sdk = signRequest(privateKey, r);
  assert.equal(sdk.contextSha256, vector.contextSha256);
  assert.equal(buildSigningString(sdk), vector.signingString);
  // Deterministic (Ed25519) and verifiable by the server with only the public key.
  assert.equal(signRequest(privateKey, r).signature, sdk.signature);
  assert.ok(verifySignature(parsePublicKey(publicKey), vector.signingString, sdk.signature));
  assert.ok(!verifySignature(parsePublicKey(publicKey), `${vector.signingString}x`, sdk.signature));

  assert.equal(buildRegisterMessage(vector.registerMessage.operatorId, publicKey), vector.registerMessage.message + publicKey);
});

test('canonical JSON: sorted keys, integers only, bounded depth', () => {
  assert.equal(canonicalJson({ currency: 'USD', amount: 1500 }), '{"amount":1500,"currency":"USD"}');
  assert.equal(canonicalJson({ b: [1, { d: null, c: true }], a: 'x"y' }), '{"a":"x\\"y","b":[1,{"c":true,"d":null}]}');
  assert.equal(canonicalJson({}), '{}');
  assert.throws(() => canonicalJson({ a: 1.5 }));
  assert.throws(() => canonicalJson({ a: 2 ** 53 }));
  assert.throws(() => canonicalJson({ a: undefined }));
  let deep = {};
  for (let i = 0; i < 40; i++) deep = { d: deep };
  assert.throws(() => canonicalJson(deep));
});

test('strict base64url and key parsing', () => {
  const { publicKey } = generateKeyPairSync('ed25519');
  const x = publicKeyB64u(publicKey);
  assert.ok(parsePublicKey(x));
  assert.equal(parsePublicKey(`${x}=`), null);
  assert.equal(parsePublicKey(x.slice(1)), null);
  assert.equal(b64uDecodeStrict('ab+c'), null);
  assert.match(keyThumbprint(x), /^[A-Za-z0-9_-]{43}$/);
  assert.equal(verifySignature(parsePublicKey(x), 'm', 'not-a-signature'), false);
});

test('credential JWS: roundtrip, tamper, alg allow-list, kid, issuer', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const claims = {
    iss: 'kyagent', sub: 'agt_x', aud: 'biz_x', iat: 1, nbf: 1, exp: 2, jti: 'crd_x',
    kya_operator: 'op_x', kya_grant: 'grt_x', kya_actions: ['a:b'], kya_constraints: {}, cnf: { jkt: 'j' },
  };
  const jws = signCredential(claims, { privateKey, kid: 'k1' });
  const opts = { publicKey, kid: 'k1', issuer: 'kyagent' };
  assert.deepEqual(verifyCredentialJws(jws, opts), claims);
  assert.equal(verifyCredentialJws(jws, { ...opts, kid: 'k2' }), null);
  assert.equal(verifyCredentialJws(jws, { ...opts, issuer: 'other' }), null);
  assert.equal(verifyCredentialJws(jws, { ...opts, publicKey: generateKeyPairSync('ed25519').publicKey }), null);
  const [h, , s] = jws.split('.');
  const forged = `${h}.${Buffer.from(JSON.stringify({ ...claims, exp: 999999 })).toString('base64url')}.${s}`;
  assert.equal(verifyCredentialJws(forged, opts), null);
  const extraHeader = signCredential(claims, { privateKey, kid: 'k1' }).replace(/^[^.]+/, Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'kya-credential+jwt', kid: 'k1', jku: 'http://evil' })).toString('base64url'));
  assert.equal(verifyCredentialJws(extraHeader, opts), null);
  const missingClaim = signCredential({ ...claims, cnf: undefined }, { privateKey, kid: 'k1' });
  assert.equal(verifyCredentialJws(missingClaim, opts), null);
  assert.equal(verifyCredentialJws(null, opts), null);
  assert.equal(verifyCredentialJws('x'.repeat(9000), opts), null);
});

test('API keys: format, fixed-offset parsing, HMAC hashing', () => {
  const { keyId, secret, plaintext } = generateApiKey();
  assert.equal(plaintext.length, 78);
  assert.deepEqual(parseApiKey(plaintext), { keyId, secret });
  assert.equal(parseApiKey(`${plaintext}x`), null);
  assert.equal(parseApiKey(plaintext.replace('kya_', 'kyb_')), null);
  const pepper = Buffer.alloc(32, 7);
  const hash = hashApiKeySecret(pepper, secret);
  assert.match(hash, /^[0-9a-f]{64}$/);
  assert.notEqual(hash, hashApiKeySecret(Buffer.alloc(32, 8), secret));
  assert.ok(secretMatches(pepper, secret, hash));
  assert.ok(!secretMatches(pepper, `${secret.slice(0, -1)}A`, hash) || secret.endsWith('A'));
  assert.ok(!secretMatches(pepper, secret, ''));
});

test('action patterns and constraints', () => {
  assert.ok(actionMatches('orders:*', 'orders:create'));
  assert.ok(actionMatches('orders:*', 'orders:refund:partial'));
  assert.ok(!actionMatches('orders:*', 'orders'));
  assert.ok(!actionMatches('orders:*', 'ordersx:create'));
  assert.ok(!actionMatches('*', 'orders:create'));
  assert.ok(actionMatches('payments:create', 'payments:create'));
  assert.ok(!actionMatches('payments:create', 'payments:create:x'));
  assert.ok(constraintsSatisfied({}, '', {}));
  assert.ok(constraintsSatisfied({ maxAmount: 10, currency: 'USD', resources: ['r'] }, 'r', { amount: 10, currency: 'USD' }));
  assert.ok(!constraintsSatisfied({ maxAmount: 10 }, '', { amount: '5' }));
  assert.ok(!constraintsSatisfied({ resources: ['r'] }, '', {}));
});

test('ULIDs are 26 Crockford base32 chars and time-ordered', () => {
  const a = ulid(1000);
  const b = ulid(2000);
  assert.match(a, /^[0-9A-HJKMNP-TV-Z]{26}$/);
  assert.ok(a < b);
});
