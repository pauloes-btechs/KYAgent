// Agent-side helper: runs on the agent host. The private key never leaves it.
//
//   import { generateAgentKey, proofOfPossession, signRequest } from 'kyagent/src/sdk/agentSigner.js';
//   const { privateKey, publicKey } = generateAgentKey();
//   const pop = proofOfPossession(privateKey, operatorId, publicKey);
//   const signedRequest = signRequest(privateKey, { agentId, audience, action, resource, context });
import { createPrivateKey, randomBytes } from 'node:crypto';
import { SIG_VERSION } from '../contracts.js';
import { buildRegisterMessage, buildSigningString, contextSha256 } from '../crypto/canonical.js';
import { generateEd25519, privateKeyFromSeed, publicKeyB64u, signMessage } from '../crypto/ed25519.js';

export function generateAgentKey() {
  return generateEd25519();
}

export function agentKeyFromSeed(seed) {
  const privateKey = privateKeyFromSeed(seed);
  return { privateKey, publicKey: publicKeyB64u(privateKey) };
}

export function proofOfPossession(privateKey, operatorId, publicKey) {
  return signMessage(privateKey, buildRegisterMessage(operatorId, publicKey));
}

export const newNonce = () => randomBytes(24).toString('base64url');

/** Build a KYA-SIG-V1 SignedRequest (crypto-and-signing.md §3). */
export function signRequest(privateKey, { agentId, audience, action, resource = '', context = {}, timestamp, nonce }) {
  const fields = {
    agentId,
    audience,
    action,
    resource,
    contextSha256: contextSha256(context),
    timestamp: timestamp ?? Math.floor(Date.now() / 1000),
    nonce: nonce ?? newNonce(),
  };
  return { version: SIG_VERSION, ...fields, signature: signMessage(privateKey, buildSigningString(fields)) };
}

/** Convenience: the full VerifyRequest body a business forwards to POST /v1/verify. */
export function buildVerifyRequest(privateKey, { agentId, audience, action, resource, context, credential, timestamp, nonce }) {
  const body = { agentId, action };
  if (resource !== undefined) body.resource = resource;
  if (context !== undefined) body.context = context;
  if (credential !== undefined) body.credential = credential;
  body.signedRequest = signRequest(privateKey, { agentId, audience, action, resource: resource ?? '', context: context ?? {}, timestamp, nonce });
  return body;
}

// ---------------------------------------------------------------- HTTP transport
// Agents send their signature to a business as HTTP headers. The business then
// derives action/resource/context from what it is about to do, and
// businessVerifier.js checks that the agent signed exactly those values.
export const KYA_HEADERS = Object.freeze({ signedRequest: 'kya-signed-request', credential: 'kya-credential' });

/** Headers carrying a KYA-SIG-V1 signature (base64url JSON) and optional credential JWS. */
export function signedHeaders(privateKey, { agentId, audience, action, resource = '', context = {}, credential, timestamp, nonce }) {
  const signedRequest = signRequest(privateKey, { agentId, audience, action, resource, context, timestamp, nonce });
  const headers = { [KYA_HEADERS.signedRequest]: Buffer.from(JSON.stringify(signedRequest), 'utf8').toString('base64url') };
  if (credential !== undefined) headers[KYA_HEADERS.credential] = credential;
  return headers;
}

// ---------------------------------------------------------------- key storage
// Private keys must never be stored in plaintext: export only as encrypted PKCS#8.
const MIN_PASSPHRASE_LENGTH = 12;

function checkPassphrase(passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error(`passphrase must be a string of at least ${MIN_PASSPHRASE_LENGTH} characters`);
  }
}

/** Encrypted PKCS#8 PEM (AES-256-CBC) for storing the agent key at rest. */
export function exportAgentKey(privateKey, passphrase) {
  checkPassphrase(passphrase);
  return privateKey.export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase });
}

/** Load a key written by exportAgentKey. Unencrypted PEMs are rejected. */
export function importAgentKey(pem, passphrase) {
  checkPassphrase(passphrase);
  if (typeof pem !== 'string' || !pem.includes('-----BEGIN ENCRYPTED PRIVATE KEY-----')) {
    throw new Error('agent key must be an encrypted PKCS#8 PEM');
  }
  const privateKey = createPrivateKey({ key: pem, format: 'pem', passphrase });
  if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('agent key must be Ed25519');
  return { privateKey, publicKey: publicKeyB64u(privateKey) };
}
