// Agent-side helper: runs on the agent host. The private key never leaves it.
//
//   import { generateAgentKey, proofOfPossession, signRequest } from 'kyagent/src/sdk/agentSigner.js';
//   const { privateKey, publicKey } = generateAgentKey();
//   const pop = proofOfPossession(privateKey, operatorId, publicKey);
//   const signedRequest = signRequest(privateKey, { agentId, audience, action, resource, context });
import { randomBytes } from 'node:crypto';
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
