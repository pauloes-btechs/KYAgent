// Business-side helper: runs on the relying party's server. Forwards an agent's
// signed request to POST /v1/verify and fails closed on anything unexpected.
//
//   import { createVerifier } from 'kyagent/src/sdk/businessVerifier.js';
//   const kya = createVerifier({ baseUrl: process.env.KYA_BASE_URL, apiKey: process.env.KYA_API_KEY });
//   const decision = await kya.verifyIncoming({ headers: req.headers, action: 'payments:create', context });
//   if (!isAllowed(decision)) return reject(decision.reasons[0].code);
import { RISK_DECISIONS } from '../contracts.js';
import { KYA_HEADERS } from './agentSigner.js';

const API_KEY_RE = /^kya_key_[0-9A-HJKMNP-TV-Z]{26}_[A-Za-z0-9_-]{43}$/;
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);
const MAX_SIGNED_HEADER_CHARS = 4096;
const MAX_CREDENTIAL_CHARS = 8192;
const MAX_RESPONSE_BYTES = 64 * 1024;

export class KyaSdkError extends Error {}

/**
 * True only for a genuine ALLOW decision. Everything else is a denial. An optional
 * `riskDecision` (decision-vocabulary.md §6) is passed through untouched, but a REVIEW or
 * BLOCK never counts as allowed.
 */
export function isAllowed(decision) {
  return (
    decision?.decision === 'ALLOW' &&
    decision.reasons?.[0]?.code === 'ALLOWED' &&
    (decision.riskDecision === undefined || decision.riskDecision === 'ALLOW')
  );
}

/** Locally produced DENY (never reached, or could not trust, the service). */
function localDeny(code, message, request) {
  return {
    verificationId: null,
    decision: 'DENY',
    reasons: [{ code, message }],
    agentId: typeof request?.agentId === 'string' ? request.agentId : null,
    operatorId: null,
    action: typeof request?.action === 'string' ? request.action : null,
    grantId: null,
    credentialId: null,
    evaluatedAt: new Date().toISOString(),
    local: true,
  };
}

function headerValue(headers, name) {
  if (!headers) return undefined;
  if (typeof headers.get === 'function') return headers.get(name) ?? undefined;
  const key = Object.keys(headers).find((k) => k.toLowerCase() === name);
  return key === undefined ? undefined : headers[key];
}

/**
 * Extract `{ signedRequest, credential }` from agent request headers (Fetch
 * `Headers` or Node's `req.headers`). Throws KyaSdkError if absent or malformed.
 */
export function readSignedHeaders(headers) {
  const raw = headerValue(headers, KYA_HEADERS.signedRequest);
  if (raw === undefined) throw new KyaSdkError(`missing ${KYA_HEADERS.signedRequest} header`);
  if (typeof raw !== 'string' || raw.length > MAX_SIGNED_HEADER_CHARS || !/^[A-Za-z0-9_-]+$/.test(raw)) {
    throw new KyaSdkError(`malformed ${KYA_HEADERS.signedRequest} header`);
  }
  let signedRequest;
  try {
    signedRequest = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8'));
  } catch {
    throw new KyaSdkError(`malformed ${KYA_HEADERS.signedRequest} header`);
  }
  if (signedRequest === null || typeof signedRequest !== 'object' || Array.isArray(signedRequest)) {
    throw new KyaSdkError(`malformed ${KYA_HEADERS.signedRequest} header`);
  }
  const credential = headerValue(headers, KYA_HEADERS.credential);
  if (credential !== undefined && (typeof credential !== 'string' || credential.length > MAX_CREDENTIAL_CHARS)) {
    throw new KyaSdkError(`malformed ${KYA_HEADERS.credential} header`);
  }
  return { signedRequest, credential };
}

function parseBaseUrl(baseUrl, allowInsecureHttp) {
  let url;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new KyaSdkError('baseUrl must be an absolute URL');
  }
  if (url.username || url.password) throw new KyaSdkError('baseUrl must not contain credentials');
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && (allowInsecureHttp || LOOPBACK_HOSTS.has(url.hostname)))) {
    throw new KyaSdkError('baseUrl must use https (plain http is only allowed for loopback)');
  }
  return url.origin + url.pathname.replace(/\/+$/, '');
}

async function readCapped(res) {
  const len = Number(res.headers.get('content-length'));
  if (Number.isFinite(len) && len > MAX_RESPONSE_BYTES) return null;
  const text = await res.text();
  return text.length > MAX_RESPONSE_BYTES ? null : text;
}

/**
 * Create a /v1/verify client for a business API key. The key stays in this
 * closure; it is never returned, logged or included in errors.
 */
export function createVerifier({ baseUrl, apiKey, timeoutMs = 5000, fetch: fetchImpl = globalThis.fetch, allowInsecureHttp = false } = {}) {
  if (typeof apiKey !== 'string' || !API_KEY_RE.test(apiKey)) throw new KyaSdkError('apiKey must be a KYAgent business API key (kya_key_…)');
  if (typeof fetchImpl !== 'function') throw new KyaSdkError('fetch implementation required');
  const endpoint = `${parseBaseUrl(baseUrl, allowInsecureHttp)}/v1/verify`;

  /** POST a VerifyRequest body. Resolves to a VerifyResponse; never rejects. */
  async function verify(request) {
    let res;
    let text;
    const controller = new AbortController();
    let timer;
    // Enforced here too, so a fetch implementation that ignores `signal` cannot hang the caller.
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(Object.assign(new Error('timeout'), { name: 'TimeoutError' }));
      }, timeoutMs);
    });
    try {
      const call = (async () => {
        const r = await fetchImpl(endpoint, {
          method: 'POST',
          headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json', accept: 'application/json' },
          body: JSON.stringify(request),
          redirect: 'error',
          signal: controller.signal,
        });
        return [r, await readCapped(r)];
      })();
      call.catch(() => {});
      [res, text] = await Promise.race([call, timeout]);
    } catch (err) {
      const why = err?.name === 'TimeoutError' ? 'timed out' : 'unreachable';
      return localDeny('INTERNAL_ERROR', `verification service ${why}`, request);
    } finally {
      clearTimeout(timer);
    }
    if (res.status === 401 || res.status === 403) {
      return localDeny('INTERNAL_ERROR', `verification service rejected the business API key (${res.status})`, request);
    }
    let body;
    try {
      body = text === null ? null : JSON.parse(text);
    } catch {
      body = null;
    }
    const wellFormed =
      body !== null &&
      typeof body === 'object' &&
      (body.decision === 'ALLOW' || body.decision === 'DENY') &&
      Array.isArray(body.reasons) &&
      body.reasons.length > 0 &&
      typeof body.reasons[0]?.code === 'string' &&
      // Tolerated, never required; an unknown value is untrustworthy.
      (body.riskDecision === undefined || RISK_DECISIONS.includes(body.riskDecision));
    if (!wellFormed || (res.status !== 200 && res.status !== 500)) {
      return localDeny('INTERNAL_ERROR', `unexpected response from verification service (${res.status})`, request);
    }
    if (body.decision === 'ALLOW') {
      // Only honour an ALLOW that is about this exact agent and action.
      if (res.status !== 200 || !isAllowed(body) || body.agentId !== request?.agentId || body.action !== request?.action) {
        return localDeny('INTERNAL_ERROR', 'inconsistent ALLOW from verification service', request);
      }
    }
    return body;
  }

  /**
   * Verify an incoming agent HTTP request. `action`, `resource` and `context`
   * must be what YOUR server is about to do; the signature must cover exactly them.
   */
  async function verifyIncoming({ headers, action, resource, context }) {
    let parsed;
    try {
      parsed = readSignedHeaders(headers);
    } catch (err) {
      return localDeny('MALFORMED_REQUEST', err.message, { action });
    }
    const { signedRequest, credential } = parsed;
    const request = { agentId: signedRequest.agentId, action, signedRequest };
    if (resource !== undefined) request.resource = resource;
    if (context !== undefined) request.context = context;
    if (credential !== undefined) request.credential = credential;
    return verify(request);
  }

  return Object.freeze({ verify, verifyIncoming });
}
