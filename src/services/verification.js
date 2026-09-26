// POST /v1/verify — deny-by-default decision engine (ARCHITECTURE.md §3).
// Checks run in the normative order and short-circuit on the first failure.
// Any exception yields DENY / INTERNAL_ERROR (HTTP 500).
import { ACTION_RE, ID_PREFIX, REASON_MESSAGES, RESOURCE_ID_RE } from '../contracts.js';
import { buildSigningString, canonicalJson, CanonicalJsonError } from '../crypto/canonical.js';
import { verifyCredentialJws } from '../crypto/credentials.js';
import { parsePublicKey, sha256hex, verifySignature } from '../crypto/ed25519.js';
import { newId } from '../ids.js';
import { schemas, validate } from '../validate.js';
import { invariant } from '../harness/invariants.js';
import { anyActionMatches, actionMatches } from './authz.js';
import { eventOut, pageOut } from './serialize.js';
import { pageQuery } from './util.js';

const MAX_CONTEXT_BYTES = 8 * 1024;
// Steps 9i/10c: grant constraints are the immutable INV_DELEGATION_MAX (harness.md §1).
const withinDelegationMax = (constraints, resource, context) =>
  invariant('INV_DELEGATION_MAX').check({ constraints, resource, context });

class Deny {
  constructor(code) {
    this.code = code;
  }
}
const deny = (code) => {
  throw new Deny(code);
};

/** Step 1: schema + signed/unsigned field consistency. Returns the normalized request. */
function checkWellFormed(body) {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) deny('MALFORMED_REQUEST');
  if (validate(schemas.verifyRequest, body).length) deny('MALFORMED_REQUEST');
  const sr = body.signedRequest;
  const resource = body.resource ?? '';
  let canonical;
  try {
    canonical = canonicalJson(body.context ?? {});
  } catch (err) {
    if (err instanceof CanonicalJsonError) deny('MALFORMED_REQUEST');
    throw err;
  }
  if (Buffer.byteLength(canonical, 'utf8') > MAX_CONTEXT_BYTES) deny('MALFORMED_REQUEST');
  if (
    sr.agentId !== body.agentId ||
    sr.action !== body.action ||
    sr.resource !== resource ||
    sr.contextSha256 !== sha256hex(Buffer.from(canonical, 'utf8'))
  ) {
    deny('MALFORMED_REQUEST');
  }
  return { agentId: body.agentId, action: body.action, resource, context: body.context ?? {}, credential: body.credential, sr };
}

export function verificationService({ store, clock, config, audit }) {
  async function evaluate(principal, body, out) {
    const now = clock.now();
    const nowSec = Math.floor(now.getTime() / 1000);
    const businessId = principal.businessId;

    // 1. well-formed
    const req = checkWellFormed(body);
    // 2. audience
    if (req.sr.audience !== businessId) deny('AUDIENCE_MISMATCH');
    // 3. agent exists
    const agent = RESOURCE_ID_RE.test(req.agentId) ? await store.agents.findById(req.agentId) : null;
    if (!agent) deny('AGENT_NOT_FOUND');
    out.operatorId = agent.operatorId;
    // 4. agent status
    if (agent.status === 'revoked') deny('AGENT_REVOKED');
    if (agent.status === 'suspended') deny('AGENT_SUSPENDED');
    if (agent.status !== 'active') deny('AGENT_REVOKED');
    // 5. operator
    const operator = await store.operators.findById(agent.operatorId);
    if (operator?.status === 'suspended') deny('OPERATOR_SUSPENDED');
    if (!operator || operator.status !== 'verified') deny('OPERATOR_NOT_VERIFIED');
    // 6. timestamp window
    if (Math.abs(nowSec - req.sr.timestamp) > config.maxSkewSeconds) deny('TIMESTAMP_OUT_OF_WINDOW');
    // 7. signature over the signed fields, with the registered key
    const signingString = buildSigningString(req.sr);
    if (!verifySignature(parsePublicKey(agent.publicKey), signingString, req.sr.signature)) deny('SIGNATURE_INVALID');
    // 8. nonce (recorded only after the signature verified)
    const nonceExpires = new Date((req.sr.timestamp + 2 * config.maxSkewSeconds) * 1000);
    if (!(await store.nonces.insertOnce(agent.id, req.sr.nonce, nonceExpires, now))) deny('NONCE_REPLAYED');

    if (req.credential !== undefined) {
      // 9a. signature / header / issuer
      const claims = verifyCredentialJws(req.credential, {
        publicKey: config.signingPublicKey,
        kid: config.kid,
        issuer: config.issuer,
      });
      if (!claims) deny('CREDENTIAL_INVALID');
      // 9b. time
      if (claims.nbf > nowSec) deny('CREDENTIAL_NOT_YET_VALID');
      if (!(claims.exp > nowSec)) deny('CREDENTIAL_EXPIRED');
      // 9c-9e. binding
      if (claims.sub !== agent.id) deny('CREDENTIAL_SUBJECT_MISMATCH');
      if (claims.aud !== businessId) deny('CREDENTIAL_AUDIENCE_MISMATCH');
      if (claims.cnf.jkt !== agent.keyThumbprint) deny('CREDENTIAL_KEY_MISMATCH');
      // 9f. record status (uncached)
      const record = await store.credentials.findById(claims.jti);
      if (!record || record.agentId !== agent.id || record.grantId !== claims.kya_grant) deny('CREDENTIAL_INVALID');
      out.credentialId = record.id;
      if (record.status !== 'active') deny('CREDENTIAL_REVOKED');
      // 9g. grant status (uncached)
      const grant = await store.grants.findById(claims.kya_grant);
      if (!grant || grant.status !== 'active') deny('GRANT_REVOKED');
      if (grant.agentId !== agent.id || grant.businessId !== businessId) deny('CREDENTIAL_INVALID');
      if (!(grant.expiresAt > now)) deny('GRANT_EXPIRED');
      out.grantId = grant.id;
      // 9h. scope: both credential and grant must permit the action
      if (!anyActionMatches(claims.kya_actions, req.action) || !anyActionMatches(grant.actions, req.action)) {
        deny('ACTION_NOT_PERMITTED');
      }
      // 9i. constraints (grant is authoritative; credential copy must also hold)
      if (
        !withinDelegationMax(grant.constraints, req.resource, req.context) ||
        !withinDelegationMax(claims.kya_constraints, req.resource, req.context)
      ) {
        deny('CONSTRAINT_VIOLATION');
      }
      return;
    }

    // 10. no credential: evaluate active grants from this business
    const grants = await store.grants.findActiveFor(agent.id, businessId, now);
    if (!grants.length) deny('NO_GRANT');
    const matching = grants.filter((g) => g.actions.some((p) => actionMatches(p, req.action)));
    if (!matching.length) deny('ACTION_NOT_PERMITTED');
    const winner = matching.find((g) => withinDelegationMax(g.constraints, req.resource, req.context));
    if (!winner) deny('CONSTRAINT_VIOLATION');
    out.grantId = winner.id;
  }

  return {
    /**
     * @param principal authenticated business principal
     * @param parsed { ok: boolean, body } — ok=false for unparsable/oversized/non-JSON bodies
     * @returns { status, body: VerifyResponse }
     */
    async verify(principal, parsed, requestId) {
      const body = parsed.ok ? parsed.body : null;
      const isObj = body !== null && typeof body === 'object' && !Array.isArray(body);
      const out = {
        agentId: isObj && typeof body.agentId === 'string' && RESOURCE_ID_RE.test(body.agentId) ? body.agentId : null,
        operatorId: null,
        action: isObj && typeof body.action === 'string' && body.action.length <= 128 && ACTION_RE.test(body.action) ? body.action : null,
        grantId: null,
        credentialId: null,
      };
      let code = 'ALLOWED';
      let status = 200;
      try {
        if (!parsed.ok) deny('MALFORMED_REQUEST');
        await evaluate(principal, body, out);
      } catch (err) {
        if (err instanceof Deny) {
          code = err.code;
        } else {
          code = 'INTERNAL_ERROR';
          status = 500;
        }
      }

      const decision = code === 'ALLOWED' ? 'ALLOW' : 'DENY';
      const event = {
        id: newId(ID_PREFIX.verification),
        businessId: principal.businessId,
        requestId,
        agentId: out.agentId,
        operatorId: out.operatorId,
        action: out.action,
        // A DENY never authorizes anything; only report grant/credential on ALLOW or when identified.
        grantId: out.grantId,
        credentialId: out.credentialId,
        decision,
        reasons: [{ code, message: REASON_MESSAGES[code] }],
        evaluatedAt: clock.now(),
      };
      // An unauditable decision must not be an ALLOW: fail closed.
      const failClosed = () => {
        event.decision = 'DENY';
        event.reasons = [{ code: 'INTERNAL_ERROR', message: REASON_MESSAGES.INTERNAL_ERROR }];
        status = 500;
      };
      // REQ-008: every decision also enters the hash-chained audit log.
      const recordDecision = () =>
        audit.record(principal, 'verification.decided', { type: 'verification', id: event.id }, {
          decision: event.decision,
          reasonCode: event.reasons[0].code,
          businessId: event.businessId,
          agentId: event.agentId,
          operatorId: event.operatorId,
          action: event.action,
          grantId: event.grantId,
          credentialId: event.credentialId,
        });
      try {
        await recordDecision();
      } catch {
        failClosed();
      }
      try {
        await store.verificationEvents.insert(event);
      } catch {
        const wasAllow = event.decision === 'ALLOW';
        failClosed();
        // The audit log already says ALLOW: append the final (DENY) outcome, best effort.
        if (wasAllow) await recordDecision().catch(() => {});
      }
      const response = eventOut(event);
      delete response.businessId;
      delete response.requestId;
      return { status, body: response };
    },

    async list(principal, q) {
      const filter = { agentId: q.agentId, decision: q.decision };
      if (principal.role === 'business') filter.businessId = principal.businessId;
      return pageOut(await store.verificationEvents.list(pageQuery(q, filter)), eventOut);
    },
  };
}
