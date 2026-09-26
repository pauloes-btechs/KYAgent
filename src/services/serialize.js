// Store documents -> API wire objects (types.ts). Never emits secrets or hashes.

const iso = (d) => (d instanceof Date ? d.toISOString() : d ?? null);

export const apiKeyOut = (k) => ({
  id: k.id,
  name: k.name,
  role: k.role,
  ownerId: k.ownerId ?? null,
  status: k.status,
  displayPrefix: `kya_${k.id}`,
  createdAt: iso(k.createdAt),
  lastUsedAt: iso(k.lastUsedAt),
  revokedAt: iso(k.revokedAt),
});

export const businessOut = (b) => ({ id: b.id, name: b.name, status: b.status, createdAt: iso(b.createdAt) });

export const operatorOut = (o) => ({
  id: o.id,
  type: o.type,
  legalName: o.legalName,
  contactEmail: o.contactEmail,
  country: o.country,
  status: o.status,
  verification: o.verification ? { ...o.verification, checkedAt: iso(o.verification.checkedAt) } : null,
  statusReason: o.statusReason ?? null,
  createdAt: iso(o.createdAt),
  updatedAt: iso(o.updatedAt),
});

export const operatorPublicOut = (o) => ({ id: o.id, type: o.type, legalName: o.legalName, country: o.country, status: o.status });

export const agentOut = (a) => ({
  id: a.id,
  operatorId: a.operatorId,
  name: a.name,
  description: a.description ?? null,
  publicKey: a.publicKey,
  keyThumbprint: a.keyThumbprint,
  status: a.status,
  statusReason: a.statusReason ?? null,
  createdAt: iso(a.createdAt),
  updatedAt: iso(a.updatedAt),
  revokedAt: iso(a.revokedAt),
});

export const grantOut = (g) => ({
  id: g.id,
  businessId: g.businessId,
  agentId: g.agentId,
  operatorId: g.operatorId,
  actions: [...g.actions],
  constraints: { ...g.constraints },
  status: g.status,
  expiresAt: iso(g.expiresAt),
  createdAt: iso(g.createdAt),
  revokedAt: iso(g.revokedAt),
  statusReason: g.statusReason ?? null,
});

export const credentialOut = (c) => ({
  id: c.id,
  agentId: c.agentId,
  operatorId: c.operatorId,
  businessId: c.businessId,
  grantId: c.grantId,
  actions: [...c.actions],
  status: c.status,
  issuedAt: iso(c.issuedAt),
  expiresAt: iso(c.expiresAt),
  revokedAt: iso(c.revokedAt),
  statusReason: c.statusReason ?? null,
});

export const eventOut = (e) => ({
  verificationId: e.id,
  decision: e.decision,
  reasons: e.reasons.map((r) => ({ code: r.code, message: r.message })),
  agentId: e.agentId ?? null,
  operatorId: e.operatorId ?? null,
  action: e.action ?? null,
  grantId: e.grantId ?? null,
  credentialId: e.credentialId ?? null,
  evaluatedAt: iso(e.evaluatedAt),
  businessId: e.businessId,
  requestId: e.requestId,
});

export const pageOut = (page, fn) => ({ data: page.data.map(fn), nextCursor: page.nextCursor });

export const auditEventOut = (e) => ({
  id: e.id,
  seq: e.seq,
  type: e.type,
  occurredAt: iso(e.occurredAt),
  actor: { role: e.actor.role, apiKeyId: e.actor.apiKeyId ?? null, ownerId: e.actor.ownerId ?? null },
  subjectType: e.subjectType,
  subjectId: e.subjectId,
  requestId: e.requestId ?? null,
  data: structuredClone(e.data ?? {}),
  prevHash: e.prevHash,
  hash: e.hash,
});
