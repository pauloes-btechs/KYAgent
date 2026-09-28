// MVP operator verification: deterministic mock KYC + sanctions screen
// (data-schema.md "Mock KYC/sanctions"). Real third-party KYC is a non-goal.
//
// The legal-name regex below is ONLY the SANCTIONS_MODE=fixture operator-onboarding screen
// (config.sanctionsMode `mock`; `off` skips it). Agent wallet / counterparty screening — the
// exact-wallet INV_SANCTIONS_EXACT_BLOCK invariant and the Atlas `$search` fuzzy/alias/phonetic
// name screen — lives in src/sanctions/screen.js and runs as the investigation `sanctions` stage.

export function mockKyc(legalName) {
  return /FAIL_KYC/i.test(legalName) ? 'fail' : 'pass';
}

export const FIXTURE_SANCTIONED_NAME = /SANCTIONED/i;

export function sanctionsScreen(legalName, sanctionsMode) {
  if (sanctionsMode === 'off') return 'skipped';
  return FIXTURE_SANCTIONED_NAME.test(legalName) ? 'hit' : 'clear';
}

export function runOperatorVerification(operator, sanctionsMode, now) {
  const kycResult = mockKyc(operator.legalName);
  const sanctionsResult = sanctionsScreen(operator.legalName, sanctionsMode);
  const status = kycResult === 'pass' && sanctionsResult !== 'hit' ? 'verified' : 'rejected';
  let statusReason = null;
  if (kycResult === 'fail') statusReason = 'KYC check failed';
  else if (sanctionsResult === 'hit') statusReason = 'Sanctions screening hit';
  return {
    status,
    statusReason,
    verification: { method: 'mock', kycResult, sanctionsMode, sanctionsResult, checkedAt: now },
  };
}
