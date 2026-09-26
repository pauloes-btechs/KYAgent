// MVP operator verification: deterministic mock KYC + sanctions screen
// (data-schema.md "Mock KYC/sanctions"). Real third-party KYC is a non-goal.

export function mockKyc(legalName) {
  return /FAIL_KYC/i.test(legalName) ? 'fail' : 'pass';
}

export function sanctionsScreen(legalName, sanctionsMode) {
  if (sanctionsMode === 'off') return 'skipped';
  return /SANCTIONED/i.test(legalName) ? 'hit' : 'clear';
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
