/**
 * policy/recorder encoding constants
 *
 * Conclusion: from v0.2.0 onward, ledger records (record_hash / actor_signature / ledger_signature)
 * output base64url by default; IntegrityChecker reads both formats via detectEncoding(),
 * ensuring v0.1.0 hex historical records are not mistakenly flagged as corrupted.
 */
export const LEDGER_ENCODING: 'hex' | 'base64url' = 'base64url';
