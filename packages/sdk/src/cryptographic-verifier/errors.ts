/**
 * SdkError — sdk sub-protocol L0 error class
 *
 * Summary: extends Error
 * (same pattern as the 6 sub-protocol L0 error classes CrError/HashChainError/AuditShareError/
 *  AuditError/SrError/DaError; it does not extend ProtocolError, to avoid the frozen
 *  union .detail: string type conflict).
 *
 * Design details:
 * - typed sub-code union (SdkErrorCode); does not pollute the frozen 53-entry ProtocolErrorCode
 * - message format `[<CODE>] <detail>` (carries forward the hcc lesson; friendly to vitest `.toThrow(/CODE/)`)
 * - carries only the failure-path error codes of the sdk v0.2 cryptographic verifier (6 entries)
 */

/** sdk v0.2 frozen error code union (6 entries) */
export type SdkErrorCode =
    | 'SDK_MTLS_VERIFY_FAILED'
    | 'SDK_JWT_VERIFY_FAILED'
    | 'SDK_OAUTH2_VERIFY_FAILED'
    | 'SDK_MAPPING_MISMATCH'
    | 'SDK_SCHEMA_VIOLATION'
    | 'SDK_FIXTURE_CROSS_LANG_MISMATCH';

/**
 * SdkError — failure-path error class for the sdk cryptographic verifier
 *
 * @example
 *   throw new SdkError('SDK_JWT_VERIFY_FAILED', 'JWT exp expired');
 *   // → err.message === '[SDK_JWT_VERIFY_FAILED] JWT exp expired'
 */
export class SdkError extends Error {
    public readonly code: SdkErrorCode;
    public readonly detail: string;

    public constructor(code: SdkErrorCode, detail: string) {
        super(`[${code}] ${detail}`);
        this.name = 'SdkError';
        this.code = code;
        this.detail = detail;
    }
}
