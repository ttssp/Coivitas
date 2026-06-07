/**
 * communication package encoding constants
 *
 * Summary: from v0.2.0 onward, all NegotiationEnvelope signatures default to base64url;
 * verifyEnvelope auto-supports both formats via crypto.verify(), so v0.1.0 hex signatures remain verifiable.
 */
export const ENVELOPE_ENCODING: 'hex' | 'base64url' = 'base64url';
