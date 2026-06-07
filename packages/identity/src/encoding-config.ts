/**
 * identity package encoding constant
 *
 * Conclusion: from v0.2.0 onward, all signature output at the identity layer defaults to base64url;
 * the read side is dual-format compatible via detectEncoding(), ensuring v0.1.0 hex fixtures remain verifiable.
 */
export const IDENTITY_ENCODING: 'hex' | 'base64url' = 'base64url';
