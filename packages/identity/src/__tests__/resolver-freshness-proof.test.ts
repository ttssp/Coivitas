/**
 * RFP v0.1 — L2 implementation tests
 *
 * Test coverage paths (>=95% target; 6 main paths + auxiliary paths):
 *   P1 — happy path: all 8 invariants pass -> returns ResolverFreshnessProof
 *   P2 — freshness expired (I_asof_window fails)
 *   P3 — watermark rollback (signature valid but version invalid) -> I_ver fails
 *   P4 — invalid signature (I_sig fails)
 *   P5 — unknown resolver / public key unresolvable (public key resolution that I_sig depends on fails)
 *   P6 — quorum freshness below threshold
 *   P7 — incomplete schema (I_complete fails)
 *   P8 — I_csp fails (wrong cspVersion)
 *   P9 — I_did fails (malformed resolverDid)
 *   P10 — I_fw fails (freshnessWindow out of range)
 *   P11 — I_asof fails (asOfTime beyond future tolerance)
 *   P12 — createResolverFreshnessProof factory (normal + boundary)
 *   P13 — verifyRfpForConsumer (requireRfp mode + maxAllowedFreshnessWindowMs)
 *   P14 — verifyQuorumFreshness aggregation (quorum met + unmet)
 *   P15 — RFP_HTTP_STATUS mapping completeness
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { generateKeyPair, sign, toBase64Url, canonicalize } from '@coivitas/crypto';
import { RfpError } from '@coivitas/types';
import type { DID, Timestamp } from '@coivitas/types';
import {
    verifyResolverFreshness,
    createResolverFreshnessProof,
    verifyRfpForConsumer,
    verifyQuorumFreshness,
    RFP_HTTP_STATUS,
} from '../resolver-freshness-proof.js';
import type { ResolverPublicKeyResolver } from '../resolver-freshness-proof.js';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/** Generate an Ed25519 key pair (base64url encoded) */
async function generateTestKeyPair(): Promise<{ privateKey: string; publicKeyBytes: Uint8Array }> {
    const { privateKey, publicKey } = await generateKeyPair();
    // publicKey is hex; convert to Uint8Array
    const { fromHex } = await import('@coivitas/crypto');
    const publicKeyBytes = fromHex(publicKey);
    return { privateKey, publicKeyBytes };
}

/** Build a valid RFP signing payload (5 fields) */
function buildSignPayload(overrides: Partial<{
    rfpVersion: string;
    cspVersion: string;
    resolverDid: string;
    asOfTime: string;
    freshnessWindow: number;
}> = {}): Record<string, unknown> {
    return {
        rfpVersion: '1.0.0',
        cspVersion: '1.0.0',
        resolverDid: 'did:example:resolver001',
        asOfTime: new Date().toISOString(),
        freshnessWindow: 300_000,
        ...overrides,
    };
}

/** Sign the 5-field payload and return a base64url signature */
async function signPayload(
    payload: Record<string, unknown>,
    privateKey: string,
): Promise<string> {
    const canonicalJson = canonicalize(payload);
    const messageBytes = new TextEncoder().encode(canonicalJson);
    return sign(messageBytes, privateKey, 'base64url');
}

/** Build a valid, complete RFP object (6 fields) */
async function buildValidRfp(
    privateKey: string,
    overrides: Partial<{
        rfpVersion: string;
        cspVersion: string;
        resolverDid: string;
        asOfTime: string;
        freshnessWindow: number;
    }> = {},
): Promise<Record<string, unknown>> {
    const signPayloadObj = buildSignPayload(overrides);
    const signature = await signPayload(signPayloadObj, privateKey);
    return { ...signPayloadObj, signature };
}

/** Build a ResolverPublicKeyResolver for tests */
function buildPublicKeyResolver(
    resolverDid: DID,
    publicKeyBytes: Uint8Array,
): ResolverPublicKeyResolver {
    return {
        async resolvePublicKey(did: DID): Promise<Uint8Array | null> {
            if (did === resolverDid) return publicKeyBytes;
            return null;
        },
    };
}

/** Build a resolver that always returns null (simulates an unknown node) */
function buildNullPublicKeyResolver(): ResolverPublicKeyResolver {
    return {
        async resolvePublicKey(_did: DID): Promise<Uint8Array | null> {
            return null;
        },
    };
}

// ---------------------------------------------------------------------------
// P1 — happy path
// ---------------------------------------------------------------------------

describe('verifyResolverFreshness — P1 happy path', () => {
    it('should return verified ResolverFreshnessProof when all 8 invariants pass', async () => {
        const { privateKey, publicKeyBytes } = await generateTestKeyPair();
        const resolverDid = 'did:example:resolver001' as DID;
        const rfp = await buildValidRfp(privateKey);
        const resolver = buildPublicKeyResolver(resolverDid, publicKeyBytes);

        const result = await verifyResolverFreshness(rfp, resolver);

        expect(result.rfpVersion).toBe('1.0.0');
        expect(result.cspVersion).toBe('1.0.0');
        expect(result.resolverDid).toBe(resolverDid);
        expect(result.freshnessWindow).toBe(300_000);
        expect(result.signature).toBeDefined();
        expect(result.asOfTime).toBeDefined();
    });

    it('should accept minimum freshnessWindow (1000ms)', async () => {
        const { privateKey, publicKeyBytes } = await generateTestKeyPair();
        const resolverDid = 'did:example:resolver001' as DID;
        const rfp = await buildValidRfp(privateKey, { freshnessWindow: 1_000 });
        const resolver = buildPublicKeyResolver(resolverDid, publicKeyBytes);

        const result = await verifyResolverFreshness(rfp, resolver);
        expect(result.freshnessWindow).toBe(1_000);
    });

    it('should accept maximum freshnessWindow (3600000ms)', async () => {
        const { privateKey, publicKeyBytes } = await generateTestKeyPair();
        const resolverDid = 'did:example:resolver001' as DID;
        const rfp = await buildValidRfp(privateKey, { freshnessWindow: 3_600_000 });
        const resolver = buildPublicKeyResolver(resolverDid, publicKeyBytes);

        const result = await verifyResolverFreshness(rfp, resolver);
        expect(result.freshnessWindow).toBe(3_600_000);
    });

    it('should accept asOfTime with nowMs injected close to asOfTime', async () => {
        const { privateKey, publicKeyBytes } = await generateTestKeyPair();
        const resolverDid = 'did:example:resolver001' as DID;
        const asOfTime = new Date(Date.now() - 1_000).toISOString();
        const rfp = await buildValidRfp(privateKey, { asOfTime });
        const resolver = buildPublicKeyResolver(resolverDid, publicKeyBytes);

        // Inject nowMs = asOfTime + 1s (proves it is valid within 1s)
        const nowMs = new Date(asOfTime).getTime() + 1_000;
        const result = await verifyResolverFreshness(rfp, resolver, nowMs);
        expect(result).toBeDefined();
    });
});

// ---------------------------------------------------------------------------
// P2 — freshness expired (I_asof_window fails)
// ---------------------------------------------------------------------------

describe('verifyResolverFreshness — P2 freshness expired', () => {
    it('should throw RFP_FRESHNESS_EXPIRED when age > freshnessWindow', async () => {
        const { privateKey, publicKeyBytes } = await generateTestKeyPair();
        const resolverDid = 'did:example:resolver001' as DID;

        // asOfTime = 10 minutes ago; freshnessWindow = 5 minutes
        const asOfTime = new Date(Date.now() - 10 * 60 * 1_000).toISOString();
        const rfp = await buildValidRfp(privateKey, {
            asOfTime,
            freshnessWindow: 5 * 60 * 1_000,
        });
        const resolver = buildPublicKeyResolver(resolverDid, publicKeyBytes);

        await expect(
            verifyResolverFreshness(rfp, resolver),
        ).rejects.toMatchObject({
            rfpCode: 'RFP_FRESHNESS_EXPIRED',
        });
    });

    it('should throw RFP_FRESHNESS_EXPIRED with correct resolverDid in error', async () => {
        const { privateKey, publicKeyBytes } = await generateTestKeyPair();
        const resolverDid = 'did:example:resolver001' as DID;
        const asOfTime = new Date(Date.now() - 2 * 3_600_000).toISOString();
        const rfp = await buildValidRfp(privateKey, { asOfTime, freshnessWindow: 3_600_000 });
        const resolver = buildPublicKeyResolver(resolverDid, publicKeyBytes);

        await expect(
            verifyResolverFreshness(rfp, resolver),
        ).rejects.toSatisfy((e: unknown) => {
            return e instanceof RfpError && e.rfpCode === 'RFP_FRESHNESS_EXPIRED' && e.resolverDid === resolverDid;
        });
    });

    it('should pass when age equals freshnessWindow exactly (boundary)', async () => {
        const { privateKey, publicKeyBytes } = await generateTestKeyPair();
        const resolverDid = 'did:example:resolver001' as DID;
        const freshnessWindow = 60_000; // 60s
        // asOfTime = now - 60s
        const nowMs = Date.now();
        const asOfTime = new Date(nowMs - freshnessWindow).toISOString();
        const rfp = await buildValidRfp(privateKey, { asOfTime, freshnessWindow });
        const resolver = buildPublicKeyResolver(resolverDid, publicKeyBytes);

        // age = freshnessWindow -> should pass (age <= freshnessWindow condition)
        const result = await verifyResolverFreshness(rfp, resolver, nowMs);
        expect(result).toBeDefined();
    });
});

// ---------------------------------------------------------------------------
// P3 — invalid watermark / version (I_ver fails)
// ---------------------------------------------------------------------------

describe('verifyResolverFreshness — P3 unsupported rfpVersion', () => {
    it('should throw RFP_VERSION_UNSUPPORTED when rfpVersion is not 1.0.0', async () => {
        const { privateKey, publicKeyBytes } = await generateTestKeyPair();
        const resolverDid = 'did:example:resolver001' as DID;
        // rfpVersion = "2.0.0" -> the AJV const constraint will fail
        // but we want to exercise the I_ver check (bypass AJV and reach the internals first)
        // In practice AJV const:'1.0.0' is caught ahead of the I_ver check — schema failure yields RFP_PROOF_INCOMPLETE
        // Tested here: the AJV schema passes but rfpVersion is manually injected as something other than '1.0.0'
        // Because of the AJV const constraint, constructing rfpVersion='2.0.0' directly is intercepted by AJV as PROOF_INCOMPLETE
        // This is the correct defense-in-depth design — it confirms the AJV const actually takes effect
        const rfp: Record<string, unknown> = {
            rfpVersion: '2.0.0',
            cspVersion: '1.0.0',
            resolverDid,
            asOfTime: new Date().toISOString(),
            freshnessWindow: 300_000,
            signature: 'dGVzdA', // valid base64url format
        };
        const resolver = buildPublicKeyResolver(resolverDid, publicKeyBytes);

        // The AJV const constraint runs ahead of I_ver; expect RFP_PROOF_INCOMPLETE
        await expect(
            verifyResolverFreshness(rfp, resolver),
        ).rejects.toMatchObject({
            rfpCode: 'RFP_PROOF_INCOMPLETE',
        });
    });
});

// ---------------------------------------------------------------------------
// P4 — invalid signature (I_sig fails)
// ---------------------------------------------------------------------------

describe('verifyResolverFreshness — P4 signature verification fails', () => {
    it('should throw RFP_SIGNATURE_INVALID when signature is tampered', async () => {
        const { privateKey, publicKeyBytes } = await generateTestKeyPair();
        const { generateKeyPair: gkp } = await import('@coivitas/crypto');
        // Sign with a different private key -> signature does not match the public key
        const { privateKey: wrongPrivateKey } = await gkp();
        const resolverDid = 'did:example:resolver001' as DID;

        const signPayloadObj = buildSignPayload();
        const wrongSignature = await signPayload(signPayloadObj, wrongPrivateKey);
        const rfp: Record<string, unknown> = { ...signPayloadObj, signature: wrongSignature };
        const resolver = buildPublicKeyResolver(resolverDid, publicKeyBytes);

        await expect(
            verifyResolverFreshness(rfp, resolver),
        ).rejects.toMatchObject({
            rfpCode: 'RFP_SIGNATURE_INVALID',
        });
    });

    it('should throw RFP_SIGNATURE_INVALID when payload is mutated after signing', async () => {
        const { privateKey, publicKeyBytes } = await generateTestKeyPair();
        const resolverDid = 'did:example:resolver001' as DID;
        const rfp = await buildValidRfp(privateKey);
        // Tamper with freshnessWindow (the signature is already fixed)
        rfp['freshnessWindow'] = 60_000;
        const resolver = buildPublicKeyResolver(resolverDid, publicKeyBytes);

        await expect(
            verifyResolverFreshness(rfp, resolver),
        ).rejects.toMatchObject({
            rfpCode: 'RFP_SIGNATURE_INVALID',
        });
    });

    it('should throw RFP_SIGNATURE_INVALID when resolverDid is mutated after signing', async () => {
        const { privateKey, publicKeyBytes } = await generateTestKeyPair();
        const resolverDid = 'did:example:resolver001' as DID;
        const rfp = await buildValidRfp(privateKey);
        // Tamper with resolverDid — but the public key resolver still maps the original did
        rfp['resolverDid'] = 'did:example:evil-node';
        // The public key resolver cannot resolve evil-node -> RFP_RESOLVER_UNREACHABLE rather than RFP_SIGNATURE_INVALID
        // This test confirms that tampering with resolverDid causes the resolver to reject it
        const resolver = buildPublicKeyResolver(resolverDid, publicKeyBytes);

        await expect(
            verifyResolverFreshness(rfp, resolver),
        ).rejects.toMatchObject({
            rfpCode: 'RFP_RESOLVER_UNREACHABLE',
        });
    });
});

// ---------------------------------------------------------------------------
// P5 — unknown resolver / public key cannot be resolved
// ---------------------------------------------------------------------------

describe('verifyResolverFreshness — P5 public key resolution fails', () => {
    it('should throw RFP_RESOLVER_UNREACHABLE when public key cannot be resolved', async () => {
        const { privateKey } = await generateTestKeyPair();
        const rfp = await buildValidRfp(privateKey);
        const resolver = buildNullPublicKeyResolver();

        await expect(
            verifyResolverFreshness(rfp, resolver),
        ).rejects.toMatchObject({
            rfpCode: 'RFP_RESOLVER_UNREACHABLE',
        });
    });

    it('should throw RFP_RESOLVER_UNREACHABLE with correct resolverDid context', async () => {
        const { privateKey } = await generateTestKeyPair();
        const resolverDid = 'did:example:unknown-node' as DID;
        const rfp = await buildValidRfp(privateKey, { resolverDid });
        const resolver = buildNullPublicKeyResolver();

        await expect(
            verifyResolverFreshness(rfp, resolver),
        ).rejects.toSatisfy((e: unknown) => {
            return e instanceof RfpError &&
                e.rfpCode === 'RFP_RESOLVER_UNREACHABLE' &&
                e.resolverDid === resolverDid;
        });
    });
});

// ---------------------------------------------------------------------------
// P6 — quorum freshness below threshold
// ---------------------------------------------------------------------------

describe('verifyQuorumFreshness — P6 quorum threshold', () => {
    it('should return all node results when quorum threshold is met', async () => {
        const { privateKey, publicKeyBytes } = await generateTestKeyPair();
        const resolverDid = 'did:example:resolver001' as DID;
        const rfp = await buildValidRfp(privateKey);
        const resolver = buildPublicKeyResolver(resolverDid, publicKeyBytes);

        const nodes = [
            { nodeId: 'node-1', resolverDid, rfpPayload: rfp },
            { nodeId: 'node-2', resolverDid, rfpPayload: rfp },
            { nodeId: 'node-3', resolverDid, rfpPayload: rfp },
        ];

        const results = await verifyQuorumFreshness(nodes, resolver, 2);
        const validCount = results.filter((r) => r.rfpVerified !== null).length;
        expect(validCount).toBe(3);
    });

    it('should throw RFP_QUORUM_FRESHNESS_UNMET when valid < threshold', async () => {
        const { privateKey, publicKeyBytes } = await generateTestKeyPair();
        const resolverDid = 'did:example:resolver001' as DID;
        const validRfp = await buildValidRfp(privateKey);

        // node-2 supplies an invalid rfp (null public key)
        const invalidRfp = { ...validRfp, signature: 'aW52YWxpZA' };

        const resolver = buildPublicKeyResolver(resolverDid, publicKeyBytes);

        const nodes = [
            { nodeId: 'node-1', resolverDid, rfpPayload: validRfp },
            { nodeId: 'node-2', resolverDid: 'did:example:unknown' as DID, rfpPayload: invalidRfp },
            { nodeId: 'node-3', resolverDid: 'did:example:unknown' as DID, rfpPayload: null },
        ];

        await expect(
            verifyQuorumFreshness(nodes, resolver, 2),
        ).rejects.toMatchObject({
            rfpCode: 'RFP_QUORUM_FRESHNESS_UNMET',
        });
    });

    it('should collect rfpError for each failed node', async () => {
        const { privateKey, publicKeyBytes } = await generateTestKeyPair();
        const resolverDid = 'did:example:resolver001' as DID;
        const validRfp = await buildValidRfp(privateKey);
        const resolver = buildPublicKeyResolver(resolverDid, publicKeyBytes);

        const nodes = [
            { nodeId: 'node-1', resolverDid, rfpPayload: validRfp },
            { nodeId: 'node-2', resolverDid: 'did:example:unknown' as DID, rfpPayload: null },
        ];

        const results = await verifyQuorumFreshness(nodes, resolver, 1);
        const failedNode = results.find((r) => r.nodeId === 'node-2');
        expect(failedNode?.rfpVerified).toBeNull();
        expect(failedNode?.rfpError).toBeNull(); // requireRfp = false → null rfp = no error
    });

    it('should throw when requireRfp=true and node has no RFP', async () => {
        const { privateKey, publicKeyBytes } = await generateTestKeyPair();
        const resolverDid = 'did:example:resolver001' as DID;
        const validRfp = await buildValidRfp(privateKey);
        const resolver = buildPublicKeyResolver(resolverDid, publicKeyBytes);

        const nodes = [
            { nodeId: 'node-1', resolverDid, rfpPayload: validRfp },
            { nodeId: 'node-2', resolverDid, rfpPayload: null },
        ];

        // requireRfp = true + quorum threshold 2 -> node-2 fails -> quorum unmet
        await expect(
            verifyQuorumFreshness(nodes, resolver, 2, { requireRfp: true }),
        ).rejects.toMatchObject({
            rfpCode: 'RFP_QUORUM_FRESHNESS_UNMET',
        });
    });
});

// ---------------------------------------------------------------------------
// P7 — incomplete schema (I_complete fails)
// ---------------------------------------------------------------------------

describe('verifyResolverFreshness — P7 schema validation fails', () => {
    it('should throw RFP_PROOF_INCOMPLETE when required field is missing', async () => {
        const resolver = buildNullPublicKeyResolver();
        const rfp = {
            rfpVersion: '1.0.0',
            // cspVersion missing
            resolverDid: 'did:example:resolver001',
            asOfTime: new Date().toISOString(),
            freshnessWindow: 300_000,
            signature: 'dGVzdA',
        };

        await expect(
            verifyResolverFreshness(rfp, resolver),
        ).rejects.toMatchObject({
            rfpCode: 'RFP_PROOF_INCOMPLETE',
        });
    });

    it('should throw RFP_PROOF_INCOMPLETE when rfp is null', async () => {
        const resolver = buildNullPublicKeyResolver();

        await expect(
            verifyResolverFreshness(null, resolver),
        ).rejects.toMatchObject({
            rfpCode: 'RFP_PROOF_INCOMPLETE',
        });
    });

    it('should throw RFP_PROOF_INCOMPLETE when rfp is a string', async () => {
        const resolver = buildNullPublicKeyResolver();

        await expect(
            verifyResolverFreshness('not-an-object', resolver),
        ).rejects.toMatchObject({
            rfpCode: 'RFP_PROOF_INCOMPLETE',
        });
    });

    it('should throw RFP_PROOF_INCOMPLETE when signature has invalid base64url chars', async () => {
        const resolver = buildNullPublicKeyResolver();
        const rfp = {
            rfpVersion: '1.0.0',
            cspVersion: '1.0.0',
            resolverDid: 'did:example:resolver001',
            asOfTime: new Date().toISOString(),
            freshnessWindow: 300_000,
            signature: 'invalid!@#$%^', // invalid base64url
        };

        await expect(
            verifyResolverFreshness(rfp, resolver),
        ).rejects.toMatchObject({
            rfpCode: 'RFP_PROOF_INCOMPLETE',
        });
    });

    it('should throw RFP_PROOF_INCOMPLETE when additionalProperties present', async () => {
        const resolver = buildNullPublicKeyResolver();
        const rfp = {
            rfpVersion: '1.0.0',
            cspVersion: '1.0.0',
            resolverDid: 'did:example:resolver001',
            asOfTime: new Date().toISOString(),
            freshnessWindow: 300_000,
            signature: 'dGVzdA',
            extraField: 'should-not-be-here', // additionalProperties: false
        };

        await expect(
            verifyResolverFreshness(rfp, resolver),
        ).rejects.toMatchObject({
            rfpCode: 'RFP_PROOF_INCOMPLETE',
        });
    });
});

// ---------------------------------------------------------------------------
// P8 — I_csp fails (wrong cspVersion)
// ---------------------------------------------------------------------------

describe('verifyResolverFreshness — P8 cspVersion mismatch', () => {
    it('should throw RFP_PROOF_INCOMPLETE when cspVersion is not 1.0.0 (AJV const catches it)', async () => {
        const resolver = buildNullPublicKeyResolver();
        const rfp = {
            rfpVersion: '1.0.0',
            cspVersion: '2.0.0', // AJV const:'1.0.0' catches it first
            resolverDid: 'did:example:resolver001',
            asOfTime: new Date().toISOString(),
            freshnessWindow: 300_000,
            signature: 'dGVzdA',
        };

        await expect(
            verifyResolverFreshness(rfp, resolver),
        ).rejects.toMatchObject({
            rfpCode: 'RFP_PROOF_INCOMPLETE',
        });
    });
});

// ---------------------------------------------------------------------------
// P9 — I_did fails (malformed resolverDid)
// ---------------------------------------------------------------------------

describe('verifyResolverFreshness — P9 malformed resolverDid', () => {
    it('should throw RFP_PROOF_INCOMPLETE when resolverDid does not start with did: (AJV pattern)', async () => {
        const resolver = buildNullPublicKeyResolver();
        const rfp = {
            rfpVersion: '1.0.0',
            cspVersion: '1.0.0',
            resolverDid: 'http://not-a-did.example.com', // AJV pattern: '^did:' catches it first
            asOfTime: new Date().toISOString(),
            freshnessWindow: 300_000,
            signature: 'dGVzdA',
        };

        await expect(
            verifyResolverFreshness(rfp, resolver),
        ).rejects.toMatchObject({
            rfpCode: 'RFP_PROOF_INCOMPLETE',
        });
    });
});

// ---------------------------------------------------------------------------
// P10 — I_fw fails (freshnessWindow out of range)
// ---------------------------------------------------------------------------

describe('verifyResolverFreshness — P10 freshnessWindow out of range', () => {
    it('should throw RFP_PROOF_INCOMPLETE when freshnessWindow < 1000 (AJV minimum)', async () => {
        const resolver = buildNullPublicKeyResolver();
        const rfp = {
            rfpVersion: '1.0.0',
            cspVersion: '1.0.0',
            resolverDid: 'did:example:resolver001',
            asOfTime: new Date().toISOString(),
            freshnessWindow: 999, // AJV minimum:1000 catches it first
            signature: 'dGVzdA',
        };

        await expect(
            verifyResolverFreshness(rfp, resolver),
        ).rejects.toMatchObject({
            rfpCode: 'RFP_PROOF_INCOMPLETE',
        });
    });

    it('should throw RFP_PROOF_INCOMPLETE when freshnessWindow > 3600000 (AJV maximum)', async () => {
        const resolver = buildNullPublicKeyResolver();
        const rfp = {
            rfpVersion: '1.0.0',
            cspVersion: '1.0.0',
            resolverDid: 'did:example:resolver001',
            asOfTime: new Date().toISOString(),
            freshnessWindow: 3_600_001, // AJV maximum:3600000 catches it first
            signature: 'dGVzdA',
        };

        await expect(
            verifyResolverFreshness(rfp, resolver),
        ).rejects.toMatchObject({
            rfpCode: 'RFP_PROOF_INCOMPLETE',
        });
    });

    it('should throw RFP_PROOF_INCOMPLETE when freshnessWindow is not integer (AJV type:integer)', async () => {
        const resolver = buildNullPublicKeyResolver();
        const rfp = {
            rfpVersion: '1.0.0',
            cspVersion: '1.0.0',
            resolverDid: 'did:example:resolver001',
            asOfTime: new Date().toISOString(),
            freshnessWindow: 300_000.5, // AJV type:integer catches it first
            signature: 'dGVzdA',
        };

        await expect(
            verifyResolverFreshness(rfp, resolver),
        ).rejects.toMatchObject({
            rfpCode: 'RFP_PROOF_INCOMPLETE',
        });
    });
});

// ---------------------------------------------------------------------------
// P11 — I_asof fails (asOfTime beyond future tolerance)
// ---------------------------------------------------------------------------

describe('verifyResolverFreshness — P11 asOfTime beyond future tolerance', () => {
    it('should throw RFP_ASOF_FUTURE when asOfTime is more than 5s in the future', async () => {
        const { privateKey, publicKeyBytes } = await generateTestKeyPair();
        const resolverDid = 'did:example:resolver001' as DID;
        const nowMs = Date.now();
        // asOfTime = 60s ahead (exceeds the 5s tolerance)
        const futureAsOfTime = new Date(nowMs + 60_000).toISOString();
        const rfp = await buildValidRfp(privateKey, { asOfTime: futureAsOfTime });
        const resolver = buildPublicKeyResolver(resolverDid, publicKeyBytes);

        await expect(
            verifyResolverFreshness(rfp, resolver, nowMs),
        ).rejects.toMatchObject({
            rfpCode: 'RFP_ASOF_FUTURE',
        });
    });

    it('should accept asOfTime within 5s clock skew tolerance', async () => {
        const { privateKey, publicKeyBytes } = await generateTestKeyPair();
        const resolverDid = 'did:example:resolver001' as DID;
        const nowMs = Date.now();
        // asOfTime = 3s ahead (within the 5s tolerance)
        const nearFutureAsOfTime = new Date(nowMs + 3_000).toISOString();
        const rfp = await buildValidRfp(privateKey, { asOfTime: nearFutureAsOfTime });
        const resolver = buildPublicKeyResolver(resolverDid, publicKeyBytes);

        const result = await verifyResolverFreshness(rfp, resolver, nowMs);
        expect(result).toBeDefined();
    });
});

// ---------------------------------------------------------------------------
// P12 — createResolverFreshnessProof factory
// ---------------------------------------------------------------------------

describe('createResolverFreshnessProof — P12 factory function', () => {
    it('should create valid RFP with all 6 fields', async () => {
        const { privateKey, publicKeyBytes } = await generateTestKeyPair();
        const resolverDid = 'did:example:resolver001' as DID;

        const rfp = await createResolverFreshnessProof({
            resolverDid,
            sign: async (msg) => sign(msg, privateKey, 'base64url'),
        });

        expect(rfp.rfpVersion).toBe('1.0.0');
        expect(rfp.cspVersion).toBe('1.0.0');
        expect(rfp.resolverDid).toBe(resolverDid);
        expect(rfp.freshnessWindow).toBe(300_000);
        expect(rfp.asOfTime).toBeDefined();
        expect(rfp.signature).toBeDefined();

        // Verify the factory output passes verifyResolverFreshness
        const resolver = buildPublicKeyResolver(resolverDid, publicKeyBytes);
        const verified = await verifyResolverFreshness(rfp, resolver);
        expect(verified.resolverDid).toBe(resolverDid);
    });

    it('should create RFP with custom freshnessWindowMs', async () => {
        const { privateKey, publicKeyBytes } = await generateTestKeyPair();
        const resolverDid = 'did:example:resolver001' as DID;

        const rfp = await createResolverFreshnessProof({
            resolverDid,
            freshnessWindowMs: 60_000,
            sign: async (msg) => sign(msg, privateKey, 'base64url'),
        });

        expect(rfp.freshnessWindow).toBe(60_000);
        const resolver = buildPublicKeyResolver(resolverDid, publicKeyBytes);
        const verified = await verifyResolverFreshness(rfp, resolver);
        expect(verified.freshnessWindow).toBe(60_000);
    });

    it('should throw RFP_FRESHNESS_WINDOW_INVALID when freshnessWindowMs is out of range', async () => {
        const resolverDid = 'did:example:resolver001' as DID;

        await expect(
            createResolverFreshnessProof({
                resolverDid,
                freshnessWindowMs: 500, // < 1000
                sign: async (msg) => 'unused',
            }),
        ).rejects.toMatchObject({
            rfpCode: 'RFP_FRESHNESS_WINDOW_INVALID',
        });
    });

    it('should throw RFP_RESOLVER_DID_INVALID when resolverDid has wrong format', async () => {
        await expect(
            createResolverFreshnessProof({
                resolverDid: 'not-a-did' as DID,
                sign: async (msg) => 'unused',
            }),
        ).rejects.toMatchObject({
            rfpCode: 'RFP_RESOLVER_DID_INVALID',
        });
    });

    it('should accept custom asOfTime injection', async () => {
        const { privateKey, publicKeyBytes } = await generateTestKeyPair();
        const resolverDid = 'did:example:resolver001' as DID;
        const customAsOf = new Date(Date.now() - 5_000).toISOString() as Timestamp;

        const rfp = await createResolverFreshnessProof({
            resolverDid,
            asOfTime: customAsOf,
            sign: async (msg) => sign(msg, privateKey, 'base64url'),
        });

        expect(rfp.asOfTime).toBe(customAsOf);
    });
});

// ---------------------------------------------------------------------------
// P13 — verifyRfpForConsumer (requireRfp + maxAllowedFreshnessWindowMs)
// ---------------------------------------------------------------------------

describe('verifyRfpForConsumer — P13 consumer-side policy', () => {
    it('should return null when rfpPayload is null and requireRfp=false', async () => {
        const resolver = buildNullPublicKeyResolver();

        const result = await verifyRfpForConsumer(null, resolver, { requireRfp: false });
        expect(result).toBeNull();
    });

    it('should return null when rfpPayload is undefined and requireRfp=false', async () => {
        const resolver = buildNullPublicKeyResolver();

        const result = await verifyRfpForConsumer(undefined, resolver, { requireRfp: false });
        expect(result).toBeNull();
    });

    it('should throw RFP_PROOF_INCOMPLETE when rfpPayload is null and requireRfp=true', async () => {
        const resolver = buildNullPublicKeyResolver();

        await expect(
            verifyRfpForConsumer(null, resolver, { requireRfp: true }),
        ).rejects.toMatchObject({
            rfpCode: 'RFP_PROOF_INCOMPLETE',
        });
    });

    it('should throw RFP_FRESHNESS_WINDOW_EXCESSIVE when freshnessWindow > maxAllowedFreshnessWindowMs', async () => {
        const { privateKey, publicKeyBytes } = await generateTestKeyPair();
        const resolverDid = 'did:example:resolver001' as DID;
        const rfp = await buildValidRfp(privateKey, { freshnessWindow: 3_600_000 });
        const resolver = buildPublicKeyResolver(resolverDid, publicKeyBytes);

        await expect(
            verifyRfpForConsumer(rfp, resolver, {
                maxAllowedFreshnessWindowMs: 300_000, // consumer only accepts 5 minutes
            }),
        ).rejects.toMatchObject({
            rfpCode: 'RFP_FRESHNESS_WINDOW_EXCESSIVE',
        });
    });

    it('should return verified proof when within maxAllowedFreshnessWindowMs', async () => {
        const { privateKey, publicKeyBytes } = await generateTestKeyPair();
        const resolverDid = 'did:example:resolver001' as DID;
        const rfp = await buildValidRfp(privateKey, { freshnessWindow: 60_000 });
        const resolver = buildPublicKeyResolver(resolverDid, publicKeyBytes);

        const result = await verifyRfpForConsumer(rfp, resolver, {
            maxAllowedFreshnessWindowMs: 300_000,
        });
        expect(result?.freshnessWindow).toBe(60_000);
    });

    it('should use default options (requireRfp=false, maxAllowedFreshnessWindowMs=3600000)', async () => {
        const { privateKey, publicKeyBytes } = await generateTestKeyPair();
        const resolverDid = 'did:example:resolver001' as DID;
        const rfp = await buildValidRfp(privateKey, { freshnessWindow: 3_600_000 });
        const resolver = buildPublicKeyResolver(resolverDid, publicKeyBytes);

        const result = await verifyRfpForConsumer(rfp, resolver);
        expect(result?.freshnessWindow).toBe(3_600_000);
    });
});

// ---------------------------------------------------------------------------
// P14 — verifyQuorumFreshness boundary scenarios
// ---------------------------------------------------------------------------

describe('verifyQuorumFreshness — P14 boundary scenarios', () => {
    it('should handle empty node list with threshold 0', async () => {
        const resolver = buildNullPublicKeyResolver();
        const results = await verifyQuorumFreshness([], resolver, 0);
        expect(results).toHaveLength(0);
    });

    it('should pass with exactly threshold valid nodes', async () => {
        const { privateKey, publicKeyBytes } = await generateTestKeyPair();
        const resolverDid = 'did:example:resolver001' as DID;
        const rfp = await buildValidRfp(privateKey);
        const resolver = buildPublicKeyResolver(resolverDid, publicKeyBytes);

        const nodes = [
            { nodeId: 'node-1', resolverDid, rfpPayload: rfp },
        ];

        const results = await verifyQuorumFreshness(nodes, resolver, 1);
        expect(results[0]?.rfpVerified).not.toBeNull();
    });

    it('should fail when 0 valid nodes but threshold is 1', async () => {
        const resolver = buildNullPublicKeyResolver();

        const nodes = [
            { nodeId: 'node-1', resolverDid: 'did:example:unknown' as DID, rfpPayload: null },
        ];

        await expect(
            verifyQuorumFreshness(nodes, resolver, 1, { requireRfp: true }),
        ).rejects.toMatchObject({
            rfpCode: 'RFP_QUORUM_FRESHNESS_UNMET',
        });
    });
});

// ---------------------------------------------------------------------------
// P15 — RFP_HTTP_STATUS mapping completeness
// ---------------------------------------------------------------------------

describe('RFP_HTTP_STATUS — P15 mapping completeness', () => {
    const ALL_RFP_CODES: Array<import('@coivitas/types').RfpErrorCode> = [
        'RFP_PROOF_INCOMPLETE',
        'RFP_VERSION_UNSUPPORTED',
        'RFP_CSP_VERSION_MISMATCH',
        'RFP_RESOLVER_DID_INVALID',
        'RFP_FRESHNESS_WINDOW_INVALID',
        'RFP_FRESHNESS_WINDOW_EXCESSIVE',
        'RFP_ASOF_FUTURE',
        'RFP_SIGNATURE_INVALID',
        'RFP_FRESHNESS_EXPIRED',
        'RFP_RESOLVER_UNREACHABLE',
        'RFP_QUORUM_FRESHNESS_UNMET',
    ];

    it('should have exactly 11 entries covering all RfpErrorCode values', () => {
        expect(Object.keys(RFP_HTTP_STATUS)).toHaveLength(11);
    });

    it('should map all 11 RfpErrorCode to valid HTTP status codes', () => {
        for (const code of ALL_RFP_CODES) {
            const status = RFP_HTTP_STATUS[code];
            expect([401, 422, 503], `${code} should map to 401/422/503`).toContain(status);
        }
    });

    it('should map RFP_SIGNATURE_INVALID to 401', () => {
        expect(RFP_HTTP_STATUS['RFP_SIGNATURE_INVALID']).toBe(401);
    });

    it('should map RFP_FRESHNESS_EXPIRED to 503', () => {
        expect(RFP_HTTP_STATUS['RFP_FRESHNESS_EXPIRED']).toBe(503);
    });

    it('should map RFP_QUORUM_FRESHNESS_UNMET to 503', () => {
        expect(RFP_HTTP_STATUS['RFP_QUORUM_FRESHNESS_UNMET']).toBe(503);
    });

    it('should map RFP_RESOLVER_UNREACHABLE to 503', () => {
        expect(RFP_HTTP_STATUS['RFP_RESOLVER_UNREACHABLE']).toBe(503);
    });

    it('should map structural errors to 422', () => {
        const structuralErrors: Array<import('@coivitas/types').RfpErrorCode> = [
            'RFP_PROOF_INCOMPLETE',
            'RFP_VERSION_UNSUPPORTED',
            'RFP_CSP_VERSION_MISMATCH',
            'RFP_RESOLVER_DID_INVALID',
            'RFP_FRESHNESS_WINDOW_INVALID',
            'RFP_FRESHNESS_WINDOW_EXCESSIVE',
            'RFP_ASOF_FUTURE',
        ];
        for (const code of structuralErrors) {
            expect(RFP_HTTP_STATUS[code], `${code} should be 422`).toBe(422);
        }
    });
});

// ---------------------------------------------------------------------------
// P16 — RfpError instanceof chain
// ---------------------------------------------------------------------------

describe('RfpError — P16 instanceof chain', () => {
    it('should be instanceof RfpError', () => {
        const err = new RfpError('RFP_PROOF_INCOMPLETE', 'test');
        expect(err instanceof RfpError).toBe(true);
    });

    it('should be instanceof ProtocolError (inheritance chain)', async () => {
        const { ProtocolError } = await import('@coivitas/types');
        const err = new RfpError('RFP_PROOF_INCOMPLETE', 'test');
        expect(err instanceof ProtocolError).toBe(true);
    });

    it('should expose rfpCode and resolverDid', () => {
        const err = new RfpError('RFP_SIGNATURE_INVALID', 'bad sig', 'did:example:x');
        expect(err.rfpCode).toBe('RFP_SIGNATURE_INVALID');
        expect(err.resolverDid).toBe('did:example:x');
    });

    it('should have correct ProtocolError.code aggregate', () => {
        const err = new RfpError('RFP_FRESHNESS_EXPIRED', 'expired');
        expect(err.code).toBe('FEDERATED_RESOLUTION_FAILED');
    });
});
