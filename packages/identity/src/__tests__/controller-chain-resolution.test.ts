/**
 * ControllerChainResolution (CCR) v0.1 — L2 implementation tests
 *
 * Test coverage paths (>=95% target; 12 main paths + auxiliary paths):
 *   P1 — normal 3-node chain passes fully -> returns ControllerChainResolution
 *   P2 — A->B->A cycle (step 3 main defense line) -> throws CCR_CHAIN_CYCLE
 *   P3 — node 2 revoked (step 6 early position) -> throws CCR_CONTROLLER_REVOKED
 *   P4 — 6-node chain exceeds MAX_CHAIN_DEPTH=5 -> throws CCR_CHAIN_DEPTH_EXCEEDED
 *   P5 — node 2 freshnessProof expired -> throws CCR_FRESHNESS_INVALID
 *   P6 — root DID unreachable -> throws CCR_RESOLVER_UNAVAILABLE
 *   P7 — chain node DID document signature invalid -> throws CCR_CHAIN_SIGNATURE_INVALID
 *   P8 — verificationMethod.controller mismatch (step 9 constraint 2) -> throws CCR_CHAIN_BINDING_INVALID
 *   P9 — root DID document missing controller field -> throws CCR_CHAIN_BROKEN
 *   P10 — verifyChainIntegrityProof cspVersion wrong -> throws CCR_VERSION_UNSUPPORTED
 *   P11 — verifyChainIntegrityProof challenge mismatch -> throws CCR_CHALLENGE_EXPIRED
 *   P12 — verifyChainIntegrityProof audience mismatch -> throws CCR_AUDIENCE_MISMATCH
 *   P9 (P9 alias: P13) — validateCcrRequest schema mismatch -> throws CCR_SCHEMA_INVALID
 *   P14 — verifyChainIntegrityProof notAfter expired -> throws CCR_FRESHNESS_INVALID
 *   P15 — verifyChainIntegrityProof signature invalid -> throws CCR_CHAIN_SIGNATURE_INVALID
 */

import { describe, it, expect } from 'vitest';
import { generateKeyPair, sign, fromHex } from '@coivitas/crypto';
import { CcrError, MAX_CHAIN_DEPTH } from '@coivitas/types';
import type { DID, Timestamp } from '@coivitas/types';
import type { ChainIntegrityProof } from '@coivitas/types';
import {
    resolveControllerChain,
    verifyChainIntegrityProof,
    validateCcrRequest,
} from '../controller-chain-resolution/controller-chain-resolution.js';
import type {
    DidDocumentResolver,
    RfpVerifierPort,
    ControllerRevocationChecker,
    CcrResolverOptions,
} from '../controller-chain-resolution/controller-chain-resolution.js';

// ---------------------------------------------------------------------------
// test helpers
// ---------------------------------------------------------------------------

const FRESHNESS_WINDOW_MS = 60_000; // 60 s

function makeDid(suffix: string): DID {
    return `did:example:${suffix}` as DID;
}

/**
 * Build a DID document.
 * controller field: when null, the document has no controller (leaf scenario).
 */
function makeDoc(
    did: string,
    controllerDid: string | null,
    verificationMethodController?: string,
): Record<string, unknown> {
    return {
        id: did,
        controller: controllerDid ?? undefined,
        versionId: '1',
        verificationMethod: [
            {
                id: `${did}#key-1`,
                type: 'Ed25519VerificationKey2020',
                controller: verificationMethodController ?? did,
                publicKeyMultibase:
                    'z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp',
            },
        ],
    };
}

/**
 * ControllerChainResolutionRequest fixture (3-node chain).
 *   targetDid -> controllerA -> controllerB -> (no further controller)
 */
interface Fixture {
    targetDid: DID;
    controllerADid: DID;
    controllerBDid: DID;
    request: {
        targetDid: DID;
        challenge: string;
        verifierDid: DID;
        maxFreshnessWindowMs?: number;
        maxChainDepth?: number;
    };
}

function makeFixture(): Fixture {
    const targetDid = makeDid('target');
    const controllerADid = makeDid('controller-a');
    const controllerBDid = makeDid('controller-b');
    return {
        targetDid,
        controllerADid,
        controllerBDid,
        request: {
            targetDid,
            challenge: 'challenge-abc123',
            verifierDid: makeDid('verifier'),
            maxFreshnessWindowMs: FRESHNESS_WINDOW_MS * 2,
        },
    };
}

/**
 * Default DID resolver: targetDid -> controllerA -> controllerB (no further controller).
 * All document signatures are treated as valid.
 */
function makeDefaultResolver(f: Fixture): DidDocumentResolver {
    // verificationMethod[0].controller = the document's own DID (the key belongs to the document's corresponding entity).
    // step 9 constraint 2: vm.controller === node.controllerDid, so the document's own DID must be used.
    const docs = new Map<string, Record<string, unknown>>([
        [f.targetDid, makeDoc(f.targetDid, f.controllerADid, f.targetDid)],
        [
            f.controllerADid,
            makeDoc(f.controllerADid, f.controllerBDid, f.controllerADid),
        ],
        [f.controllerBDid, makeDoc(f.controllerBDid, null, f.controllerBDid)],
    ]);
    return {
        resolve: (did: DID) => Promise.resolve(docs.get(did) ?? null),
        verifyDocumentSignature: (_doc: Record<string, unknown>) =>
            Promise.resolve(true),
    };
}

/**
 * Default RFP verifier: all nodes are fresh + within window.
 */
function makeDefaultRfpVerifier(): RfpVerifierPort {
    return {
        getResolverFreshnessProof: (_did: DID) =>
            Promise.resolve({
                freshnessWindowMs: FRESHNESS_WINDOW_MS,
                asOfTime: new Date().toISOString(),
                verified: true,
            }),
    };
}

/**
 * Default revocation checker: no node is revoked.
 */
function makeDefaultRevocationChecker(): ControllerRevocationChecker {
    return {
        isControllerRevoked: (_did: DID) => Promise.resolve(false),
    };
}

// ---------------------------------------------------------------------------
// P1 — normal 3-node chain passes fully
// ---------------------------------------------------------------------------

describe('resolveControllerChain — P1 normal 3-node chain', () => {
    it('should return ControllerChainResolution when 3-node chain is valid', async () => {
        const f = makeFixture();
        const resolver = makeDefaultResolver(f);
        const rfp = makeDefaultRfpVerifier();
        const revocation = makeDefaultRevocationChecker();

        // producer-side fail-closed crypto enforce:
        // dev/test explicitly opt in with allowPlaceholderSignature=true to take the placeholder path;
        // production must pass options.signFn + options.resolverDid (producer-side throw when omitted)
        const result = await resolveControllerChain(
            f.request,
            resolver,
            rfp,
            revocation,
            { allowPlaceholderSignature: true },
        );

        expect(result.ccrVersion).toBe('1.0.0');
        expect(result.chainDepth).toBe(2); // controllerA + controllerB
        expect(result.freshnessVerified).toBe(true);
        expect(result.cycleAbsent).toBe(true);
        expect(result.chainBinding.rootBindingValid).toBe(true);
        expect(result.chainBinding.verificationMethodBindingValid).toBe(true);
        expect(result.chainBinding.leafBindingValid).toBe(true);
        expect(result.chain).toHaveLength(2);
        expect(result.chain[0]!.isRoot).toBe(true);
        expect(result.chain[0]!.parentControllerDid).toBeNull();
        expect(result.integrityProof.cspVersion).toBe('1.0.0');
        expect(result.integrityProof.challenge).toBe(f.request.challenge);
        expect(result.integrityProof.audience).toBe(f.request.verifierDid);
    });
});

// ---------------------------------------------------------------------------
// P2 — A->B->A cycle (step 3 main defense line)
// ---------------------------------------------------------------------------

describe('resolveControllerChain — P2 cycle detection step 3', () => {
    it('should throw CCR_CHAIN_CYCLE when A→B→A cycle detected', async () => {
        const f = makeFixture();

        // targetDid → A → B → A (cycle: B controller points back to A)
        const cyclicDocs = new Map<string, Record<string, unknown>>([
            [
                f.targetDid,
                makeDoc(f.targetDid, f.controllerADid, f.controllerADid),
            ],
            [
                f.controllerADid,
                makeDoc(f.controllerADid, f.controllerBDid, f.controllerBDid),
            ],
            [
                f.controllerBDid,
                makeDoc(f.controllerBDid, f.controllerADid, f.controllerADid),
            ], // cycle
        ]);

        const cyclicResolver: DidDocumentResolver = {
            resolve: (did: DID) => Promise.resolve(cyclicDocs.get(did) ?? null),
            verifyDocumentSignature: (_doc: Record<string, unknown>) =>
                Promise.resolve(true),
        };

        await expect(
            resolveControllerChain(
                f.request,
                cyclicResolver,
                makeDefaultRfpVerifier(),
                makeDefaultRevocationChecker(),
            ),
        ).rejects.toSatisfy((err: unknown) => {
            expect(err).toBeInstanceOf(CcrError);
            expect((err as CcrError).ccrCode).toBe('CCR_CHAIN_CYCLE');
            return true;
        });
    });
});

// ---------------------------------------------------------------------------
// P3 — node 2 revoked (step 6 early position)
// ---------------------------------------------------------------------------

describe('resolveControllerChain — P3 revocation step 6 early', () => {
    it('should throw CCR_CONTROLLER_REVOKED when node 2 is revoked', async () => {
        const f = makeFixture();
        const resolver = makeDefaultResolver(f);
        const rfp = makeDefaultRfpVerifier();

        // controllerA (node 0) not revoked; controllerB (node 1) revoked
        const revocation: ControllerRevocationChecker = {
            isControllerRevoked: (did: DID) =>
                Promise.resolve(did === f.controllerBDid),
        };

        await expect(
            resolveControllerChain(f.request, resolver, rfp, revocation),
        ).rejects.toSatisfy((err: unknown) => {
            expect(err).toBeInstanceOf(CcrError);
            expect((err as CcrError).ccrCode).toBe('CCR_CONTROLLER_REVOKED');
            return true;
        });
    });
});

// ---------------------------------------------------------------------------
// P4 — 6-node chain exceeds MAX_CHAIN_DEPTH=5
// ---------------------------------------------------------------------------

describe('resolveControllerChain — P4 chain depth exceeded', () => {
    it('should throw CCR_CHAIN_DEPTH_EXCEEDED when chain has 6 nodes', async () => {
        // build a depth-6 chain (target + c1 + c2 + c3 + c4 + c5 + c6, node count=6)
        const targetDid = makeDid('target');
        const controllers = Array.from({ length: 6 }, (_, i) =>
            makeDid(`ctrl-${i}`),
        );

        const lastController = controllers[controllers.length - 1];
        if (!lastController)
            throw new Error('Fixture setup error: no last controller');
        const docs = new Map<string, Record<string, unknown>>();
        docs.set(
            targetDid,
            makeDoc(targetDid, controllers[0] ?? '', controllers[0] ?? ''),
        );
        for (let i = 0; i < controllers.length - 1; i++) {
            const curr = controllers[i] ?? '';
            const next = controllers[i + 1] ?? '';
            docs.set(curr, makeDoc(curr, next, next));
        }
        // the last controller has no further controller
        docs.set(lastController, makeDoc(lastController, null, lastController));

        const deepResolver: DidDocumentResolver = {
            resolve: (did: DID) => Promise.resolve(docs.get(did) ?? null),
            verifyDocumentSignature: (_doc: Record<string, unknown>) =>
                Promise.resolve(true),
        };

        const request = {
            targetDid,
            challenge: 'ch-deep',
            verifierDid: makeDid('verifier'),
        };

        await expect(
            resolveControllerChain(
                request,
                deepResolver,
                makeDefaultRfpVerifier(),
                makeDefaultRevocationChecker(),
            ),
        ).rejects.toSatisfy((err: unknown) => {
            expect(err).toBeInstanceOf(CcrError);
            expect((err as CcrError).ccrCode).toBe('CCR_CHAIN_DEPTH_EXCEEDED');
            return true;
        });
    });
});

// ---------------------------------------------------------------------------
// P5 — node 2 freshnessProof expired
// ---------------------------------------------------------------------------

describe('resolveControllerChain — P5 freshness expired', () => {
    it('should throw CCR_FRESHNESS_INVALID when node 2 freshness window exceeded', async () => {
        const f = makeFixture();
        const resolver = makeDefaultResolver(f);
        const revocation = makeDefaultRevocationChecker();

        // controllerA fresh; controllerB freshnessWindow exceeds request.maxFreshnessWindowMs
        const rfp: RfpVerifierPort = {
            getResolverFreshnessProof: (did: DID) => {
                if (did === f.controllerBDid) {
                    return Promise.resolve({
                        // freshnessWindowMs far exceeds request.maxFreshnessWindowMs
                        freshnessWindowMs:
                            (f.request.maxFreshnessWindowMs ??
                                FRESHNESS_WINDOW_MS) * 10,
                        asOfTime: new Date().toISOString(),
                        verified: true,
                    });
                }
                return Promise.resolve({
                    freshnessWindowMs: FRESHNESS_WINDOW_MS,
                    asOfTime: new Date().toISOString(),
                    verified: true,
                });
            },
        };

        await expect(
            resolveControllerChain(f.request, resolver, rfp, revocation),
        ).rejects.toSatisfy((err: unknown) => {
            expect(err).toBeInstanceOf(CcrError);
            expect((err as CcrError).ccrCode).toBe('CCR_FRESHNESS_INVALID');
            return true;
        });
    });
});

// ---------------------------------------------------------------------------
// P6 — root DID unreachable
// ---------------------------------------------------------------------------

describe('resolveControllerChain — P6 root DID unavailable', () => {
    it('should throw CCR_RESOLVER_UNAVAILABLE when root DID returns null', async () => {
        const f = makeFixture();

        const brokenResolver: DidDocumentResolver = {
            resolve: (_did: DID) => Promise.resolve(null),
            verifyDocumentSignature: (_doc: Record<string, unknown>) =>
                Promise.resolve(true),
        };

        await expect(
            resolveControllerChain(
                f.request,
                brokenResolver,
                makeDefaultRfpVerifier(),
                makeDefaultRevocationChecker(),
            ),
        ).rejects.toSatisfy((err: unknown) => {
            expect(err).toBeInstanceOf(CcrError);
            expect((err as CcrError).ccrCode).toBe('CCR_RESOLVER_UNAVAILABLE');
            return true;
        });
    });
});

// ---------------------------------------------------------------------------
// P7 — chain node document signature invalid
// ---------------------------------------------------------------------------

describe('resolveControllerChain — P7 document signature invalid', () => {
    it('should throw CCR_CHAIN_SIGNATURE_INVALID when document signature fails', async () => {
        const f = makeFixture();

        // all documents resolve normally; but the controllerA document signature is invalid
        const sigFailResolver: DidDocumentResolver = {
            resolve: (did: DID) => makeDefaultResolver(f).resolve(did),
            verifyDocumentSignature: (doc: Record<string, unknown>) => {
                // controllerA document signature fails
                if ((doc['id'] as string) === f.controllerADid) {
                    return Promise.resolve(false);
                }
                return Promise.resolve(true);
            },
        };

        await expect(
            resolveControllerChain(
                f.request,
                sigFailResolver,
                makeDefaultRfpVerifier(),
                makeDefaultRevocationChecker(),
            ),
        ).rejects.toSatisfy((err: unknown) => {
            expect(err).toBeInstanceOf(CcrError);
            expect((err as CcrError).ccrCode).toBe(
                'CCR_CHAIN_SIGNATURE_INVALID',
            );
            return true;
        });
    });
});

// ---------------------------------------------------------------------------
// P8 — verificationMethod.controller mismatch -> CCR_CHAIN_BINDING_INVALID (step 9 constraint 2)
// ---------------------------------------------------------------------------

describe('resolveControllerChain — P8 verificationMethod binding mismatch', () => {
    it('should throw CCR_CHAIN_BINDING_INVALID when verificationMethod[0].controller does not match controllerDid', async () => {
        const f = makeFixture();
        const unrelatedDid = makeDid('unrelated');

        // controllerA's DID document verificationMethod.controller points to unrelated
        // (in the controllerA document, vm.controller does not match controllerA's own DID)
        // step 9 constraint 2 checks every node's vm[0].controller === node.controllerDid -> fails
        const vmMismatchResolver: DidDocumentResolver = {
            resolve: (did: DID) => {
                if (did === f.controllerADid) {
                    return Promise.resolve(
                        makeDoc(
                            f.controllerADid,
                            f.controllerBDid,
                            unrelatedDid,
                        ),
                    );
                }
                return makeDefaultResolver(f).resolve(did);
            },
            verifyDocumentSignature: (_doc: Record<string, unknown>) =>
                Promise.resolve(true),
        };

        await expect(
            resolveControllerChain(
                f.request,
                vmMismatchResolver,
                makeDefaultRfpVerifier(),
                makeDefaultRevocationChecker(),
            ),
        ).rejects.toSatisfy((err: unknown) => {
            expect(err).toBeInstanceOf(CcrError);
            expect((err as CcrError).ccrCode).toBe('CCR_CHAIN_BINDING_INVALID');
            return true;
        });
    });
});

// ---------------------------------------------------------------------------
// P8b — root DID document missing controller -> CCR_CHAIN_BROKEN
// ---------------------------------------------------------------------------

describe('resolveControllerChain — P8b missing root controller', () => {
    it('should throw CCR_CHAIN_BROKEN when root DID document has no controller field', async () => {
        const f = makeFixture();

        // root DID document has no controller field
        const noControllerResolver: DidDocumentResolver = {
            resolve: (did: DID) => {
                if (did === f.targetDid) {
                    return Promise.resolve({ id: f.targetDid, versionId: '1' }); // no controller
                }
                return makeDefaultResolver(f).resolve(did);
            },
            verifyDocumentSignature: (_doc: Record<string, unknown>) =>
                Promise.resolve(true),
        };

        await expect(
            resolveControllerChain(
                f.request,
                noControllerResolver,
                makeDefaultRfpVerifier(),
                makeDefaultRevocationChecker(),
            ),
        ).rejects.toSatisfy((err: unknown) => {
            expect(err).toBeInstanceOf(CcrError);
            expect((err as CcrError).ccrCode).toBe('CCR_CHAIN_BROKEN');
            return true;
        });
    });
});

// ---------------------------------------------------------------------------
// P9 — validateCcrRequest schema mismatch -> CCR_SCHEMA_INVALID
// ---------------------------------------------------------------------------

describe('validateCcrRequest — P9 schema invalid', () => {
    it('should throw CCR_SCHEMA_INVALID when data does not match schema', () => {
        const schema = {
            type: 'object',
            properties: {
                targetDid: { type: 'string' },
                challenge: { type: 'string' },
            },
            required: ['targetDid', 'challenge'],
            additionalProperties: false,
        };

        // missing required field challenge
        let thrown: unknown;
        try {
            validateCcrRequest({ targetDid: 'did:example:foo' }, schema);
        } catch (e) {
            thrown = e;
        }
        expect(thrown).toBeInstanceOf(CcrError);
        expect((thrown as CcrError).ccrCode).toBe('CCR_SCHEMA_INVALID');
    });

    it('should not throw when data matches schema', () => {
        const schema = {
            type: 'object',
            properties: {
                targetDid: { type: 'string' },
                challenge: { type: 'string' },
            },
            required: ['targetDid', 'challenge'],
            additionalProperties: false,
        };

        expect(() =>
            validateCcrRequest(
                { targetDid: 'did:example:foo', challenge: 'abc' },
                schema,
            ),
        ).not.toThrow();
    });
});

// ---------------------------------------------------------------------------
// — verifyChainIntegrityProof series
// ---------------------------------------------------------------------------

describe('verifyChainIntegrityProof — proof verification', () => {
    const VERIFIER_DID = makeDid('verifier');
    const CHALLENGE = 'test-challenge-xyz';
    const NOW_PROOF_MS = Date.now();

    function makeValidProof(
        overrides: Partial<ChainIntegrityProof> = {},
    ): ChainIntegrityProof {
        return {
            token: 'ccr:did:example:controller-a:depth=2',
            disclosedClaims: [
                '0:did:example:controller-a',
                '1:did:example:controller-b',
            ],
            challenge: CHALLENGE,
            audience: VERIFIER_DID,
            notAfter: new Date(
                NOW_PROOF_MS + 60_000,
            ).toISOString() as Timestamp,
            cspVersion:
                '1.0.0' as import('@coivitas/types').CspVersionString,
            chainSignature:
                'PLACEHOLDER_SIGNATURE_NO_SIGN_FN' as import('@coivitas/types').Signature,
            resolverDid: makeDid('resolver'),
            ...overrides,
        };
    }

    // P10 — cspVersion unsupported
    it('should throw CCR_VERSION_UNSUPPORTED when cspVersion is not 1.0.0', async () => {
        const proof = makeValidProof({
            cspVersion:
                '2.0.0' as import('@coivitas/types').CspVersionString,
        });
        const { publicKey: pkHex } = generateKeyPair();
        const publicKeyBytes = fromHex(pkHex);

        await expect(
            verifyChainIntegrityProof(
                proof,
                publicKeyBytes,
                CHALLENGE,
                VERIFIER_DID,
            ),
        ).rejects.toSatisfy((err: unknown) => {
            expect(err).toBeInstanceOf(CcrError);
            expect((err as CcrError).ccrCode).toBe('CCR_VERSION_UNSUPPORTED');
            return true;
        });
    });

    // P11 — challenge mismatch
    it('should throw CCR_CHALLENGE_EXPIRED when challenge does not match', async () => {
        const proof = makeValidProof();
        const { publicKey: pkHex } = generateKeyPair();
        const publicKeyBytes = fromHex(pkHex);

        await expect(
            verifyChainIntegrityProof(
                proof,
                publicKeyBytes,
                'wrong-challenge',
                VERIFIER_DID,
            ),
        ).rejects.toSatisfy((err: unknown) => {
            expect(err).toBeInstanceOf(CcrError);
            expect((err as CcrError).ccrCode).toBe('CCR_CHALLENGE_EXPIRED');
            return true;
        });
    });

    // P12 — audience mismatch
    it('should throw CCR_AUDIENCE_MISMATCH when audience does not match verifierDid', async () => {
        const proof = makeValidProof();
        const { publicKey: pkHex } = generateKeyPair();
        const publicKeyBytes = fromHex(pkHex);

        await expect(
            verifyChainIntegrityProof(
                proof,
                publicKeyBytes,
                CHALLENGE,
                makeDid('wrong-verifier'),
            ),
        ).rejects.toSatisfy((err: unknown) => {
            expect(err).toBeInstanceOf(CcrError);
            expect((err as CcrError).ccrCode).toBe('CCR_AUDIENCE_MISMATCH');
            return true;
        });
    });

    // P14 — notAfter expired
    it('should throw CCR_FRESHNESS_INVALID when proof is expired (notAfter in the past)', async () => {
        const expiredProof = makeValidProof({
            notAfter: new Date(NOW_PROOF_MS - 1_000).toISOString() as Timestamp,
        });
        const { publicKey: pkHex } = generateKeyPair();
        const publicKeyBytes = fromHex(pkHex);

        await expect(
            verifyChainIntegrityProof(
                expiredProof,
                publicKeyBytes,
                CHALLENGE,
                VERIFIER_DID,
            ),
        ).rejects.toSatisfy((err: unknown) => {
            expect(err).toBeInstanceOf(CcrError);
            expect((err as CcrError).ccrCode).toBe('CCR_FRESHNESS_INVALID');
            return true;
        });
    });

    // P15 — Ed25519 signature invalid (placeholder signature string + random keypair)
    it('should throw CCR_CHAIN_SIGNATURE_INVALID when Ed25519 signature is invalid', async () => {
        const proof = makeValidProof();
        // use the correct challenge + audience + verifierDid, but the signature is a placeholder string
        const { publicKey: pkHex } = generateKeyPair(); // a fresh random keypair; the signature is necessarily invalid
        const publicKeyBytes = fromHex(pkHex);

        // PLACEHOLDER_SIGNATURE_NO_SIGN_FN is not a valid Ed25519 signature, so verify necessarily returns false/throws
        await expect(
            verifyChainIntegrityProof(
                proof,
                publicKeyBytes,
                CHALLENGE,
                VERIFIER_DID,
            ),
        ).rejects.toSatisfy((err: unknown) => {
            expect(err).toBeInstanceOf(CcrError);
            expect((err as CcrError).ccrCode).toBe(
                'CCR_CHAIN_SIGNATURE_INVALID',
            );
            return true;
        });
    });

    // extra: valid proof with real Ed25519 signature should pass
    it('should not throw when proof signature is valid', async () => {
        const { privateKey, publicKey: pkHex } = generateKeyPair();
        const publicKeyBytes = fromHex(pkHex);

        // build signedPayload using the same field order as buildChainIntegrityProof
        const notAfter = new Date(
            Date.now() + 60_000,
        ).toISOString() as Timestamp;
        const token = 'ccr:did:example:controller-a:depth=2';
        const disclosedClaims = [
            '0:did:example:controller-a',
            '1:did:example:controller-b',
        ];

        const { canonicalize } = await import('@coivitas/crypto');
        const signedPayload = {
            audience: VERIFIER_DID,
            challenge: CHALLENGE,
            cspVersion: '1.0.0',
            disclosedClaims,
            notAfter,
            token,
        };
        const canonical = canonicalize(
            signedPayload as unknown as Record<string, unknown>,
        );
        const msgBytes = new TextEncoder().encode(canonical);
        // sign() returns a hex-encoded signature by default; verify() accepts hex
        const sigHex = sign(msgBytes, privateKey);

        const validProof = makeValidProof({
            token,
            disclosedClaims,
            notAfter,
            chainSignature:
                sigHex as unknown as import('@coivitas/types').Signature,
        });

        await expect(
            verifyChainIntegrityProof(
                validProof,
                publicKeyBytes,
                CHALLENGE,
                VERIFIER_DID,
            ),
        ).resolves.toBeUndefined();
    });
});

// ---------------------------------------------------------------------------
// P15b — producer-side fail-closed crypto enforcement
// ---------------------------------------------------------------------------

describe('resolveControllerChain — producer-side fail-closed when signFn missing', () => {
    it('should throw CCR_CHAIN_SIGNATURE_INVALID when signFn missing AND allowPlaceholderSignature default false', async () => {
        const f = makeFixture();
        const resolver = makeDefaultResolver(f);
        const rfp = makeDefaultRfpVerifier();
        const revocation = makeDefaultRevocationChecker();

        // default allowPlaceholderSignature=false -> producer-side throw when signFn is missing
        // producer-side fail-closed
        await expect(
            resolveControllerChain(f.request, resolver, rfp, revocation),
        ).rejects.toThrow(/CCR_CHAIN_SIGNATURE_INVALID/);
    });

    it('should throw CCR_CHAIN_SIGNATURE_INVALID when resolverDid missing AND allowPlaceholderSignature default false', async () => {
        const f = makeFixture();
        const resolver = makeDefaultResolver(f);
        const rfp = makeDefaultRfpVerifier();
        const revocation = makeDefaultRevocationChecker();

        const signFn = (_msg: Uint8Array): Promise<string> =>
            Promise.resolve('dGVzdA==');

        // signFn injected but resolverDid missing -> producer-side throw
        await expect(
            resolveControllerChain(f.request, resolver, rfp, revocation, {
                signFn,
            }),
        ).rejects.toThrow(/CCR_CHAIN_SIGNATURE_INVALID/);
    });

    it('should accept placeholder signature when allowPlaceholderSignature=true (dev/test opt-in)', async () => {
        const f = makeFixture();
        const resolver = makeDefaultResolver(f);
        const rfp = makeDefaultRfpVerifier();
        const revocation = makeDefaultRevocationChecker();

        const result = await resolveControllerChain(
            f.request,
            resolver,
            rfp,
            revocation,
            { allowPlaceholderSignature: true },
        );

        // dev/test opt-in takes the placeholder path (consumer-side verify still fail-closed)
        expect(result.integrityProof.chainSignature).toBe(
            'PLACEHOLDER_SIGNATURE_NO_SIGN_FN',
        );
    });
});

// ---------------------------------------------------------------------------
// P16 — options.signFn injection path (buildChainIntegrityProof signature injection)
// ---------------------------------------------------------------------------

describe('resolveControllerChain — P16 options.signFn injection', () => {
    it('should call signFn and use its result as chainSignature when options.signFn is provided', async () => {
        const f = makeFixture();
        const resolver = makeDefaultResolver(f);
        const rfp = makeDefaultRfpVerifier();
        const revocation = makeDefaultRevocationChecker();

        // signFn injection: returns a fixed base64 string (the production path uses a real Ed25519 signature; this tests the injection mechanism)
        const CUSTOM_SIGNATURE = 'dGVzdF9zaWduYXR1cmVfYmFzZTY0'; // base64
        const signFn = (_msg: Uint8Array): Promise<string> =>
            Promise.resolve(CUSTOM_SIGNATURE);

        const options: CcrResolverOptions = {
            signFn,
            resolverDid: makeDid('custom-resolver'),
        };

        const result = await resolveControllerChain(
            f.request,
            resolver,
            rfp,
            revocation,
            options,
        );

        // after signFn injection, chainSignature should be signFn's return value (not the placeholder string)
        expect(result.integrityProof.chainSignature).toBe(CUSTOM_SIGNATURE);
        // resolverDid should also use the value injected via options
        expect(result.integrityProof.resolverDid).toBe(
            makeDid('custom-resolver'),
        );
    });
});

// ---------------------------------------------------------------------------
// P17 — Resolver returns null for a mid-chain (non-root) node -> CCR_RESOLVER_UNAVAILABLE
// ---------------------------------------------------------------------------

describe('resolveControllerChain — P17 mid-chain resolver unavailable', () => {
    it('should throw CCR_RESOLVER_UNAVAILABLE when resolver returns null for mid-chain controller node', async () => {
        const f = makeFixture();

        // targetDid resolves normally; controllerADid (the first mid-chain node) resolves to null
        const partialResolver: DidDocumentResolver = {
            resolve: (did: DID) => {
                if (did === f.targetDid) {
                    return Promise.resolve(
                        makeDoc(f.targetDid, f.controllerADid, f.targetDid),
                    );
                }
                // controllerADid returns null — mid-chain node unavailable
                return Promise.resolve(null);
            },
            verifyDocumentSignature: (_doc: Record<string, unknown>) =>
                Promise.resolve(true),
        };

        await expect(
            resolveControllerChain(
                f.request,
                partialResolver,
                makeDefaultRfpVerifier(),
                makeDefaultRevocationChecker(),
            ),
        ).rejects.toSatisfy((err: unknown) => {
            expect(err).toBeInstanceOf(CcrError);
            expect((err as CcrError).ccrCode).toBe('CCR_RESOLVER_UNAVAILABLE');
            return true;
        });
    });
});

// ---------------------------------------------------------------------------
// P18 — RFP freshnessWindowMs exceeds maxFreshnessWindowMs -> CCR_FRESHNESS_INVALID
// ---------------------------------------------------------------------------

describe('resolveControllerChain — P18 RFP freshness window exceeded', () => {
    it('should throw CCR_FRESHNESS_INVALID when RFP freshnessWindowMs exceeds maxFreshnessWindowMs', async () => {
        const f = makeFixture();
        const resolver = makeDefaultResolver(f);
        const revocation = makeDefaultRevocationChecker();

        // returns freshnessWindowMs = 200_000, but request.maxFreshnessWindowMs = 60_000 * 2 = 120_000
        // 200_000 > 120_000 -> freshness_window_exceeded -> CCR_FRESHNESS_INVALID
        const tooWideRfpVerifier: RfpVerifierPort = {
            getResolverFreshnessProof: (_did: DID) =>
                Promise.resolve({
                    freshnessWindowMs: 200_000, // exceeds request.maxFreshnessWindowMs
                    asOfTime: new Date().toISOString(),
                    verified: true,
                }),
        };

        await expect(
            resolveControllerChain(
                f.request,
                resolver,
                tooWideRfpVerifier,
                revocation,
            ),
        ).rejects.toSatisfy((err: unknown) => {
            expect(err).toBeInstanceOf(CcrError);
            expect((err as CcrError).ccrCode).toBe('CCR_FRESHNESS_INVALID');
            return true;
        });
    });
});

// ---------------------------------------------------------------------------
// P19 — RFP asOfTime older than freshnessWindowMs (stale) -> CCR_FRESHNESS_INVALID
// ---------------------------------------------------------------------------

describe('resolveControllerChain — P19 stale RFP asOfTime', () => {
    it('should throw CCR_FRESHNESS_INVALID when RFP asOfTime is stale beyond freshnessWindowMs', async () => {
        const f = makeFixture();
        const resolver = makeDefaultResolver(f);
        const revocation = makeDefaultRevocationChecker();

        // asOfTime = 10 seconds ago; freshnessWindowMs = 1 second
        // nowMs - asOfMs = ~10_000 > 1_000 -> stale -> CCR_FRESHNESS_INVALID
        const staleRfpVerifier: RfpVerifierPort = {
            getResolverFreshnessProof: (_did: DID) =>
                Promise.resolve({
                    freshnessWindowMs: 1_000,
                    asOfTime: new Date(Date.now() - 10_000).toISOString(),
                    verified: true,
                }),
        };

        await expect(
            resolveControllerChain(
                f.request,
                resolver,
                staleRfpVerifier,
                revocation,
            ),
        ).rejects.toSatisfy((err: unknown) => {
            expect(err).toBeInstanceOf(CcrError);
            expect((err as CcrError).ccrCode).toBe('CCR_FRESHNESS_INVALID');
            return true;
        });
    });
});

// ---------------------------------------------------------------------------
// P20 — RFP verifier throws an exception -> reason: rfp_unavailable -> CCR_FRESHNESS_INVALID
// ---------------------------------------------------------------------------

describe('resolveControllerChain — P20 RFP verifier throws exception', () => {
    it('should throw CCR_FRESHNESS_INVALID when RFP verifier throws', async () => {
        const f = makeFixture();
        const resolver = makeDefaultResolver(f);
        const revocation = makeDefaultRevocationChecker();

        // getResolverFreshnessProof throws -> catch block -> reason: 'rfp_unavailable' -> CCR_FRESHNESS_INVALID
        const throwingRfpVerifier: RfpVerifierPort = {
            getResolverFreshnessProof: (_did: DID) =>
                Promise.reject(new Error('RFP service unavailable')),
        };

        await expect(
            resolveControllerChain(
                f.request,
                resolver,
                throwingRfpVerifier,
                revocation,
            ),
        ).rejects.toSatisfy((err: unknown) => {
            expect(err).toBeInstanceOf(CcrError);
            expect((err as CcrError).ccrCode).toBe('CCR_FRESHNESS_INVALID');
            return true;
        });
    });
});

// ---------------------------------------------------------------------------
// P21 — single-node chain (target points directly to the root controller, no further controller) passes normally
// ---------------------------------------------------------------------------

describe('resolveControllerChain — P21 single-node chain success', () => {
    it('should return ControllerChainResolution with chainDepth=1 for single-node chain', async () => {
        // targetDid's controller = controllerADid; controllerADid has no further controller
        const targetDid = makeDid('single-target');
        const controllerDid = makeDid('single-controller');
        const request = {
            targetDid,
            challenge: 'challenge-p21',
            verifierDid: makeDid('verifier-p21'),
        };

        const singleNodeResolver: DidDocumentResolver = {
            resolve: (did: DID) => {
                if (did === targetDid)
                    return Promise.resolve(
                        makeDoc(targetDid, controllerDid, targetDid),
                    );
                if (did === controllerDid)
                    return Promise.resolve(
                        makeDoc(controllerDid, null, controllerDid),
                    );
                return Promise.resolve(null);
            },
            verifyDocumentSignature: (_doc: Record<string, unknown>) =>
                Promise.resolve(true),
        };

        // producer-side fail-closed:
        const result = await resolveControllerChain(
            request,
            singleNodeResolver,
            makeDefaultRfpVerifier(),
            makeDefaultRevocationChecker(),
            { allowPlaceholderSignature: true },
        );

        expect(result.chainDepth).toBe(1);
        expect(result.chain).toHaveLength(1);
        expect(result.chain[0]!.isRoot).toBe(true);
        expect(result.chain[0]!.parentControllerDid).toBeNull();
        expect(result.freshnessVerified).toBe(true);
    });
});

// ---------------------------------------------------------------------------
// MAX_CHAIN_DEPTH constant verification
// ---------------------------------------------------------------------------

describe('MAX_CHAIN_DEPTH constant', () => {
    it('should equal 5', () => {
        expect(MAX_CHAIN_DEPTH).toBe(5);
    });
});
