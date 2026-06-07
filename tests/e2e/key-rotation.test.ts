/**
 * Key rotation E2E (real Registry DB + triple signature + Grace Period in effect)
 *
 * This case covers the full lifecycle from v1 registration -> initiate(ROTATING) -> the old-key token
 * still verifies within the Grace Period -> the new key issues a token -> complete(ACTIVE) -> the old-key
 * token becomes invalid -> the new-key token remains valid -> getDocumentHistory returns [v2, v1].
 *
 * Key constraints (aligned with the implementation, not free-form):
 *
 *   1. Registry authoritative state machine:
 *      - Step 4 "initiate rotation" = the application layer's initiateKeyRotation() generates the v2 intermediate document,
 *        then calls registry.update(v2Doc, 1) to persist; on the SQL side this sets rotation_state
 *        to 'ROTATING' and writes rotation_started_at=NOW() (registry.ts:146-155).
 *      - Step 8 "complete rotation" = the application layer's completeKeyRotation() strips the _rotatingState marker
 *        to obtain a clean AgentIdentityDocument. But the Registry currently does not expose the ROTATING->ACTIVE
 *        state-machine transition; here the E2E simulates that transition with a direct SQL write, explicitly labeled
 *        "drives state transition via SQL"; this should later be replaced with a formal API.
 *
 *   2. Grace Period verification goes through the verifyCapabilityToken(resolvedKeys) dual-key path:
 *      token-verifier.ts:144-183. T1's issuerDid is didKey(oldPub); to hit the
 *      resolvedKeys fallback branch, resolvedKeys must be passed in explicitly, otherwise it goes through the did:key single-key
 *      path and directly verifies successfully with oldPub, making the Grace Period semantics unobservable.
 *
 *   3. previousValidBefore must be explicitly set in resolvedKeys:
 *      resolvePublicKeys only inserts it in the ROTATING branch; the resolvedKeys at Step 9 (already ACTIVE)
 *      does not contain this field -> fail-closed rejection of the old key, consistent with the security constraint.
 *
 *   4. `describeIfDatabase`: only runs when DATABASE_URL is present (aligned with authorization-chain/
 *      key-rotation.integration); skips when CI has no DB, so it does not pollute the unit suite.
 *
 * Note: the Token itself is issued in did:key form (issuerDid = didKey(publicKey)), which is the
 *     public-key resolution path; during ROTATING we inject the dual key via resolvedKeys, while token.issuerDid itself
 *     is not re-anchored to did:agent (that belongs to the future L5 scope of Agents issuing tokens).
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
    canonicalize,
    generateKeyPair,
    sign,
} from '../../packages/crypto/src/index.js';
import {
    completeKeyRotation,
    createAgentIdentity,
    didKeyFromPublicKey,
    IdentityRegistry,
    initiateKeyRotation,
    issueCapabilityToken,
    verifyCapabilityToken,
} from '../../packages/identity/src/index.js';
import { createTestDatabase } from '../../packages/shared/src/index.js';
import type {
    AgentIdentityDocument,
    DID,
    ResolvedPublicKeys,
    Signature,
    Timestamp,
} from '../../packages/types/src/index.js';

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

/**
 * Construct the principal-signature part of the triple signature (principalApproval).
 * The principal private key does not enter the Agent Runtime; the caller completes pre-signing externally.
 * The payload field order must match key-rotation.ts:buildSignedPayloadBytes (agentDid,
 * newPublicKey, oldPublicKey, rotatedAt), with canonicalize guaranteeing lexicographic order.
 */
function signRotationPayload(
    payload: {
        agentDid: DID;
        newPublicKey: string;
        oldPublicKey: string;
        rotatedAt: Timestamp;
    },
    privateKey: string,
): Signature {
    const bytes = new TextEncoder().encode(
        canonicalize({
            agentDid: payload.agentDid,
            newPublicKey: payload.newPublicKey,
            oldPublicKey: payload.oldPublicKey,
            rotatedAt: payload.rotatedAt,
        }),
    );
    return sign(bytes, privateKey) as Signature;
}

describeIfDatabase('key rotation e2e', () => {
    let cleanup: (() => Promise<void>) | undefined;
    let pool: Awaited<ReturnType<typeof createTestDatabase>>['pool'];
    let registry: IdentityRegistry;

    beforeAll(async () => {
        const database = await createTestDatabase();
        cleanup = database.cleanup;
        pool = database.pool;
        registry = new IdentityRegistry(pool);
    });

    afterAll(async () => {
        await cleanup?.();
    });

    it('covers the full rotation lifecycle with Grace Period enforcement and version history', async () => {
        // ─────────────────────────────────────────────────────────────────────
        // Step 1: create Agent A's identity (version=1, ACTIVE)
        // ─────────────────────────────────────────────────────────────────────
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const agent = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
            capabilities: ['INQUIRY'],
        });
        const v1Doc: AgentIdentityDocument = agent.document;
        const key1Private = agent.privateKey;
        const key1Public = v1Doc.publicKey;

        await registry.register(v1Doc);

        // Sanity: initial state version=1, rotation_state='ACTIVE' (SQL DEFAULT)
        {
            const row = await pool.query<{
                version: number;
                rotation_state: 'ACTIVE' | 'ROTATING';
            }>(
                `SELECT version, rotation_state FROM identity.agents WHERE did = $1`,
                [v1Doc.id],
            );
            expect(row.rows[0]?.version).toBe(1);
            expect(row.rows[0]?.rotation_state).toBe('ACTIVE');
        }

        // ─────────────────────────────────────────────────────────────────────
        // Step 2: Agent A issues Token T1 with key1
        // issuerDid = didKey(key1Public): under the public-key resolution path the issuer is the did:key form of key1;
        // after rotation the same DID still points to the old key1, with no need to re-derive.
        // ─────────────────────────────────────────────────────────────────────
        const issuerDidKey1 = didKeyFromPublicKey(
            Buffer.from(key1Public, 'hex'),
        );
        const issuedAtT1 = '2026-04-23T08:00:00.000Z' as Timestamp;
        const T1 = issueCapabilityToken({
            issuerDid: issuerDidKey1,
            issuedTo: v1Doc.id,
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'recipient',
                        values: ['supplier-a'],
                    },
                },
            ],
            expiresAt: '2099-12-31T23:59:59.000Z' as Timestamp,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuerPrivateKey: key1Private,
            issuedAt: issuedAtT1,
        });

        // ─────────────────────────────────────────────────────────────────────
        // Step 3: verify T1 is valid (during ACTIVE it goes through the single-key did:key path)
        // ─────────────────────────────────────────────────────────────────────
        expect(verifyCapabilityToken(T1, issuedAtT1)).toEqual({ valid: true });

        // ─────────────────────────────────────────────────────────────────────
        // Step 4: initiate key rotation (initiateKeyRotation -> v2 intermediate document + registry.update
        // sets rotation_state to 'ROTATING', rotation_started_at=NOW()).
        // rotatedAt is generated uniformly by the caller, so the principal pre-signature and the internal signature use the same payload.
        // ─────────────────────────────────────────────────────────────────────
        const key2 = generateKeyPair();
        const rotatedAt = new Date().toISOString() as Timestamp;
        const principalApproval = signRotationPayload(
            {
                agentDid: v1Doc.id,
                newPublicKey: key2.publicKey,
                oldPublicKey: key1Public,
                rotatedAt,
            },
            principal.privateKey,
        );
        const rotatingDoc = initiateKeyRotation({
            currentDoc: v1Doc,
            currentPrivateKey: key1Private,
            newKeyPair: key2,
            principalApproval,
            rotatedAt,
        });

        // completeKeyRotation can be called at this stage (it only does format conversion + triple-signature re-verification);
        // only the resulting v2Doc can be accepted by registry.update (registry.update does not recognize the _rotatingState
        // runtime marker). The application-layer semantic "state machine: ROTATING" is reflected on the DB row.
        const v2Doc: AgentIdentityDocument = completeKeyRotation(rotatingDoc);
        expect(v2Doc.version).toBe(2);
        expect(v2Doc.publicKey).toBe(key2.publicKey);
        expect(v2Doc.previousPublicKey).toBe(key1Public);

        await registry.update(v2Doc, 1);

        // assert the DB: version=2 and in ROTATING (registry.ts:146-155 handles this transition)
        const rotatingRow = await pool.query<{
            version: number;
            rotation_state: 'ACTIVE' | 'ROTATING';
            rotation_started_at: string | null;
        }>(
            `SELECT version, rotation_state, rotation_started_at FROM identity.agents WHERE did = $1`,
            [v1Doc.id],
        );
        expect(rotatingRow.rows[0]?.version).toBe(2);
        expect(rotatingRow.rows[0]?.rotation_state).toBe('ROTATING');
        expect(rotatingRow.rows[0]?.rotation_started_at).not.toBeNull();
        const rotationStartedAtDb = new Date(
            rotatingRow.rows[0]!.rotation_started_at!,
        ).toISOString() as Timestamp;

        // ─────────────────────────────────────────────────────────────────────
        // Step 5: T1 is still valid within the Grace Period (the key1 signature falls back via resolvedKeys.previous)
        // resolvedKeys must be passed explicitly, otherwise the verifier goes through the did:key single-key path
        // (still verifying successfully with key1 directly) — that would make the Grace Period semantics unobservable, a false-positive green.
        // ─────────────────────────────────────────────────────────────────────
        const resolvedKeysRotating: ResolvedPublicKeys = {
            current: key2.publicKey,
            previous: key1Public,
            previousValidBefore: rotationStartedAtDb,
            rotationState: 'ROTATING',
            // ResolvedPublicKeys removed the `version` field in v0.3.0 (retained as an
            // AgentRegistryRecord / AgentIdentityDocument field; not part of the verifier-layer
            // contract); the old `version: 2` literal has been deleted to align with
            // the v0.3.0 contract of packages/types/src/identity.ts.
        };

        // issuedAtT1 = 2026-04-23T08:00:00Z, far earlier than rotationStartedAtDb (now),
        // satisfying token-verifier.ts:162's issuedAt <= previousValidBefore condition.
        expect(
            verifyCapabilityToken(T1, issuedAtT1, resolvedKeysRotating),
        ).toEqual({ valid: true });

        // ─────────────────────────────────────────────────────────────────────
        // Step 6: Agent A issues Token T2 with key2
        // issuerDid = didKey(key2.publicKey): the did:key corresponding to the new key.
        // ─────────────────────────────────────────────────────────────────────
        const issuerDidKey2 = didKeyFromPublicKey(
            Buffer.from(key2.publicKey, 'hex'),
        );
        const issuedAtT2 = new Date().toISOString() as Timestamp;
        const T2 = issueCapabilityToken({
            issuerDid: issuerDidKey2,
            issuedTo: v1Doc.id,
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'recipient',
                        values: ['supplier-a'],
                    },
                },
            ],
            expiresAt: '2099-12-31T23:59:59.000Z' as Timestamp,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuerPrivateKey: key2.privateKey,
            issuedAt: issuedAtT2,
        });

        // ─────────────────────────────────────────────────────────────────────
        // Step 7: verify T2 is valid (during ROTATING it verifies directly with current=key2)
        // ─────────────────────────────────────────────────────────────────────
        expect(
            verifyCapabilityToken(T2, issuedAtT2, resolvedKeysRotating),
        ).toEqual({ valid: true });

        // ─────────────────────────────────────────────────────────────────────
        // Step 8: complete rotation (rotation_state -> 'ACTIVE')

        // Note: the Registry does not yet expose a ROTATING->ACTIVE state-machine transition API,
        // so here we simulate that transition with a controlled SQL write. At the document level v2Doc is already
        // in clean form (completeKeyRotation has stripped _rotatingState); the SQL only updates the state column, not the document.
        // ─────────────────────────────────────────────────────────────────────
        await pool.query(
            `
            UPDATE identity.agents
            SET rotation_state = 'ACTIVE',
                rotation_started_at = NULL,
                updated_at = NOW()
            WHERE did = $1
            `,
            [v1Doc.id],
        );

        const activeRow = await pool.query<{
            version: number;
            rotation_state: 'ACTIVE' | 'ROTATING';
            rotation_started_at: string | null;
        }>(
            `SELECT version, rotation_state, rotation_started_at FROM identity.agents WHERE did = $1`,
            [v1Doc.id],
        );
        expect(activeRow.rows[0]?.version).toBe(2);
        expect(activeRow.rows[0]?.rotation_state).toBe('ACTIVE');
        expect(activeRow.rows[0]?.rotation_started_at).toBeNull();

        // ─────────────────────────────────────────────────────────────────────
        // Step 9: after rotation completes, the old-key T1 should become invalid
        // resolvedKeys no longer contains previous / previousValidBefore -> token-verifier.ts:154's
        // ROTATING+previous fallback branch is not entered at all, and the T1 signature (key1) does not match
        // current (key2) -> SIGNATURE_INVALID.
        // ─────────────────────────────────────────────────────────────────────
        const resolvedKeysActive: ResolvedPublicKeys = {
            current: key2.publicKey,
            // ResolvedKeyRotationState is a three-state enum
            // 'STABLE' | 'ROTATING' | 'FROZEN' (packages/types/src/identity.ts);
            // the old 'ACTIVE' is the DB-layer KeyRotationState (deprecated in v0.3.0).
            // Rotation completion (rotation_state='ACTIVE' in DB) maps to the verifier layer = 'STABLE'
            // (no previous + no previousValidBefore + only current valid).
            rotationState: 'STABLE',
        };
        const verifyT1AfterComplete = verifyCapabilityToken(
            T1,
            issuedAtT1,
            resolvedKeysActive,
        );
        expect(verifyT1AfterComplete.valid).toBe(false);
        expect(verifyT1AfterComplete.code).toBe('SIGNATURE_INVALID');

        // ─────────────────────────────────────────────────────────────────────
        // Step 10: the new-key T2 is still valid (verifies with current=key2)
        // ─────────────────────────────────────────────────────────────────────
        expect(
            verifyCapabilityToken(T2, issuedAtT2, resolvedKeysActive),
        ).toEqual({ valid: true });

        // ─────────────────────────────────────────────────────────────────────
        // Step 11: query version history -> [v2, v1] (descending by version)
        // registry.ts:207-239's getDocumentHistory assembles from the document/previous_document
        // columns; the current schema only retains the two most recent versions.
        // ─────────────────────────────────────────────────────────────────────
        const history = await registry.getDocumentHistory(v1Doc.id);
        expect(history).toHaveLength(2);
        expect(history[0]!.version).toBe(2);
        expect(history[0]!.publicKey).toBe(key2.publicKey);
        expect(history[1]!.version).toBe(1);
        expect(history[1]!.publicKey).toBe(key1Public);
    });
});
