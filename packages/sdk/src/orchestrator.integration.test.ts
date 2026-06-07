/**
 * Orchestrator integration test
 *
 * Goal: use a **real** PolicyEngine + RuntimeGuard + in-memory TokenStore to prove
 *   - a capability-bound envelope (carrying the sender's tokenRef) is authorized correctly on the recipient side;
 *   - the recipient's RuntimeGuard authorizes against **the recipient's own token pool**,
 *     and does not falsely reject because the sender's tokenId was incorrectly threaded through.
 *
 * Uses an in-memory TokenStore instead of Postgres to avoid depending on an external service.
 */
import { describe, expect, it } from 'vitest';

import { generateKeyPair } from '@coivitas/crypto';
import {
    didKeyFromPublicKey,
    issueCapabilityToken,
} from '@coivitas/identity';
import { PolicyEngine, RuntimeGuard } from '@coivitas/policy';
import type {
    ActionRecordInput,
    RecordWriteResult,
} from '@coivitas/policy';
import type {
    AgentIdentityDocument,
    CapabilityToken,
    DID,
    Timestamp,
} from '@coivitas/types';
import { SPEC_VERSION_0_2_0 } from '@coivitas/types';
import { buildEnvelope } from '@coivitas/communication';

import { Orchestrator } from './orchestrator.js';

/**
 * In-memory TokenStore — RuntimeGuard only needs getTokensForAgent.
 * The real TokenStore is indexed by agentDid, so here we also store by agentDid -> Token[].
 */
class InMemoryTokenStore {
    private readonly byAgent = new Map<string, CapabilityToken[]>();

    public put(agentDid: DID, token: CapabilityToken): void {
        const list = this.byAgent.get(agentDid) ?? [];
        list.push(token);
        this.byAgent.set(agentDid, list);
    }

    public getTokensForAgent(agentDid: DID): Promise<CapabilityToken[]> {
        return Promise.resolve(this.byAgent.get(agentDid) ?? []);
    }

    public getToken(tokenId: string): Promise<CapabilityToken | null> {
        for (const list of this.byAgent.values()) {
            const found = list.find((t) => t.id === tokenId);
            if (found) return Promise.resolve(found);
        }
        return Promise.resolve(null);
    }
}

describe('Orchestrator integration: capability-bound envelope with real PolicyEngine/RuntimeGuard', () => {
    it('should authorize capability-bound envelope against recipient local token pool (not sender pool)', async () => {
        // ── Sender (Alice's Agent A) ──
        const aliceKeyPair = generateKeyPair();
        const alicePrincipalDid = didKeyFromPublicKey(
            Buffer.from(aliceKeyPair.publicKey, 'hex'),
        );
        const agentAKeyPair = generateKeyPair();
        const agentADid =
            'did:agent:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' as DID;

        // Token-A that Alice signs for Agent A (lives on Alice's side / the sender side)
        const senderToken = issueCapabilityToken({
            issuerDid: alicePrincipalDid,
            issuedTo: agentADid,
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
            expiresAt: '2026-04-22T10:00:00.000Z' as Timestamp,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuerPrivateKey: aliceKeyPair.privateKey,
            issuedAt: '2026-04-21T10:00:00.000Z' as Timestamp,
        });

        // ── Recipient (Bob's Agent B) ──
        const bobKeyPair = generateKeyPair();
        const bobPrincipalDid = didKeyFromPublicKey(
            Buffer.from(bobKeyPair.publicKey, 'hex'),
        );
        const agentBKeyPair = generateKeyPair();
        const agentBDid =
            'did:agent:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' as DID;

        // Token-B that Bob signs for Agent B (lives on Bob's side / the recipient side; different from the sender Token)
        const recipientToken = issueCapabilityToken({
            issuerDid: bobPrincipalDid,
            issuedTo: agentBDid,
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
            expiresAt: '2026-04-22T10:00:00.000Z' as Timestamp,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuerPrivateKey: bobKeyPair.privateKey,
            issuedAt: '2026-04-21T10:00:00.000Z' as Timestamp,
        });

        // Recipient-side TokenStore: holds only the Token Bob signed (key point)
        const recipientStore = new InMemoryTokenStore();
        recipientStore.put(agentBDid, recipientToken);

        // Sender-side TokenStore (used by Orchestrator step3.5 to resolve the sender tokenRef)
        const senderStore = new InMemoryTokenStore();
        senderStore.put(agentADid, senderToken);

        // PolicyEngine uses a real RuntimeGuard + a real recorder stub
        const recordedActions: ActionRecordInput[] = [];
        const recorder = {
            record: (input: ActionRecordInput): Promise<RecordWriteResult> => {
                recordedActions.push(input);
                return Promise.resolve({
                    recordId: `record-${recordedActions.length}`,
                    hash: 'a'.repeat(64),
                });
            },
        };
        const runtimeGuard = new RuntimeGuard({
            tokenStore: recipientStore,
            revocationChecker: () => Promise.resolve(false),
            now: () => '2026-04-21T10:30:00.000Z' as Timestamp,
        });
        const policyEngine = new PolicyEngine({
            guard: runtimeGuard,
            recorder,
        });

        // ── Orchestrator (held by recipient-side Agent B) ──
        // step3.5 needs to resolve the sender's Token -> inject senderStore as the tokenStore port
        const orchestrator = new Orchestrator({
            agentDid: agentBDid,
            agentPrivateKey: agentBKeyPair.privateKey,
            principalDid: bobPrincipalDid,
            policyEngine,
            transport: {} as never,
            // Inject the same clock into the step3.5 leaf time-window check, to avoid wall-clock drift
            // past the token's expiry causing a false delegation_token_expired.
            now: () => '2026-04-21T10:30:00.000Z' as Timestamp,
            // Public-key resolution: must be able to resolve both sender (Agent A) and recipient (Agent B)
            resolvePublicKey: (did) => {
                if (did === agentADid) {
                    return Promise.resolve(agentAKeyPair.publicKey);
                }
                if (did === agentBDid) {
                    return Promise.resolve(agentBKeyPair.publicKey);
                }
                return Promise.resolve(null);
            },
            // Document resolution: we only care that the sender's principalDid matches senderToken
            resolveAgentDocument: (did) => {
                if (did === agentADid) {
                    return Promise.resolve({
                        id: agentADid,
                        specVersion: SPEC_VERSION_0_2_0,
                        principalDid: alicePrincipalDid,
                        publicKey: agentAKeyPair.publicKey,
                        bindingProof: {} as never,
                        createdAt: '2026-04-21T10:00:00.000Z',
                        updatedAt: '2026-04-21T10:00:00.000Z',
                    } as unknown as AgentIdentityDocument);
                }
                return Promise.resolve(null);
            },
            tokenStore: senderStore,
            revocationChecker: () => Promise.resolve(false),
            delegationChainValidator: () =>
                Promise.resolve({ valid: true, depth: 0 }),
            // A step3.5 rejection must also write an ActionRecord; reuse the PolicyEngine's recorder
            // so the audit chain stays unified on the same ledger.
            policyRecorder: recorder,
            businessHandler: ({ action, params }) =>
                Promise.resolve({
                    handledAction: action,
                    echoedRecipient: params['recipient'],
                }),
        });

        // ── Build the capability-bound envelope (signed by sender) ──
        const incoming = buildEnvelope({
            senderDid: agentADid,
            senderPrivateKey: agentAKeyPair.privateKey,
            recipientDid: agentBDid,
            sessionId: 'session-integration',
            messageType: 'NEGOTIATION_REQUEST',
            body: {
                action: 'INQUIRY',
                params: { recipient: 'supplier-a' },
                requestId: 'req-integration-1',
            },
            capabilityTokenRef: senderToken.id,
        });

        // ── Execute ──
        const result = await orchestrator.handleEnvelope(incoming);

        // ── Assert: this request should pass all 5 steps (key point: RuntimeGuard uses the recipient pool, unaffected by the sender tokenId) ──
        expect(result.handled).toBe(true);
        expect(result.rejectionReason).toBeUndefined();

        // The ActionRecord should record the recipient's tokenId (Bob-side Token-B.id), not the sender's tokenId
        expect(recordedActions.length).toBe(1);
        const authRef = recordedActions[0]?.authorizationRef as
            | Record<string, unknown>
            | undefined;
        expect(authRef?.['tokenId']).toBe(recipientToken.id);
        expect(authRef?.['tokenId']).not.toBe(senderToken.id);
    });

    it('should still reject capability-bound envelope when recipient has no matching local authorization', async () => {
        // Regression: the sender's tokenRef passes validation, but the recipient pool has no matching Token
        // -> RuntimeGuard rejects per the direct-path semantics (no tokens found).
        const aliceKeyPair = generateKeyPair();
        const alicePrincipalDid = didKeyFromPublicKey(
            Buffer.from(aliceKeyPair.publicKey, 'hex'),
        );
        const agentAKeyPair = generateKeyPair();
        const agentADid =
            'did:agent:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' as DID;

        const senderToken = issueCapabilityToken({
            issuerDid: alicePrincipalDid,
            issuedTo: agentADid,
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
            expiresAt: '2026-04-22T10:00:00.000Z' as Timestamp,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuerPrivateKey: aliceKeyPair.privateKey,
            issuedAt: '2026-04-21T10:00:00.000Z' as Timestamp,
        });

        const bobKeyPair = generateKeyPair();
        const bobPrincipalDid = didKeyFromPublicKey(
            Buffer.from(bobKeyPair.publicKey, 'hex'),
        );
        const agentBKeyPair = generateKeyPair();
        const agentBDid =
            'did:agent:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' as DID;

        // Recipient pool is empty: Bob signed no Token for Agent B
        const recipientStore = new InMemoryTokenStore();
        const senderStore = new InMemoryTokenStore();
        senderStore.put(agentADid, senderToken);

        const recorder = {
            record: () =>
                Promise.resolve({
                    recordId: 'record-denied',
                    hash: 'b'.repeat(64),
                }),
        };
        const runtimeGuard = new RuntimeGuard({
            tokenStore: recipientStore,
            revocationChecker: () => Promise.resolve(false),
            now: () => '2026-04-21T10:30:00.000Z' as Timestamp,
        });
        const policyEngine = new PolicyEngine({
            guard: runtimeGuard,
            recorder,
        });

        const orchestrator = new Orchestrator({
            agentDid: agentBDid,
            agentPrivateKey: agentBKeyPair.privateKey,
            principalDid: bobPrincipalDid,
            policyEngine,
            transport: {} as never,
            // Same as above: inject the clock to avoid wall-clock drift falsely expiring the leaf token.
            now: () => '2026-04-21T10:30:00.000Z' as Timestamp,
            resolvePublicKey: (did) => {
                if (did === agentADid) {
                    return Promise.resolve(agentAKeyPair.publicKey);
                }
                return Promise.resolve(null);
            },
            resolveAgentDocument: (did) => {
                if (did === agentADid) {
                    return Promise.resolve({
                        id: agentADid,
                        specVersion: SPEC_VERSION_0_2_0,
                        principalDid: alicePrincipalDid,
                        publicKey: agentAKeyPair.publicKey,
                        bindingProof: {} as never,
                        createdAt: '2026-04-21T10:00:00.000Z',
                        updatedAt: '2026-04-21T10:00:00.000Z',
                    } as unknown as AgentIdentityDocument);
                }
                return Promise.resolve(null);
            },
            tokenStore: senderStore,
            revocationChecker: () => Promise.resolve(false),
            delegationChainValidator: () =>
                Promise.resolve({ valid: true, depth: 0 }),
            // A step3.5 rejection must also write an ActionRecord; reuse the PolicyEngine's recorder
            // so the audit chain stays unified on the same ledger.
            policyRecorder: recorder,
            businessHandler: () => Promise.resolve({}),
        });

        const incoming = buildEnvelope({
            senderDid: agentADid,
            senderPrivateKey: agentAKeyPair.privateKey,
            recipientDid: agentBDid,
            sessionId: 'session-no-local-auth',
            messageType: 'NEGOTIATION_REQUEST',
            body: {
                action: 'INQUIRY',
                params: { recipient: 'supplier-a' },
            },
            capabilityTokenRef: senderToken.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        // step3.5 passes (sender tokenRef is valid), step4 RuntimeGuard rejects (recipient pool is empty)
        expect(result.handled).toBe(false);
        expect(result.rejectionReason).toBe('no tokens found');
    });
});
