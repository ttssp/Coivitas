/**
 * e2e positive test — verification of a healthy ledger that contains SESSION_SUPERSEDED should pass.
 *
 * Precondition: DATABASE_URL must point at a usable Postgres (same gate as integrity-checker.test.ts).
 *
 * Core assertions:
 * 1. Mixed ledger (ordinary agent record + governor SESSION_SUPERSEDED record) -> valid: true
 * 2. With the governor public key missing, the same ledger -> valid: false + reason='agent public key unavailable'
 *    (i.e. the "healthy ledger misjudged as corrupt" phenomenon)
 * 3. With the wrong governor public key -> valid: false + reason='actor_signature invalid'
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { generateKeyPair } from '@coivitas/crypto';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
    IdentityRegistry,
} from '@coivitas/identity';
import { createTestDatabase } from '@coivitas/shared';
import type { DID } from '@coivitas/types';
import { SESSION_GOVERNOR_DID } from '@coivitas/types';

import { ActionRecorder, IntegrityChecker } from '../../index.js';
import { assertSchemaCompliant } from '../../audit-governor-lane/assert-schema-compliant.js';
import { InMemorySideTableAppender } from '../../audit-governor-lane/side-table.js';

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

describeIfDatabase(
    'IntegrityChecker with SESSION_SUPERSEDED',
    () => {
        let cleanup: (() => Promise<void>) | undefined;
        let pool: Awaited<ReturnType<typeof createTestDatabase>>['pool'];
        let registry: IdentityRegistry;

        // ordinary agent
        let agentDid: DID;
        let agentPrivateKey: string;
        let principalDid: DID;

        // governor key pair (control-plane signer)
        let governorKeyPair: { publicKey: string; privateKey: string };

        // ledger signing key pair
        let ledgerKeyPair: { publicKey: string; privateKey: string };
        let recorder: ActionRecorder;
        // lane enforcement routes SESSION_SUPERSEDED through the control-plane recorder
        let controlPlaneRecorder: ActionRecorder;

        beforeAll(async () => {
            const database = await createTestDatabase();
            cleanup = database.cleanup;
            pool = database.pool;

            registry = new IdentityRegistry(pool);

            // 1. register an ordinary agent
            const principal = generateKeyPair();
            principalDid = didKeyFromPublicKey(
                Buffer.from(principal.publicKey, 'hex'),
            );
            const agent = createAgentIdentity({
                principalDid,
                principalPrivateKey: principal.privateKey,
            });
            agentDid = agent.document.id;
            agentPrivateKey = agent.privateKey;
            await registry.register(agent.document);

            // 2. generate the governor key pair (not registered in the registry — the governor does not participate in federated DID resolution)
            governorKeyPair = generateKeyPair();

            // 3. generate the ledger key pair
            ledgerKeyPair = generateKeyPair();
            recorder = new ActionRecorder(pool, {
                kind: 'standard',
                ledgerPrivateKey: ledgerKeyPair.privateKey.slice(0, 64),
            });
            // control-plane must inject sessionOwnerResolver + assertSchemaCompliant.
            // The integration test uses a permissive resolver (returns, for any sessionId, the affected DIDs used at write time).
            const permissiveResolver = {
                resolveOwner: () =>
                    Promise.resolve({
                        agentDid: agentDid,
                        principalDid: principalDid,
                    }),
            };
            controlPlaneRecorder = new ActionRecorder(pool, {
                kind: 'control-plane',
                ledgerPrivateKey: ledgerKeyPair.privateKey.slice(0, 64),
                sessionOwnerResolver: permissiveResolver,
                assertSchemaCompliant,
                sideTableAppender: new InMemorySideTableAppender(),
            });

            // 4. write an ordinary agent record (standard recorder)
            await recorder.record({
                agentDid,
                principalDid,
                actionType: 'INQUIRY',
                parametersSummary: { product: 'test' },
                resultSummary: { ok: true },
                actorPrivateKey: agentPrivateKey,
            });

            // 5. write a SESSION_SUPERSEDED record (governor as actor, control-plane recorder)
            await controlPlaneRecorder.record({
                agentDid: SESSION_GOVERNOR_DID as DID,
                principalDid: SESSION_GOVERNOR_DID as DID,
                actionType: 'SESSION_SUPERSEDED',
                parametersSummary: {
                    oldSessionId: 'session-old-001',
                    newSessionId: 'session-new-001',
                    reason: 'EXPLICIT_CLOSE',
                    timestamp: new Date().toISOString(),
                    affectedAgentDid: agentDid,
                    affectedPrincipalDid: principalDid,
                },
                resultSummary: null,
                actorPrivateKey: governorKeyPair.privateKey.slice(0, 64),
            });

            // 6. write one more ordinary agent record (verifies mixed-chain integrity, standard recorder)
            await recorder.record({
                agentDid,
                principalDid,
                actionType: 'CONFIRM',
                parametersSummary: { confirmed: true },
                resultSummary: { ok: true },
                actorPrivateKey: agentPrivateKey,
            });
        });

        afterAll(async () => {
            await cleanup?.();
        });

        it('should verify a healthy mixed ledger (agent + governor records) using separate DU checkers', async () => {
            // After the DU refactor, standard and control-plane are independent checker instances.
            // Core happy path: the standard checker verifies the agent chain, the control-plane checker verifies the governor chain.
            const standardChecker = new IntegrityChecker(pool, {
                kind: 'standard',
                ledgerPrivateKey: ledgerKeyPair.privateKey.slice(0, 64),
                ledgerPublicKey: recorder.ledgerPublicKey,
                resolveIdentity: async (did) =>
                    (await registry.query(did))?.publicKey ?? null,
            });

            const controlPlaneChecker = new IntegrityChecker(pool, {
                kind: 'control-plane',
                ledgerPrivateKey: ledgerKeyPair.privateKey.slice(0, 64),
                ledgerPublicKey: recorder.ledgerPublicKey,
                resolveControlPlanePublicKey: () =>
                    Promise.resolve(governorKeyPair.publicKey),
            });

            // agent record chain verification (standard checker)
            const agentResult = await standardChecker.verifyIntegrity(agentDid);
            expect(agentResult).toEqual({ valid: true });

            // governor record chain verification (control-plane checker)
            const governorResult = await controlPlaneChecker.verifyIntegrity(
                SESSION_GOVERNOR_DID as DID,
            );
            expect(governorResult).toEqual({ valid: true });
        });

        it('should fail-closed when standard checker encounters governor DID (DU compile-time enforcement)', async () => {
            // After the DU refactor, a standard-mode checker automatically fail-closes when it encounters a governor DID.
            // This replaces the old runtime check (the "governor public key is null" judgment has been absorbed into the type layer).
            const standardChecker = new IntegrityChecker(pool, {
                kind: 'standard',
                ledgerPrivateKey: ledgerKeyPair.privateKey.slice(0, 64),
                ledgerPublicKey: recorder.ledgerPublicKey,
                resolveIdentity: async (did) =>
                    (await registry.query(did))?.publicKey ?? null,
            });

            // agent record chain is unaffected
            const agentResult = await standardChecker.verifyIntegrity(agentDid);
            expect(agentResult).toEqual({ valid: true });

            // governor record chain: in standard mode a governor DID -> fail-closed
            const governorResult = await standardChecker.verifyIntegrity(
                SESSION_GOVERNOR_DID as DID,
            );
            expect(governorResult.valid).toBe(false);
            expect(governorResult.reason).toBe('agent public key unavailable');
        });

        it('should detect wrong governor public key as signature invalid (control-plane checker)', async () => {
            // control-plane checker uses the wrong governor public key -> signature verification fails
            const wrongKey = generateKeyPair();
            const controlPlaneChecker = new IntegrityChecker(pool, {
                kind: 'control-plane',
                ledgerPrivateKey: ledgerKeyPair.privateKey.slice(0, 64),
                ledgerPublicKey: recorder.ledgerPublicKey,
                resolveControlPlanePublicKey: () =>
                    Promise.resolve(wrongKey.publicKey),
            });

            const governorResult = await controlPlaneChecker.verifyIntegrity(
                SESSION_GOVERNOR_DID as DID,
            );
            expect(governorResult.valid).toBe(false);
            expect(governorResult.reason).toBe('actor_signature invalid');
        });
    },
);
