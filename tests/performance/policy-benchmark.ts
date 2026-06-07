import { performance } from 'node:perf_hooks';

import { generateKeyPair } from '@coivitas/crypto';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
    issueCapabilityToken,
    verifyCapabilityToken,
} from '@coivitas/identity';
import { createTestDatabase } from '@coivitas/shared';
import type { Timestamp } from '@coivitas/types';

import {
    ActionRecorder,
    PolicyEngine,
    RuntimeGuard,
    TokenStore,
} from '../../packages/policy/src/index.js';

async function main(): Promise<void> {
    if (!process.env.DATABASE_URL) {
        throw new Error(
            'DATABASE_URL is required to run the policy benchmark.',
        );
    }

    const database = await createTestDatabase();

    try {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const agent = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });
        const ledger = generateKeyPair();
        const issuer = generateKeyPair();
        const issuerDid = didKeyFromPublicKey(
            Buffer.from(issuer.publicKey, 'hex'),
        );
        const token = issueCapabilityToken({
            issuerDid,
            issuedTo: agent.document.id,
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
            issuerPrivateKey: issuer.privateKey,
            issuedAt: '2026-04-21T10:00:00.000Z' as Timestamp,
        });

        const tokenStore = new TokenStore(database.pool);
        await tokenStore.store(agent.document.id, token);
        const guard = new RuntimeGuard({
            tokenStore,
            revocationChecker() {
                return Promise.resolve(false);
            },
            now: () => '2026-04-21T10:05:00.000Z' as Timestamp,
        });
        const recorder = new ActionRecorder(database.pool, {
            kind: 'standard',
            ledgerPrivateKey: ledger.privateKey.slice(0, 64),
        });
        const engine = new PolicyEngine({ guard, recorder });

        const verifyDuration = await benchmark(() => {
            verifyCapabilityToken(
                token,
                '2026-04-21T10:05:00.000Z' as Timestamp,
            );
            return Promise.resolve();
        });
        const guardDuration = await benchmark(async () => {
            await guard.check(
                'INQUIRY',
                { recipient: 'supplier-a' },
                agent.document.id,
            );
        });
        const recorderDuration = await benchmark(async () => {
            await recorder.record({
                agentDid: agent.document.id,
                principalDid,
                actionType: 'INQUIRY',
                parametersSummary: { recipient: 'supplier-a' },
                resultSummary: { status: 'SUCCESS' },
                actorPrivateKey: agent.privateKey,
            });
        });
        const engineDuration = await benchmark(async () => {
            await engine.executeWithPolicy({
                action: 'INQUIRY',
                params: { recipient: 'supplier-a' },
                agentDid: agent.document.id,
                principalDid,
                actorPrivateKey: agent.privateKey,
                executor: () => Promise.resolve(true),
            });
        });

        console.log(
            JSON.stringify(
                {
                    environment: {
                        node: process.version,
                        platform: process.platform,
                        arch: process.arch,
                    },
                    verifyCapabilityTokenP99Ms: verifyDuration,
                    guardCheckP99Ms: guardDuration,
                    actionRecorderRecordP99Ms: recorderDuration,
                    engineExecuteP99Ms: engineDuration,
                },
                null,
                2,
            ),
        );
    } finally {
        await database.cleanup();
    }
}

async function benchmark(
    fn: () => Promise<void>,
    iterations = 1000,
): Promise<number> {
    const samples: number[] = [];

    for (let index = 0; index < iterations; index += 1) {
        const start = performance.now();
        await fn();
        samples.push(performance.now() - start);
    }

    samples.sort((left, right) => left - right);
    return (
        samples[
            Math.min(samples.length - 1, Math.floor(samples.length * 0.99))
        ] ?? 0
    );
}

void main();
