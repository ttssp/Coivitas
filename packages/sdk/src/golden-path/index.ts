import { IdentityRegistry, RevocationList } from '@coivitas/identity';

import type {
    GoldenPathContext,
    GoldenPathOptions,
    GoldenPathResult,
} from './context.js';
import { runStep } from './runner.js';
import {
    runStep0,
    runStep1,
    runStep2,
    runStep3,
    runStep4,
} from './steps-0-4.js';
import {
    runStep10,
    runStep11,
    runStep12,
    runStep13,
    runStep14,
    runStep15,
} from './steps-10-15.js';
import {
    runStep5,
    runStep6,
    runStep7,
    runStep8,
    runStep9,
} from './steps-5-9.js';
import {
    runStep16,
    runStep17,
    runStep18,
    runStep19,
    runStep20,
} from './steps-16-20.js';
import {
    runStep21,
    runStep22,
    runStep23,
    runStep24,
    runStep25,
} from './steps-21-25.js';
import {
    runStep26,
    runStep27,
    runStep28,
    runStep29,
    runStep30,
    runStep31,
    runStep32,
} from './steps-26-32.js';
import {
    ensureLedgerPrivateKey,
    ensurePool,
    startLocalIdentityService,
} from './utils.js';

export async function runGoldenPath(
    options: GoldenPathOptions,
): Promise<GoldenPathResult> {
    const startedAt = Date.now();
    const { pool, ownPool } = ensurePool(options.pool);
    const verbose = options.verbose ?? false;
    const identityService =
        options.identityRegistryUrl === undefined
            ? await startLocalIdentityService(pool)
            : null;

    const ctx: GoldenPathContext = {
        pool,
        ownPool,
        verbose,
        identityRegistryUrl:
            options.identityRegistryUrl ?? identityService!.url,
        ledgerPrivateKey: ensureLedgerPrivateKey(options.ledgerPrivateKey),
        // (F1-twenty): the governor public key is injected from options or an environment variable.
        governorPublicKey:
            options.governorPublicKey ??
            process.env.GOVERNOR_PUBLIC_KEY ??
            undefined,
        // The governor private key is injected from options or an environment variable.
        // When omitted, Step 32 falls back to ledgerPrivateKey (only applicable to the "governor and ledger share a key" development model).
        governorPrivateKey:
            options.governorPrivateKey ??
            process.env.GOVERNOR_PRIVATE_KEY ??
            undefined,
        cleanups: [],
    };
    ctx.identityRegistry = new IdentityRegistry(pool);
    ctx.revocationList = new RevocationList(pool);

    if (identityService) {
        ctx.cleanups.push(identityService.close);
    }

    const errors: Array<{ step: number; error: string }> = [];
    const records = [];
    const stepStartForCoreFlow: number[] = [];

    // Step 31 is now implemented: EnvelopeLedger crash-recovery integration test (no longer SKIPped).
    // STEP_31_SKIP_RECORD removed; Step 31 is registered as a real function in the step array below.

    for (const [number, name, fn] of [
        [0, 'Generate principal keys', () => runStep0(ctx)],
        [1, 'Register Agent-A', () => runStep1(ctx)],
        [2, 'Register Agent-B', () => runStep2(ctx)],
        [3, 'Issue token A', () => runStep3(ctx)],
        [4, 'Issue token B', () => runStep4(ctx)],
        [5, 'Resolve Agent-B DID', () => runStep5(ctx)],
        [6, 'Complete handshake', () => runStep6(ctx)],
        [7, 'Send inquiry request', () => runStep7(ctx)],
        [8, 'Responder authorization check', () => runStep8()],
        [9, 'Receive quote response', () => runStep9(ctx)],
        [10, 'Authorize confirm on Agent-A', () => runStep10(ctx)],
        [11, 'Send confirm request', () => runStep11(ctx)],
        [12, 'Write action records', () => runStep12(ctx)],
        [13, 'Verify ledger integrity', () => runStep13(ctx)],
        [14, 'Revoke token A', () => runStep14(ctx)],
        [15, 'Verify revoked token denial', () => runStep15(ctx)],
        [16, 'Publish Agent-A AgentCard', () => runStep16(ctx)],
        [17, 'Discover Agent-A via AgentCard', () => runStep17(ctx)],
        [18, 'Confirm Principal→A direct issuance', () => runStep18(ctx)],
        [19, 'Delegate A→B sub-token + verify chain', () => runStep19(ctx)],
        [20, 'Revocation cascades to delegated token', () => runStep20(ctx)],
        [21, 'Initiate key rotation for Agent-A', () => runStep21(ctx)],
        [22, 'Grace-period old signature remains valid', () => runStep22(ctx)],
        [23, 'Complete rotation: old fails, new passes', () => runStep23(ctx)],
        [24, 'temporal_scope enforces time window', () => runStep24(ctx)],
        [25, 'cumulative_limit enforces running total', () => runStep25(ctx)],
        [26, 'Dual-key ROTATING pass', () => runStep26(ctx)],
        [27, 'E2E encryption happy path', () => runStep27(ctx)],
        [28, 'audit-before-execute barrier', () => runStep28(ctx)],
        [29, 'cumulative settle cross-domain', () => runStep29(ctx)],
        [30, 'quorum fault injection', () => runStep30(ctx)],
        [31, 'EnvelopeLedger crash recovery', () => runStep31(ctx)],
        [32, 'SESSION_SUPERSEDED on-chain', () => runStep32(ctx)],
    ] as const) {
        if (number >= 6 && number <= 11) {
            stepStartForCoreFlow.push(Date.now());
        }

        const result = await runStep(number, name, fn, verbose);
        records.push(result.record);
        if (result.error) {
            errors.push({ step: number, error: result.error.message });
        }
    }

    await Promise.all(
        ctx.cleanups
            .slice()
            .reverse()
            .map(async (cleanup) => {
                await cleanup();
            }),
    );

    if (ownPool) {
        await pool.end();
    }

    const coreSteps = records.filter(
        (record) => record.number >= 6 && record.number <= 11,
    );

    return {
        success: errors.length === 0,
        steps: records,
        totalDurationMs: Date.now() - startedAt,
        coreFlowDurationMs: coreSteps.reduce(
            (sum, record) => sum + record.durationMs,
            0,
        ),
        errors,
    };
}
