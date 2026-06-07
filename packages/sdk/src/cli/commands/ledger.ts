import { Command } from 'commander';

import { ActionRecorder, IntegrityChecker } from '@coivitas/policy';
import type {
    ActionRecordQueryFilters,
    IntegrityCheckResult,
} from '@coivitas/policy';
import type { DatabasePool } from '@coivitas/shared';
import type { DID } from '@coivitas/types';
import {
    isSessionGovernorDid,
    SESSION_GOVERNOR_DID,
} from '@coivitas/types';

import { createCliPool, printOutput, resolveRegistryUrl } from '../runtime.js';
import { resolveDemoPublicKey } from '../../golden-path/utils.js';
import { createLedgerAnchorCommand } from './ledger-anchor.js';

export const createLedgerCommand = (): Command => {
    const command = new Command('ledger').description(
        'Query and verify ledger-backed action records.',
    );

    command
        .command('query')
        .description('Query ledger records for an agent.')
        .requiredOption('--agent-did <did>', 'Agent DID to inspect.')
        .option(
            '--since <timestamp>',
            'Optional ISO-8601 timestamp lower bound for the query.',
        )
        .option('--json', 'Print machine-readable JSON.', false)
        .action(
            async (options: {
                agentDid: string;
                since?: string;
                json?: boolean;
            }) => {
                const pool = createCliPool();
                try {
                    // LEDGER_PRIVATE_KEY fail-fast (aligned with the verify subcommand).
                    const ledgerPrivateKey = process.env.LEDGER_PRIVATE_KEY;
                    if (!ledgerPrivateKey) {
                        throw new Error(
                            'LEDGER_PRIVATE_KEY is required for ledger query.',
                        );
                    }
                    const recorder = new ActionRecorder(pool, {
                        kind: 'standard',
                        ledgerPrivateKey,
                    });
                    const { records } = await recorder.query({
                        agentDid: options.agentDid as never,
                        createdFrom: options.since as never,
                    });

                    printOutput(records, options.json);
                } finally {
                    await pool.end();
                }
            },
        );

    command.addCommand(createLedgerVerifyCommand());
    command.addCommand(createLedgerAnchorCommand());

    return command;
};

export interface LedgerVerifyOptions {
    agentDid: string;
    registryUrl?: string;
    chain?: boolean;
    from?: string;
    to?: string;
    json?: boolean;
}

export interface VerifyChecker {
    verifyIntegrity(
        agentDid: DID,
        filters?: Omit<ActionRecordQueryFilters, 'agentDid'>,
    ): Promise<IntegrityCheckResult>;
}

/**
 * Chain-segment genesis lookup interface: returns the createdAt (ISO string) of this agent's earliest record in history.
 * When the window start specified by --chain --from <ts> is strictly later than createdAt, correct verification requires
 * "anchoring to the record_hash of the record before the window" -- IntegrityChecker currently hardcodes
 * `expectedPreviousRecordHash = ''` (genesis sentinel) and does not support non-genesis anchors. The same
 * limitation also exists in the GET /records/chain/verify server-side route (cf.
 * packages/policy/src/recorder/action-record-routes.ts:800). This CLI only proceeds once it has confirmed that
 * the window start <= the genesis record's time, to avoid producing a spurious "previous_record_hash mismatch".
 *
 * Real non-genesis chain-segment verification requires adding
 * verifyChainSegment(agentDid, anchorRecordHash, filters) (or an equivalent API) to IntegrityChecker;
 * once that lands, the rejection branch here can be removed.
 */
export interface GenesisProbe {
    findGenesisCreatedAt(agentDid: DID): Promise<string | null>;
}

export interface LedgerVerifyDeps {
    /** Optional override for tests; in production we build IntegrityChecker against the pool.*/
    checkerFactory?: (pool: DatabasePool) => VerifyChecker;
    /** Optional override for tests; defaults to ActionRecorder.query(limit:1, ASC).*/
    genesisProbeFactory?: (pool: DatabasePool) => GenesisProbe;
}

function defaultGenesisProbeFactory(pool: DatabasePool): GenesisProbe {
    // The genesis lookup only reads created_at, but ActionRecorder
    // construction still needs ledgerPrivateKey; this goes through the verify subcommand's same env-check path,
    // and the upstream runLedgerVerify has already fail-fasted to guarantee LEDGER_PRIVATE_KEY is present.
    const recorder = new ActionRecorder(pool, {
        kind: 'standard',
        ledgerPrivateKey: process.env.LEDGER_PRIVATE_KEY!,
    });
    return {
        async findGenesisCreatedAt(agentDid) {
            const { records } = await recorder.query({
                agentDid,
                limit: 1,
            });
            return records[0]?.createdAt ?? null;
        },
    };
}

export async function runLedgerVerify(
    options: LedgerVerifyOptions,
    deps: LedgerVerifyDeps = {},
): Promise<IntegrityCheckResult> {
    const pool = createCliPool();

    try {
        let checker: VerifyChecker;
        if (deps.checkerFactory) {
            checker = deps.checkerFactory(pool);
        } else {
            const ledgerPrivateKey = process.env.LEDGER_PRIVATE_KEY;
            if (!ledgerPrivateKey) {
                throw new Error(
                    'LEDGER_PRIVATE_KEY is required for ledger verify.',
                );
            }
            // Automatically pick the lane by agentDid.
            // - agentDid === SESSION_GOVERNOR_DID: use the control-plane checker,
            // injecting GOVERNOR_PUBLIC_KEY as resolveControlPlanePublicKey;
            // - any other business agent: use the standard checker, going through federated DID resolution.
            // If it always used kind='standard', the governor DID would falsely report
            // 'agent public key unavailable' -> loss of governance-lane observability.
            if (isSessionGovernorDid(options.agentDid)) {
                const governorPublicKey = process.env.GOVERNOR_PUBLIC_KEY;
                if (!governorPublicKey) {
                    throw new Error(
                        'GOVERNOR_PUBLIC_KEY is required for ledger verify on ' +
                            'SESSION_GOVERNOR_DID. Set GOVERNOR_PUBLIC_KEY env ' +
                            'or pass --registry-url for an environment that exposes it.',
                    );
                }
                checker = new IntegrityChecker(pool, {
                    kind: 'control-plane',
                    ledgerPrivateKey,
                    resolveControlPlanePublicKey: (did: DID) =>
                        Promise.resolve(
                            (did as string) === SESSION_GOVERNOR_DID
                                ? governorPublicKey
                                : null,
                        ),
                });
            } else {
                checker = new IntegrityChecker(pool, {
                    kind: 'standard',
                    ledgerPrivateKey,
                    resolveIdentity: async (did: DID) =>
                        await resolveDemoPublicKey(
                            did,
                            resolveRegistryUrl(options.registryUrl),
                        ),
                });
            }
        }

        // chain mode is enabled only when --chain is explicitly given, to avoid inadvertently silently dropping off-chain records.
        const filters: Omit<ActionRecordQueryFilters, 'agentDid'> = {};
        if (options.chain) {
            if (options.from === undefined && options.to === undefined) {
                throw new Error(
                    '--chain requires at least one of --from or --to.',
                );
            }
            if (options.from !== undefined) {
                // Anchor pre-check: if --from is strictly later than this agent's
                // genesis record, the window must use "the previous record's record_hash" as the expected value, whereas
                // IntegrityChecker.verifyIntegrity currently hardcodes '' (empty hash) for the first record,
                // so proceeding directly would yield a spurious previous_record_hash mismatch.
                // Real non-genesis anchor verification requires extending IntegrityChecker (see the
                // GenesisProbe interface comment); reject here for now to avoid misleading the operator.
                const probe = (
                    deps.genesisProbeFactory ?? defaultGenesisProbeFactory
                )(pool);
                const genesisCreatedAt = await probe.findGenesisCreatedAt(
                    options.agentDid as DID,
                );
                if (
                    genesisCreatedAt !== null &&
                    genesisCreatedAt < options.from
                ) {
                    throw new Error(
                        `--chain --from=${options.from} starts after the agent's genesis record (${genesisCreatedAt}). ` +
                            `Non-genesis chain-segment verification is not yet supported by the upstream IntegrityChecker ` +
                            `(IntegrityChecker.verifyChainSegment with explicit anchor hash is not implemented). ` +
                            `Workaround: omit --from to verify the entire ledger, or use --chain --to=<ts> only.`,
                    );
                }
                filters.createdFrom = options.from as never;
            }
            if (options.to !== undefined) {
                filters.createdTo = options.to as never;
            }
        }

        const result = await checker.verifyIntegrity(
            options.agentDid as DID,
            filters,
        );

        const payload = {
            agentDid: options.agentDid,
            chain: options.chain ?? false,
            from: options.from,
            to: options.to,
            ...result,
        };

        if (options.json) {
            printOutput(payload, true);
        } else if (result.valid) {
            printOutput(
                options.chain
                    ? `Chain segment verified for ${options.agentDid} (${options.from ?? '-∞'} → ${options.to ?? '+∞'}).`
                    : `Ledger verified for ${options.agentDid}.`,
            );
        } else {
            printOutput(
                [
                    `Ledger verification FAILED for ${options.agentDid}`,
                    `  brokenAt: ${result.brokenAt ?? '(unknown)'}`,
                    `  reason:   ${result.reason ?? '(unknown)'}`,
                ].join('\n'),
            );
        }

        if (!result.valid) {
            process.exitCode = 1;
        }

        return result;
    } finally {
        await pool.end();
    }
}

export const createLedgerVerifyCommand = (): Command => {
    return new Command('verify')
        .description('Verify ledger integrity for an agent.')
        .requiredOption('--agent-did <did>', 'Agent DID to verify.')
        .option(
            '--registry-url <url>',
            'Identity registry URL used to resolve agent public keys.',
        )
        .option(
            '--chain',
            'Restrict verification to the chain segment given by --from / --to.',
            false,
        )
        .option(
            '--from <timestamp>',
            'ISO-8601 lower bound (inclusive) for chain segment verification.',
        )
        .option(
            '--to <timestamp>',
            'ISO-8601 upper bound (inclusive) for chain segment verification.',
        )
        .option('--json', 'Print machine-readable JSON.', false)
        .action(async (options: LedgerVerifyOptions) => {
            await runLedgerVerify(options);
        });
};
