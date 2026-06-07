import { Command } from 'commander';

import {
    delegateCapabilityToken,
    issueCapabilityToken,
    verifyCapabilityToken,
} from '@coivitas/identity';
import type {
    Capability,
    CapabilityToken,
    DID,
    Timestamp,
} from '@coivitas/types';

import {
    defaultPrivateKeyPath,
    postJson,
    printOutput,
    readJsonFile,
    readPrivateKeyFile,
    resolveRegistryUrl,
} from '../runtime.js';

const DEFAULT_REVOCATION_URL =
    'https://revocation.example.com/api/v1/revocations/{id}';

export const createTokenCommand = (): Command => {
    const command = new Command('token').description(
        'Issue, verify, and revoke capability tokens.',
    );

    command
        .command('issue')
        .description('Issue a capability token for a target agent.')
        .requiredOption(
            '--issuer-did <did>',
            'Principal DID issuing the capability token.',
        )
        .requiredOption('--agent-did <did>', 'Agent DID receiving the token.')
        .requiredOption(
            '--action <action>',
            'Authorized action vocabulary item.',
        )
        .requiredOption(
            '--scope <json>',
            'JSON-encoded scope object applied to the action.',
        )
        .option('--expires-in <seconds>', 'Token validity in seconds.', '86400')
        .option(
            '--issuer-key-file <path>',
            'Issuer private key file. Defaults to ~/.coivitas/keys/<issuer-did>.pem',
        )
        .option('--json', 'Print the full token JSON.', false)
        .action(
            async (options: {
                issuerDid: string;
                agentDid: string;
                action: string;
                scope: string;
                expiresIn: string;
                issuerKeyFile?: string;
                json?: boolean;
            }) => {
                const issuerKey = await readPrivateKeyFile(
                    options.issuerKeyFile ??
                        defaultPrivateKeyPath(options.issuerDid),
                );
                const expiresAt = new Date(
                    Date.now() + Number(options.expiresIn) * 1000,
                ).toISOString();
                const scope = JSON.parse(options.scope) as Record<
                    string,
                    unknown
                >;
                const token = issueCapabilityToken({
                    issuerDid: options.issuerDid as never,
                    issuedTo: options.agentDid as never,
                    capabilities: [
                        {
                            action: options.action as never,
                            scope: scope as never,
                        },
                    ],
                    expiresAt: expiresAt as never,
                    revocationUrl:
                        'https://revocation.example.com/api/v1/revocations/{id}',
                    issuerPrivateKey: issuerKey,
                });

                if (options.json) {
                    printOutput(token, true);
                    return;
                }

                printOutput(
                    [
                        'Capability token issued',
                        `  Token ID: ${token.id}`,
                        `  Issuer:   ${token.issuerDid}`,
                        `  Agent:    ${token.issuedTo}`,
                        `  Action:   ${options.action}`,
                        `  Expires:  ${token.expiresAt}`,
                    ].join('\n'),
                );
            },
        );

    command
        .command('verify')
        .description('Verify a capability token JSON file.')
        .argument('<token-json-file>', 'Path to the token JSON file.')
        .option('--now <timestamp>', 'Verification timestamp override.')
        .action(async (tokenJsonFile: string, options: { now?: string }) => {
            const token =
                await readJsonFile<Parameters<typeof verifyCapabilityToken>[0]>(
                    tokenJsonFile,
                );
            const result = verifyCapabilityToken(
                token,
                (options.now ?? new Date().toISOString()) as never,
            );

            printOutput(result, true);

            if (!result.valid) {
                process.exitCode = 1;
            }
        });

    command
        .command('revoke')
        .description('Revoke a capability token by id.')
        .argument('<token-id>', 'Capability token id to revoke.')
        .requiredOption(
            '--principal-did <did>',
            'Principal DID revoking the token.',
        )
        .option(
            '--registry-url <url>',
            'Identity registry URL hosting the revocation route.',
        )
        .action(
            async (
                tokenId: string,
                options: { principalDid: string; registryUrl?: string },
            ) => {
                const registryUrl = resolveRegistryUrl(options.registryUrl);
                const result = await postJson(
                    registryUrl,
                    '/api/v1/revocations',
                    {
                        tokenId,
                        revokedBy: options.principalDid,
                        reason: 'MANUAL_REVOCATION',
                    },
                );

                printOutput(result, true);
            },
        );

    command.addCommand(createTokenDelegateCommand());

    return command;
};

export interface DelegateTokenOptions {
    parentToken: string;
    delegateeDid: string;
    capabilities: string;
    expiresIn: string;
    delegatorKeyFile?: string;
    revocationUrl?: string;
    json?: boolean;
}

// Extracted for unit testing; the commander action only forwards parameters.
export async function runTokenDelegate(
    options: DelegateTokenOptions,
): Promise<CapabilityToken> {
    const parentToken = await readJsonFile<CapabilityToken>(
        options.parentToken,
    );
    const delegatorKeyFile =
        options.delegatorKeyFile ?? defaultPrivateKeyPath(parentToken.issuedTo);
    const delegatorPrivateKey = await readPrivateKeyFile(delegatorKeyFile);

    const attenuatedCapabilities = JSON.parse(
        options.capabilities,
    ) as Capability[];
    if (!Array.isArray(attenuatedCapabilities)) {
        throw new Error(
            'Capabilities must be a JSON array of { action, scope } objects.',
        );
    }

    const expiresInSec = Number(options.expiresIn);
    if (!Number.isFinite(expiresInSec) || expiresInSec <= 0) {
        throw new Error('--expires-in must be a positive number of seconds.');
    }
    const expiresAt = new Date(
        Date.now() + expiresInSec * 1000,
    ).toISOString() as Timestamp;

    const child = delegateCapabilityToken({
        parentToken,
        delegatorPrivateKey,
        delegateeDid: options.delegateeDid as DID,
        attenuatedCapabilities,
        expiresAt,
        revocationUrl: options.revocationUrl ?? DEFAULT_REVOCATION_URL,
    });

    if (options.json) {
        printOutput(child, true);
    } else {
        printOutput(
            [
                'Delegated capability token issued',
                `  Token ID:        ${child.id}`,
                `  Parent token:    ${parentToken.id}`,
                `  Delegator DID:   ${parentToken.issuedTo}`,
                `  Delegatee DID:   ${child.issuedTo}`,
                `  Expires:         ${child.expiresAt}`,
                `  Chain depth:     ${child.delegationChain?.length ?? 0}`,
            ].join('\n'),
        );
    }

    return child;
}

export const createTokenDelegateCommand = (): Command => {
    return new Command('delegate')
        .description(
            'Create a child capability token by delegating from a parent token.',
        )
        .requiredOption(
            '--parent-token <path>',
            'JSON file containing the parent CapabilityToken.',
        )
        .requiredOption(
            '--delegatee-did <did>',
            'did:agent: of the agent receiving the delegated token.',
        )
        .requiredOption(
            '--capabilities <json>',
            'JSON array of attenuated Capability objects.',
        )
        .option(
            '--expires-in <seconds>',
            'Child token validity in seconds (capped at parent expiresAt).',
            '3600',
        )
        .option(
            '--delegator-key-file <path>',
            'Delegator (parent.issuedTo) private key file. Defaults to ~/.coivitas/keys/<delegator-did>.pem',
        )
        .option(
            '--revocation-url <url>',
            'HTTPS revocation URL template containing {id}.',
        )
        .option('--json', 'Print machine-readable JSON.', false)
        .action(async (options: DelegateTokenOptions) => {
            await runTokenDelegate(options);
        });
};
