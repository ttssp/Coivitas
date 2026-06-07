import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';

import { Command } from 'commander';

import { canonicalize, generateKeyPair, sign } from '@coivitas/crypto';
import {
    completeKeyRotation,
    createAgentIdentity,
    IdentityRegistry,
    initiateKeyRotation,
    resolveAgentDID,
} from '@coivitas/identity';
import type {
    AgentIdentityDocument,
    DID,
    Signature,
    Timestamp,
} from '@coivitas/types';

import {
    createCliPool,
    defaultPrivateKeyPath,
    postJson,
    printOutput,
    readPrivateKeyFile,
    resolveRegistryUrl,
    stagePrivateKeyFile,
    writePrivateKeyFile,
} from '../runtime.js';

export const createIdentityCommand = (): Command => {
    const command = new Command('identity').description(
        'Create and resolve agent identities.',
    );

    command
        .command('create')
        .description('Create an agent identity for a principal DID.')
        .requiredOption('--name <name>', 'Human-friendly agent name.')
        .requiredOption(
            '--principal-did <did>',
            'Principal DID that will own the new agent identity.',
        )
        .option(
            '--principal-key-file <path>',
            'Principal private key file. Defaults to ~/.coivitas/keys/<principal-did>.pem',
        )
        .option(
            '--registry-url <url>',
            'Identity registry URL. Defaults to $IDENTITY_REGISTRY_URL.',
        )
        .action(
            async (options: {
                name: string;
                principalDid: string;
                principalKeyFile?: string;
                registryUrl?: string;
            }) => {
                const registryUrl = resolveRegistryUrl(options.registryUrl);
                const principalKey = await readPrivateKeyFile(
                    options.principalKeyFile ??
                        defaultPrivateKeyPath(options.principalDid),
                );
                const identity = createAgentIdentity({
                    principalDid: options.principalDid as never,
                    principalPrivateKey: principalKey,
                });

                await postJson<{ did: string }>(
                    registryUrl,
                    '/api/v1/identities',
                    identity.document,
                );

                const keyFile = await writePrivateKeyFile(
                    identity.document.id,
                    identity.privateKey,
                );

                printOutput(
                    [
                        'Agent identity created',
                        `  DID:      ${identity.document.id}`,
                        `  Name:     ${options.name}`,
                        `  Key file: ${keyFile}`,
                    ].join('\n'),
                );
            },
        );

    command.addCommand(createIdentityRotateCommand());

    command
        .command('resolve')
        .description('Resolve and print an existing DID document.')
        .argument('<did>', 'Agent DID to resolve.')
        .option(
            '--registry-url <url>',
            'Identity registry URL. Defaults to $IDENTITY_REGISTRY_URL.',
        )
        .option('--json', 'Print the full JSON document.', false)
        .action(
            async (
                did: string,
                options: { registryUrl?: string; json?: boolean },
            ) => {
                const document = await resolveAgentDID(
                    did as never,
                    resolveRegistryUrl(options.registryUrl),
                );

                if (!document) {
                    throw new Error(`Identity ${did} was not found.`);
                }

                if (options.json) {
                    printOutput(document, true);
                    return;
                }

                printOutput(
                    [
                        'Agent Identity Document',
                        `  DID:        ${document.id}`,
                        `  Principal:  ${document.principalDid}`,
                        `  Public Key: ${document.publicKey}`,
                        `  Created:    ${document.createdAt}`,
                    ].join('\n'),
                );
            },
        );

    return command;
};

// Default confirmation prompt -- extracted so unit tests can inject their own.
async function defaultConfirm(prompt: string): Promise<boolean> {
    const rl = createInterface({ input: stdin, output: stdout });
    try {
        const answer = (await rl.question(prompt)).trim().toLowerCase();
        return answer === 'y' || answer === 'yes';
    } finally {
        rl.close();
    }
}

// Principal pre-signature: sign the rotation payload with the principal's private key.
function buildPrincipalApproval(
    payload: {
        agentDid: DID;
        newPublicKey: string;
        oldPublicKey: string;
        rotatedAt: Timestamp;
    },
    principalPrivateKey: string,
): Signature {
    const bytes = new TextEncoder().encode(
        canonicalize({
            agentDid: payload.agentDid,
            newPublicKey: payload.newPublicKey,
            oldPublicKey: payload.oldPublicKey,
            rotatedAt: payload.rotatedAt,
        }),
    );
    return sign(bytes, principalPrivateKey) as Signature;
}

export interface RotateIdentityOptions {
    did: string;
    currentKeyFile?: string;
    principalKeyFile?: string;
    yes?: boolean;
    json?: boolean;
}

export interface RotateIdentityDeps {
    confirm?: (prompt: string) => Promise<boolean>;
    registryFactory?: (
        pool: ReturnType<typeof createCliPool>,
    ) => IdentityRegistry;
}

// The actual execution body -- extracted so unit tests can call it directly, bypassing commander parsing.
export async function runIdentityRotate(
    options: RotateIdentityOptions,
    deps: RotateIdentityDeps = {},
): Promise<void> {
    const confirm = deps.confirm ?? defaultConfirm;
    const pool = createCliPool();

    try {
        const registry = deps.registryFactory
            ? deps.registryFactory(pool)
            : new IdentityRegistry(pool);

        const currentDoc = await registry.query(options.did as DID);
        if (!currentDoc) {
            throw new Error(`Identity ${options.did} was not found.`);
        }
        const currentVersion = currentDoc.version ?? 1;

        const currentPrivateKey = await readPrivateKeyFile(
            options.currentKeyFile ?? defaultPrivateKeyPath(options.did),
        );
        if (!options.principalKeyFile) {
            throw new Error(
                'Principal key file is required (--principal-key-file). Key rotation must be authorized by the principal.',
            );
        }
        const principalKey = await readPrivateKeyFile(options.principalKeyFile);

        const newKeyPair = generateKeyPair();
        const rotatedAt = new Date().toISOString() as Timestamp;
        const principalApproval = buildPrincipalApproval(
            {
                agentDid: currentDoc.id,
                newPublicKey: newKeyPair.publicKey,
                oldPublicKey: currentDoc.publicKey,
                rotatedAt,
            },
            principalKey,
        );

        const rotatingDoc = initiateKeyRotation({
            currentDoc,
            currentPrivateKey,
            newKeyPair,
            principalApproval,
            rotatedAt,
        });

        const summary = {
            did: currentDoc.id,
            previousPublicKey: currentDoc.publicKey,
            newPublicKey: newKeyPair.publicKey,
            previousVersion: currentVersion,
            newVersion: rotatingDoc.version ?? currentVersion + 1,
            rotatedAt,
        };

        if (!options.yes) {
            const confirmed = await confirm(
                [
                    'About to rotate identity:',
                    `  DID:           ${summary.did}`,
                    `  Old publicKey: ${summary.previousPublicKey}`,
                    `  New publicKey: ${summary.newPublicKey}`,
                    `  Old version:   ${summary.previousVersion}`,
                    `  New version:   ${summary.newVersion}`,
                    'Proceed? [y/N]: ',
                ].join('\n'),
            );
            if (!confirmed) {
                throw new Error('Key rotation cancelled by operator.');
            }
        }

        // Ordering constraints:
        // 1) completeKeyRotation first strips _rotatingState, yielding a clean final document
        // -- the intermediate document carrying _rotatingState must not be persisted, otherwise the next
        // query() load still has that field in the JSONB, and initiateKeyRotation's precondition check
        // would refuse to rotate again.
        // Registry.update recognizes the "isKeyRotation" path on its own via the publicKey change +
        // rotationProof, without relying on _rotatingState.
        // 2) Write the new private key to a .pending file first -- if the disk is full / not writable, the
        // registry has not yet published the new public key, there is no local side effect, and the operation can be safely retried.
        // 3) Only commit the private key (atomic rename) after registry.update succeeds.
        // This guarantees the invariant: "once the registry publishes the new public key, the local side definitely holds the matching private key".
        const finalDoc: AgentIdentityDocument =
            completeKeyRotation(rotatingDoc);
        const stagedKey = await stagePrivateKeyFile(
            finalDoc.id,
            newKeyPair.privateKey,
        );

        let newKeyPath: string;
        try {
            await registry.update(finalDoc, currentVersion);
            newKeyPath = await stagedKey.commit();
        } catch (err) {
            await stagedKey.rollback();
            throw err;
        }

        const result = {
            ...summary,
            keyFile: newKeyPath,
            documentVersion: finalDoc.version,
            rotationProof: finalDoc.rotationProof,
        };

        if (options.json) {
            printOutput(result, true);
        } else {
            printOutput(
                [
                    'Key rotation complete',
                    `  DID:           ${result.did}`,
                    `  New version:   ${result.newVersion}`,
                    `  New publicKey: ${result.newPublicKey}`,
                    `  Key file:      ${result.keyFile}`,
                ].join('\n'),
            );
        }
    } finally {
        await pool.end();
    }
}

export const createIdentityRotateCommand = (): Command => {
    return new Command('rotate')
        .description('Rotate an agent identity key (interactive).')
        .requiredOption('--did <did>', 'Agent DID to rotate.')
        .option(
            '--current-key-file <path>',
            'Current agent private key file. Defaults to ~/.coivitas/keys/<did>.pem',
        )
        .requiredOption(
            '--principal-key-file <path>',
            'Principal private key file used to sign rotation approval.',
        )
        .option('--yes', 'Skip the interactive confirmation prompt.', false)
        .option('--json', 'Print machine-readable JSON.', false)
        .action(async (options: RotateIdentityOptions) => {
            await runIdentityRotate(options);
        });
};
