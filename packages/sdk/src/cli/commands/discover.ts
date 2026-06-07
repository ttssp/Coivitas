import { Command } from 'commander';

import { verifyAgentCard } from '@coivitas/communication';
import { resolveAgentDID } from '@coivitas/identity';
import type { AgentCard, DID } from '@coivitas/types';

import { printOutput, resolveRegistryUrl } from '../runtime.js';
import { createDiscoverEnvelopeCommand } from './discover-envelope.js';

// Remote AgentCard fetch -- extracted so unit tests can inject via a fetch mock.
export async function fetchAgentCard(endpoint: string): Promise<AgentCard> {
    const url = `${endpoint.replace(/\/$/, '')}/.well-known/agent.json`;
    let response: Response;
    try {
        response = await fetch(url);
    } catch (cause) {
        throw new Error(
            `Discovery endpoint unreachable: ${url}: ${String(cause)}`,
        );
    }

    if (!response.ok) {
        throw new Error(
            `Discovery endpoint returned HTTP ${response.status}: ${url}`,
        );
    }

    try {
        return (await response.json()) as AgentCard;
    } catch {
        throw new Error(`Invalid JSON from discovery endpoint: ${url}`);
    }
}

// Pretty-print the AgentCard fields
function formatAgentCard(card: AgentCard, signatureValid: boolean): string {
    const lines: string[] = [
        'AgentCard',
        `  DID:               ${card.did}`,
        `  Spec Version:      ${card.specVersion}`,
        `  Document Version:  ${card.documentVersion}`,
        `  Public Key:        ${card.publicKey}`,
        `  Updated At:        ${card.updatedAt}`,
        `  Signature Valid:   ${signatureValid ? 'yes' : 'NO'}`,
    ];

    if (card.displayName !== undefined) {
        lines.push(`  Display Name:      ${card.displayName}`);
    }
    if (card.description !== undefined) {
        lines.push(`  Description:       ${card.description}`);
    }

    if (card.serviceEndpoints.length > 0) {
        lines.push('  Service Endpoints:');
        for (const ep of card.serviceEndpoints) {
            lines.push(`    - ${ep.id} (${ep.type ?? 'unknown'}): ${ep.url}`);
        }
    } else {
        lines.push('  Service Endpoints: (none)');
    }

    if (card.capabilitiesDeclared.length > 0) {
        lines.push('  Capabilities:');
        for (const cap of card.capabilitiesDeclared) {
            lines.push(`    - ${cap}`);
        }
    } else {
        lines.push('  Capabilities:       (none)');
    }

    return lines.join('\n');
}

export const createDiscoverCommand = (): Command => {
    const command = new Command('discover')
        .description(
            'Fetch and verify an AgentCard from a remote discovery endpoint.',
        )
        .argument(
            '<endpoint>',
            'Base URL serving /.well-known/agent.json (e.g. https://agent.example.com).',
        )
        .option(
            '--registry-url <url>',
            'Identity registry URL used to resolve authoritative documents. Defaults to $IDENTITY_REGISTRY_URL.',
        )
        .option(
            '--expected-did <did>',
            'Optional DID assertion — fails if the card.did differs.',
        )
        .option('--json', 'Print machine-readable JSON.', false)
        .action(
            async (
                endpoint: string,
                options: {
                    registryUrl?: string;
                    expectedDid?: string;
                    json?: boolean;
                },
            ) => {
                const registryUrl = resolveRegistryUrl(options.registryUrl);
                const card = await fetchAgentCard(endpoint);

                const signatureValid = await verifyAgentCard(
                    card,
                    async (did) => await resolveAgentDID(did, registryUrl),
                    options.expectedDid as DID | undefined,
                );

                if (options.json) {
                    printOutput(
                        {
                            endpoint,
                            card,
                            signatureValid,
                        },
                        true,
                    );
                } else {
                    printOutput(formatAgentCard(card, signatureValid));
                }

                if (!signatureValid) {
                    process.exitCode = 1;
                }
            },
        );

    command.addCommand(createDiscoverEnvelopeCommand());

    return command;
};
