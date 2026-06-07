/**
 * ap discover envelope — debug CLI command for DISCOVERY_REQUEST
 *
 * Purpose: send a DISCOVERY_REQUEST envelope to a given responder URL,
 * and display the request envelope JSON along with the received DISCOVERY_RESPONSE.
 *
 * Implementation notes (client perspective):
 * 1. Build a DISCOVERY_REQUEST with buildEnvelope (specVersion='0.3.0')
 * 2. HTTP POST to the responder URL
 * 3. Print the request envelope + response JSON
 *
 * Note: SENDER_PRIVATE_KEY and SENDER_DID must be supplied via the --sender-did / --sender-key
 * options or the AGENT_PRIVATE_KEY / AGENT_DID environment variables.
 *
 */

import { Command } from 'commander';

import { buildEnvelope } from '@coivitas/communication';
import type { NegotiationEnvelope } from '@coivitas/types';
import type { DID, Timestamp } from '@coivitas/types';
import { ProtocolError } from '@coivitas/types';

import { printOutput } from '../runtime.js';

// ── Public types ──────────────────────────────────────────────────────────────────

export interface DiscoverEnvelopeOptions {
    target: string;
    responderUrl: string;
    senderDid?: string;
    senderKey?: string;
}

export interface DiscoverEnvelopeResult {
    requestEnvelope: NegotiationEnvelope;
    response: unknown;
}

export interface DiscoverEnvelopeDeps {
    /** Injectable HTTP send function, for ease of unit testing */
    postEnvelope?: (
        url: string,
        envelope: NegotiationEnvelope,
    ) => Promise<unknown>;
}

/**
 * Execution body (extracted for ease of unit testing)
 *
 * 1. Resolve senderDid + senderKey (option > env var > throw ProtocolError)
 * 2. Build the DiscoveryRequestBody { targetDid, requestedAt }
 * 3. Call buildEnvelope (messageType='DISCOVERY_REQUEST', specVersion='0.3.0')
 * 4. HTTP POST to responderUrl (default endpoint /api/v1/envelopes)
 * 5. Return { requestEnvelope, response }
 */
export async function runDiscoverEnvelope(
    options: DiscoverEnvelopeOptions,
    deps: DiscoverEnvelopeDeps = {},
): Promise<DiscoverEnvelopeResult> {
    const { target, responderUrl } = options;

    // Resolve senderDid
    const senderDid = (options.senderDid ?? process.env.AGENT_DID) as
        | DID
        | undefined;
    if (!senderDid) {
        throw new ProtocolError(
            'INTERNAL_ERROR',
            'senderDid is required: pass --sender-did or set AGENT_DID.',
        );
    }

    // Resolve senderKey
    const senderKey = options.senderKey ?? process.env.AGENT_PRIVATE_KEY;
    if (!senderKey) {
        throw new ProtocolError(
            'INTERNAL_ERROR',
            'senderKey is required: pass --sender-key or set AGENT_PRIVATE_KEY.',
        );
    }

    // Build the request envelope
    const requestEnvelope = buildEnvelope({
        senderDid,
        senderPrivateKey: senderKey,
        recipientDid: target as DID,
        sessionId: null,
        messageType: 'DISCOVERY_REQUEST',
        specVersion: '0.3.0',
        body: {
            targetDid: target as DID,
            requestedAt: new Date().toISOString() as Timestamp,
        },
    });

    // Send
    let response: unknown;
    if (deps.postEnvelope) {
        response = await deps.postEnvelope(responderUrl, requestEnvelope);
    } else {
        const fetchResponse = await fetch(responderUrl, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(requestEnvelope),
        }).catch((err: unknown) => {
            throw new ProtocolError(
                'TRANSPORT_ERROR',
                `HTTP POST to ${responderUrl} failed: ${String(err)}`,
            );
        });

        if (!fetchResponse.ok) {
            throw new ProtocolError(
                'TRANSPORT_ERROR',
                `HTTP ${fetchResponse.status} from ${responderUrl}`,
            );
        }

        response = await fetchResponse.json();
    }

    return { requestEnvelope, response };
}

export const createDiscoverEnvelopeCommand = (): Command => {
    const command = new Command('envelope')
        .description(
            'Debug: send a DISCOVERY_REQUEST envelope to a responder URL.',
        )
        .requiredOption('--target <DID>', 'Target DID to discover.')
        .requiredOption('--responder-url <URL>', 'Responder HTTP endpoint URL.')
        .option('--sender-did <DID>', 'Sender DID (overrides AGENT_DID env).')
        .option(
            '--sender-key <HEX>',
            'Sender Ed25519 private key hex (overrides AGENT_PRIVATE_KEY env).',
        )
        .action(async (options: DiscoverEnvelopeOptions) => {
            const result = await runDiscoverEnvelope(options);
            printOutput(result, true);
        });

    return command;
};
