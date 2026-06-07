import type { AgentIdentityDocument, DID } from '@coivitas/types';
import { ProtocolError } from '@coivitas/types';

export async function resolveAgentDID(
    did: DID,
    registryUrl: string,
    timeoutMs = 10_000,
): Promise<AgentIdentityDocument | null> {
    const url = new URL(
        `/api/v1/identities/${encodeURIComponent(did)}`,
        registryUrl,
    );
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
        const response = await fetch(url, {
            method: 'GET',
            signal: controller.signal,
        });

        if (response.status === 404) {
            return null;
        }

        if (!response.ok) {
            throw new ProtocolError(
                'INTERNAL_ERROR',
                `Failed to resolve DID from ${url.toString()}: HTTP ${response.status}`,
            );
        }

        return (await response.json()) as AgentIdentityDocument;
    } catch (error) {
        if (error instanceof ProtocolError) {
            throw error;
        }

        throw new ProtocolError(
            'INTERNAL_ERROR',
            `Failed to resolve DID from ${url.toString()}`,
        );
    } finally {
        clearTimeout(timer);
    }
}
