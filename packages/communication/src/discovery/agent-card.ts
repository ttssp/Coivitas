import { canonicalize, sign, verify } from '@coivitas/crypto';
import type {
    AgentCard,
    AgentIdentityDocument,
    BuildAgentCardParams,
    DID,
    Signature,
    VerifyAgentCardParams,
} from '@coivitas/types';

export type { BuildAgentCardParams, VerifyAgentCardParams };

export function buildAgentCard(params: BuildAgentCardParams): AgentCard {
    const { doc, privateKey, displayName, description } = params;

    // Build the signing payload per the discovery spec (excluding optional undefined fields)
    const payload: Record<string, unknown> = {
        did: doc.id,
        specVersion: doc.specVersion,
        serviceEndpoints: doc.serviceEndpoints ?? [],
        capabilitiesDeclared: doc.capabilities ?? [],
        publicKey: doc.publicKey,
        documentVersion: doc.version ?? 1,
        updatedAt: doc.updatedAt,
    };

    // Add optional fields only when present (canonicalize would include undefined keys, causing signature mismatch)
    if (displayName !== undefined) payload['displayName'] = displayName;
    if (description !== undefined) payload['description'] = description;

    const canonical = canonicalize(payload);
    const bytes = new TextEncoder().encode(canonical);
    const signature = sign(bytes, privateKey) as unknown as Signature;

    const card: AgentCard = {
        did: doc.id,
        specVersion: doc.specVersion,
        serviceEndpoints: doc.serviceEndpoints ?? [],
        capabilitiesDeclared: doc.capabilities ?? [],
        publicKey: doc.publicKey,
        documentVersion: doc.version ?? 1,
        updatedAt: doc.updatedAt,
        signature,
    };

    if (displayName !== undefined) card.displayName = displayName;
    if (description !== undefined) card.description = description;

    return card;
}

export async function verifyAgentCard(
    card: AgentCard,
    resolveDocument: (did: DID) => Promise<AgentIdentityDocument | null>,
    expectedDid?: DID,
): Promise<boolean> {
    // Step 0: DID binding check (mandatory in the discoverByDid scenario)
    if (expectedDid !== undefined && card.did !== expectedDid) return false;

    // Step 1: basic format validation
    if (!/^did:agent:[a-f0-9]{40}$/.test(card.did)) return false;
    if (!/^[a-f0-9]{128}$/.test(card.signature)) return false;

    // Steps 2-3: reconstruct the signing payload + verify signature
    const { signature, ...rest } = card;
    const payload: Record<string, unknown> = { ...rest };
    // Delete undefined optional fields (consistent with buildAgentCard)
    if (payload['displayName'] === undefined) delete payload['displayName'];
    if (payload['description'] === undefined) delete payload['description'];

    try {
        const canonical = canonicalize(payload);
        const bytes = new TextEncoder().encode(canonical);
        if (!verify(bytes, signature, card.publicKey)) return false;
    } catch {
        return false;
    }

    // Step 4: fetch the authoritative document from the IdentityRegistry
    const doc = await resolveDocument(card.did);
    if (doc === null) return false;

    // Step 5: consistency check of all derived fields
    if (card.publicKey !== doc.publicKey) return false;
    if (card.did !== doc.id) return false;
    if (card.documentVersion !== (doc.version ?? 1)) return false;
    if (card.specVersion !== doc.specVersion) return false;

    // Step 6: endpoints and capabilities must be a subset of the authoritative document (no superset)
    const docEndpoints = new Set((doc.serviceEndpoints ?? []).map((e) => e.id));
    for (const ep of card.serviceEndpoints) {
        if (!docEndpoints.has(ep.id)) return false;
    }

    const docCaps = new Set(doc.capabilities ?? []);
    for (const cap of card.capabilitiesDeclared) {
        if (!docCaps.has(cap)) return false;
    }

    return true;
}
