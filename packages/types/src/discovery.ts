// Discovery-layer type definitions: AgentCard / event and cache interfaces.
// The SSOT for AgentCard / AgentCardSignedPayload / DocumentUpdatedEvent is in identity.ts;
// they are re-exported here to keep the import path backward-compatible.

import type { DID } from './base.js';
import type { AgentCard, AgentIdentityDocument } from './identity.js';

// Re-exported from identity.ts (the single source of truth is identity.ts).
export type {
    AgentCard,
    AgentCardSignedPayload,
    DocumentUpdatedEvent,
} from './identity.js';

// AgentCard client cache interface (injected into DiscoveryService).
export interface AgentCardCache {
    get(did: DID): AgentCard | null;
    set(did: DID, card: AgentCard, ttlMs?: number): void;
    invalidate(did: DID): void;
    clear(): void;
}

// DiscoveryService dependency interface — the unified entry point for discoverByDid / discoverFromEndpoint.
// The DID discovery path must verify card.did === requested did (prevents cross-identity endpoint theft).
export interface DiscoveryService {
    discover(did: DID): Promise<AgentCard>;
    discoverFromEndpoint(
        endpoint: string,
        expectedDid?: DID,
    ): Promise<AgentCard>;
    invalidateCache(did: DID): void;
}

// AgentCard build parameters (used by the buildAgentCard implementation).
export interface BuildAgentCardParams {
    doc: AgentIdentityDocument;
    privateKey: string; // Ed25519 agent private key (hex/base64url, normalized by L1)
    displayName?: string;
    description?: string;
}

// AgentCard verification parameters.
// - expectedDid: passed in by discoverByDid, used for binding validation
// - resolveDocument: fetches the authoritative document from IdentityRegistry (required for cross-validation)
export interface VerifyAgentCardParams {
    card: AgentCard;
    resolveDocument: (did: DID) => Promise<AgentIdentityDocument | null>;
    expectedDid?: DID;
}
