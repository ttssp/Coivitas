import { verifyAgentCard } from './agent-card.js';
import type {
    AgentCard,
    AgentCardCache,
    AgentIdentityDocument,
    DID,
    DiscoveryService,
    FederatedResolver,
} from '@coivitas/types';

// ── 04c: TTL cache ─────────────────────────────────────────────────────────────
const DEFAULT_TTL_MS = 5 * 60 * 1000; // 5 minutes

interface CacheEntry {
    card: AgentCard;
    expiresAt: number;
}

export class InMemoryAgentCardCache implements AgentCardCache {
    private readonly ttlMs: number;
    private readonly store = new Map<DID, CacheEntry>();

    public constructor(ttlMs: number = DEFAULT_TTL_MS) {
        this.ttlMs = ttlMs;
    }

    public get(did: DID): AgentCard | null {
        const entry = this.store.get(did);
        if (entry === undefined) return null;
        if (Date.now() > entry.expiresAt) {
            this.store.delete(did);
            return null;
        }
        return entry.card;
    }

    public set(did: DID, card: AgentCard, ttlMs?: number): void {
        this.store.set(did, { card, expiresAt: Date.now() + (ttlMs ?? this.ttlMs) });
    }

    public invalidate(did: DID): void {
        this.store.delete(did);
    }

    public clear(): void {
        this.store.clear();
    }
}

// ── 04a: internal discovery helper (not exported) ──────────────────────────────
// Requests {endpoint}/.well-known/agent.json, verifies the signature, and returns the AgentCard.
async function discoverAgent(
    endpoint: string,
    resolveDocument: (did: DID) => Promise<AgentIdentityDocument | null>,
    expectedDid?: DID,
): Promise<AgentCard> {
    const url = `${endpoint.replace(/\/$/, '')}/.well-known/agent.json`;
    let response: Response;
    try {
        response = await fetch(url);
    } catch (err) {
        throw new Error(`Discovery endpoint unreachable: ${url}: ${String(err)}`);
    }
    if (!response.ok) {
        throw new Error(`Discovery endpoint returned ${response.status}: ${url}`);
    }
    let card: AgentCard;
    try {
        card = (await response.json()) as AgentCard;
    } catch {
        throw new Error(`Invalid JSON from discovery endpoint: ${url}`);
    }
    const valid = await verifyAgentCard(card, resolveDocument, expectedDid);
    if (!valid) {
        throw new Error(`AgentCard signature verification failed for endpoint: ${url}`);
    }
    return card;
}

// ── 04b: DefaultDiscoveryService ──────────────────────────────────────────────

export interface DefaultDiscoveryServiceOptions {
    resolver: FederatedResolver;
    cache?: AgentCardCache;
    cacheTtlMs?: number;
}

export class DefaultDiscoveryService implements DiscoveryService {
    private readonly resolver: FederatedResolver;
    private readonly cache: AgentCardCache;

    public constructor(options: DefaultDiscoveryServiceOptions) {
        this.resolver = options.resolver;
        this.cache = options.cache ?? new InMemoryAgentCardCache(options.cacheTtlMs);
    }

    // DiscoveryService.discoverFromEndpoint — public signature is (endpoint, expectedDid?)
    public async discoverFromEndpoint(endpoint: string, expectedDid?: DID): Promise<AgentCard> {
        return discoverAgent(endpoint, (d) => this.resolver.resolve(d), expectedDid);
    }

    // DiscoveryService.discover — resolves serviceEndpoints via the DID and tries each one in turn
    public async discover(did: DID): Promise<AgentCard> {
        const cached = this.cache.get(did);
        if (cached !== null) return cached;

        const doc = await this.resolver.resolve(did);
        if (doc === null) throw new Error(`Identity not found: ${did}`);

        const endpoints = doc.serviceEndpoints ?? [];
        if (endpoints.length === 0) throw new Error(`No service endpoints for: ${did}`);

        const errors: string[] = [];
        for (const ep of endpoints) {
            try {
                // Pass expectedDid=did to enforce card.did === the requested DID (prevents cross-identity endpoint hijacking)
                const card = await discoverAgent(ep.url, (d) => this.resolver.resolve(d), did);
                this.cache.set(did, card);
                return card;
            } catch (err) {
                errors.push(`${ep.url}: ${String(err)}`);
            }
        }
        throw new Error(`All endpoints failed for ${did}: ${errors.join('; ')}`);
    }

    public invalidateCache(did: DID): void {
        this.cache.invalidate(did);
    }
}
