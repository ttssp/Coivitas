import { describe, expect, it } from 'vitest';

import type {
    ActionRecord,
    AgentIdentityDocument,
    CapabilityToken,
    NegotiationEnvelope,
    PrincipalIdentity,
} from '../../types/src/index.js';
import { validateAgainstSchema } from '../../types/src/index.js';

import scenario1 from '../../../examples/scenarios/scenario-1-data.json';
import scenario2 from '../../../examples/scenarios/scenario-2-data.json';
import scenario3 from '../../../examples/scenarios/scenario-3-data.json';

interface ScenarioFixture {
    scenarioId: string;
    principals: PrincipalIdentity[];
    agentDocuments: AgentIdentityDocument[];
    capabilityTokens?: CapabilityToken[];
    envelopes: NegotiationEnvelope[];
    actionRecords?: ActionRecord[];
    schemaStatus?: {
        phase1CompatibleArtifacts: string[];
        phase2PendingArtifacts: string[];
    };
    expectedOutcomes: Record<string, unknown>;
    requestedCapabilities?: Array<Record<string, unknown>>;
}

const assertValidCollection = <T>(
    items: T[],
    schemaId: Parameters<typeof validateAgainstSchema>[1],
) => {
    for (const item of items) {
        expect(validateAgainstSchema(item, schemaId).valid).toBe(true);
    }
};

describe('scenario fixtures', () => {
    it('keeps scenario 1 fully aligned with current L0 schemas', () => {
        const fixture = scenario1 as ScenarioFixture;

        assertValidCollection(fixture.principals, 'principalIdentity');
        assertValidCollection(fixture.agentDocuments, 'agentIdentityDocument');
        assertValidCollection(
            fixture.capabilityTokens ?? [],
            'capabilityToken',
        );
        assertValidCollection(fixture.envelopes, 'negotiationEnvelope');
        assertValidCollection(fixture.actionRecords ?? [], 'actionRecord');

        expect(fixture.expectedOutcomes.finalOrderStatus).toBe('confirmed');
    });

    it('keeps scenario 2 publish artifacts schema-valid after vocabulary alignment', () => {
        const fixture = scenario2 as ScenarioFixture;

        assertValidCollection(fixture.principals, 'principalIdentity');
        assertValidCollection(fixture.agentDocuments, 'agentIdentityDocument');
        assertValidCollection(
            fixture.capabilityTokens ?? [],
            'capabilityToken',
        );
        assertValidCollection(fixture.envelopes, 'negotiationEnvelope');
        assertValidCollection(fixture.actionRecords ?? [], 'actionRecord');

        expect(fixture.expectedOutcomes.publishStatus).toBe('published');
    });

    it('documents scenario 3 as a structured versioned boundary case', () => {
        const fixture = scenario3 as ScenarioFixture;

        assertValidCollection(fixture.principals, 'principalIdentity');
        assertValidCollection(fixture.agentDocuments, 'agentIdentityDocument');
        assertValidCollection(fixture.envelopes, 'negotiationEnvelope');

        expect(fixture.schemaStatus?.phase2PendingArtifacts).toContain(
            'requestedCapabilities',
        );
        expect(fixture.requestedCapabilities?.[0]?.action).toBe('QUERY');
        expect(fixture.expectedOutcomes.supportedToday).toBe(false);
    });
});
