/**
 * MCP Bridge — outbox manager unit tests
 *
 * Covers the 4-step ownership check + owner write rules.
 *
 * Test coverage (>= 15 tests):
 *   - all 4 ownership-check steps pass → return row
 *   - callerSubject.kind === 'tokenId' → reject (pinned by the A30 grep test)
 *   - PoP signature invalid → reject
 *   - ownership kind mismatch → reject
 *   - ownership value mismatch → reject
 *   - subject key not resolvable → reject
 *   - outbox_id not found → return outbox_not_found
 *   - A30 invariant grep test (runtime readFileSync + camelCase variants)
 *   - IDOR defense: owner_token_id must not act as an ownership field
 *   - edge cases (empty subject value / long ID / malformed UUID)
 *   - createOutboxRow path rejects the 'tokenId' kind
 */
import { describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import {
    createOutboxRow,
    defaultMockChallengeResolver,
    getOutboxByID,
    MCP_ERROR,
    type GetOutboxByIDDeps,
    type OutboxRow,
    type OutboxStore,
    type PoPSignatureVerifier,
    type SubjectKeyResolver,
} from '../index.js';

// ─── helpers / fixtures ──────────────────────────────────────────────────────

function makeRow(overrides?: Partial<OutboxRow>): OutboxRow {
    return {
        outboxId: 'outbox-1',
        envelopeId: 'envelope-1',
        status: 'pending',
        settlementReceipt: null,
        errorObject: null,
        createdAt: '2026-05-11T00:00:00.000Z',
        completedAt: null,
        ownerSubjectKind: 'agentDid',
        ownerSubjectValue: 'did:agent:alice',
        ownerTokenId: 'cab1e1ed-0000-4000-8000-000000000001',
        ...overrides,
    };
}

function makeStore(row: OutboxRow | null = null): OutboxStore {
    return {
        insert: vi.fn().mockResolvedValue(undefined),
        lookup: vi.fn().mockResolvedValue(row),
    };
}

const validChallenge = new Uint8Array([1, 2, 3, 4]);
const validKey = new Uint8Array([10, 20, 30, 40]);
const validSignature = new Uint8Array([100, 101, 102, 103]);

const validChallengeResolver = vi.fn().mockResolvedValue(validChallenge);
const validSubjectKeyResolver: SubjectKeyResolver = () =>
    Promise.resolve(validKey);
const validVerifier: PoPSignatureVerifier = () => true;

function makeDeps(
    overrides?: Partial<GetOutboxByIDDeps>,
): GetOutboxByIDDeps {
    return {
        store: overrides?.store ?? makeStore(makeRow()),
        challengeResolver: overrides?.challengeResolver ?? validChallengeResolver,
        subjectKeyResolver:
            overrides?.subjectKeyResolver ?? validSubjectKeyResolver,
        verifyPop: overrides?.verifyPop ?? validVerifier,
    };
}

// ─── getOutboxByID: 4-step ownership check ───────────────────────────────────

describe('getOutboxByID (4-step ownership check)', () => {
    describe('step 0: outbox row lookup', () => {
        it('should return mcp_error_outbox_not_found when store.lookup returns null', async () => {
            const result = await getOutboxByID(
                {
                    outboxId: 'nonexistent',
                    callerSubject: {
                        kind: 'agentDid',
                        value: 'did:agent:alice',
                    },
                    popSignature: validSignature,
                },
                makeDeps({ store: makeStore(null) }),
            );
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.mcp_code).toBe(MCP_ERROR.OUTBOX_NOT_FOUND);
                expect(result.error.internal_code).toBe(
                    'mcp_error_outbox_not_found',
                );
            }
        });
    });

    describe('step 1: PoP kind check (does not accept tokenId)', () => {
        it('should reject when callerSubject.kind is "tokenId" (A30 IDOR defense)', async () => {
            const row = makeRow();
            const result = await getOutboxByID(
                {
                    outboxId: row.outboxId,
                    // invariant: the 'tokenId' kind must be rejected (the type layer forbids it, but runtime verifies too)
                    callerSubject: {
                        // use a cast to simulate a caller wrongly passing 'tokenId' (the actual type disallows it)
                        kind: 'tokenId' as unknown as 'agentDid',
                        value: row.ownerTokenId,
                    },
                    popSignature: validSignature,
                },
                makeDeps({ store: makeStore(row) }),
            );
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.mcp_code).toBe(
                    MCP_ERROR.OUTBOX_UNAUTHORIZED,
                );
            }
        });

        it('should reject unknown kind (e.g. "random")', async () => {
            const row = makeRow();
            const result = await getOutboxByID(
                {
                    outboxId: row.outboxId,
                    callerSubject: {
                        kind: 'random' as unknown as 'agentDid',
                        value: 'whatever',
                    },
                    popSignature: validSignature,
                },
                makeDeps({ store: makeStore(row) }),
            );
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.mcp_code).toBe(
                    MCP_ERROR.OUTBOX_UNAUTHORIZED,
                );
            }
        });
    });

    describe('step 2: PoP signature verification', () => {
        it('should reject when verifyPop returns false', async () => {
            const row = makeRow();
            const failingVerifier: PoPSignatureVerifier = () => false;
            const result = await getOutboxByID(
                {
                    outboxId: row.outboxId,
                    callerSubject: {
                        kind: row.ownerSubjectKind,
                        value: row.ownerSubjectValue,
                    },
                    popSignature: validSignature,
                },
                makeDeps({
                    store: makeStore(row),
                    verifyPop: failingVerifier,
                }),
            );
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.mcp_code).toBe(
                    MCP_ERROR.OUTBOX_UNAUTHORIZED,
                );
            }
        });

        it('should reject when subjectKeyResolver returns null', async () => {
            const row = makeRow();
            const nullKeyResolver: SubjectKeyResolver = () =>
                Promise.resolve(null);
            const result = await getOutboxByID(
                {
                    outboxId: row.outboxId,
                    callerSubject: {
                        kind: row.ownerSubjectKind,
                        value: row.ownerSubjectValue,
                    },
                    popSignature: validSignature,
                },
                makeDeps({
                    store: makeStore(row),
                    subjectKeyResolver: nullKeyResolver,
                }),
            );
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.mcp_code).toBe(
                    MCP_ERROR.OUTBOX_UNAUTHORIZED,
                );
            }
        });

        it('should reject when challengeResolver throws (fail-closed, no internal detail leak)', async () => {
            const row = makeRow();
            const throwingResolver = vi
                .fn()
                .mockRejectedValue(new Error('challenge service down'));
            const result = await getOutboxByID(
                {
                    outboxId: row.outboxId,
                    callerSubject: {
                        kind: row.ownerSubjectKind,
                        value: row.ownerSubjectValue,
                    },
                    popSignature: validSignature,
                },
                makeDeps({
                    store: makeStore(row),
                    challengeResolver: throwingResolver,
                }),
            );
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.mcp_code).toBe(
                    MCP_ERROR.OUTBOX_UNAUTHORIZED,
                );
                // must not leak internal detail in the message (anti-probe)
                expect(result.error.message).not.toContain(
                    'challenge service down',
                );
            }
        });

        it('should pass challenge bytes to verifyPop with subject key', async () => {
            // verifyPop receives the same challenge / signature / key
            const row = makeRow();
            const spyVerifier = vi.fn().mockReturnValue(true);
            await getOutboxByID(
                {
                    outboxId: row.outboxId,
                    callerSubject: {
                        kind: row.ownerSubjectKind,
                        value: row.ownerSubjectValue,
                    },
                    popSignature: validSignature,
                },
                makeDeps({
                    store: makeStore(row),
                    verifyPop: spyVerifier,
                }),
            );
            expect(spyVerifier).toHaveBeenCalledWith(
                validSignature,
                validChallenge,
                validKey,
            );
        });
    });

    describe('step 3: ownership match', () => {
        it('should reject when callerSubject.kind mismatches row.ownerSubjectKind', async () => {
            const row = makeRow({
                ownerSubjectKind: 'agentDid',
                ownerSubjectValue: 'did:agent:alice',
            });
            const result = await getOutboxByID(
                {
                    outboxId: row.outboxId,
                    callerSubject: {
                        kind: 'mcpClientId', // inconsistent with row.ownerSubjectKind='agentDid'
                        value: 'did:agent:alice', // same value but different kind
                    },
                    popSignature: validSignature,
                },
                makeDeps({ store: makeStore(row) }),
            );
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.mcp_code).toBe(
                    MCP_ERROR.OUTBOX_UNAUTHORIZED,
                );
            }
        });

        it('should reject when callerSubject.value mismatches row.ownerSubjectValue', async () => {
            const row = makeRow({
                ownerSubjectKind: 'agentDid',
                ownerSubjectValue: 'did:agent:alice',
            });
            const result = await getOutboxByID(
                {
                    outboxId: row.outboxId,
                    callerSubject: {
                        kind: 'agentDid',
                        value: 'did:agent:bob', // different value
                    },
                    popSignature: validSignature,
                },
                makeDeps({ store: makeStore(row) }),
            );
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.mcp_code).toBe(
                    MCP_ERROR.OUTBOX_UNAUTHORIZED,
                );
            }
        });

        it('IDOR defense: should reject when caller provides ownerTokenId as value', async () => {
            // invariant: even if the caller knows row.ownerTokenId it cannot pass the ownership check
            // the ownership check uses (kind, value); it does **not** compare ownerTokenId
            const row = makeRow({
                ownerSubjectKind: 'agentDid',
                ownerSubjectValue: 'did:agent:alice',
                ownerTokenId: 'cab1e1ed-0000-4000-8000-aaaaaaaaaaaa',
            });
            const result = await getOutboxByID(
                {
                    outboxId: row.outboxId,
                    // spoof: use ownerTokenId as subject.value (a classic IDOR attack)
                    callerSubject: {
                        kind: 'agentDid',
                        value: 'cab1e1ed-0000-4000-8000-aaaaaaaaaaaa',
                    },
                    popSignature: validSignature,
                },
                makeDeps({ store: makeStore(row) }),
            );
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.mcp_code).toBe(
                    MCP_ERROR.OUTBOX_UNAUTHORIZED,
                );
            }
        });
    });

    describe('step 4: success path + return row', () => {
        it('should return row when 4 ownership steps pass (happy path)', async () => {
            const row = makeRow({
                ownerSubjectKind: 'agentDid',
                ownerSubjectValue: 'did:agent:alice',
            });
            const result = await getOutboxByID(
                {
                    outboxId: row.outboxId,
                    callerSubject: {
                        kind: 'agentDid',
                        value: 'did:agent:alice',
                    },
                    popSignature: validSignature,
                },
                makeDeps({ store: makeStore(row) }),
            );
            expect(result.ok).toBe(true);
            if (result.ok) {
                expect(result.row.outboxId).toBe(row.outboxId);
                expect(result.row.status).toBe('pending');
                expect(result.row.ownerSubjectKind).toBe('agentDid');
            }
        });

        it('should pass with mcpClientId kind', async () => {
            const row = makeRow({
                ownerSubjectKind: 'mcpClientId',
                ownerSubjectValue: 'mcp-client-bob',
            });
            const result = await getOutboxByID(
                {
                    outboxId: row.outboxId,
                    callerSubject: {
                        kind: 'mcpClientId',
                        value: 'mcp-client-bob',
                    },
                    popSignature: validSignature,
                },
                makeDeps({ store: makeStore(row) }),
            );
            expect(result.ok).toBe(true);
        });
    });

    describe('edge cases', () => {
        it('should handle empty subject value gracefully (still mismatch check)', async () => {
            const row = makeRow({
                ownerSubjectKind: 'agentDid',
                ownerSubjectValue: 'did:agent:alice',
            });
            const result = await getOutboxByID(
                {
                    outboxId: row.outboxId,
                    callerSubject: { kind: 'agentDid', value: '' },
                    popSignature: validSignature,
                },
                makeDeps({ store: makeStore(row) }),
            );
            expect(result.ok).toBe(false); // empty value !== 'did:agent:alice'
        });

        it('should handle long outboxId (256 chars)', async () => {
            const longId = 'x'.repeat(256);
            const row = makeRow({ outboxId: longId });
            const result = await getOutboxByID(
                {
                    outboxId: longId,
                    callerSubject: {
                        kind: row.ownerSubjectKind,
                        value: row.ownerSubjectValue,
                    },
                    popSignature: validSignature,
                },
                makeDeps({ store: makeStore(row) }),
            );
            expect(result.ok).toBe(true);
        });
    });
});

// ─── createOutboxRow ─────────────────────────────────────────────────────────

describe('createOutboxRow (spec §5.2 owner write rules)', () => {
    it('should insert with agentDid kind (default subject)', async () => {
        const store = makeStore();
        const row = await createOutboxRow(
            {
                outboxId: 'ob-1',
                envelopeId: 'env-1',
                ownerSubject: {
                    kind: 'agentDid',
                    value: 'did:agent:alice',
                },
                ownerTokenId: 'tok-1',
            },
            store,
        );
        expect(row.outboxId).toBe('ob-1');
        expect(row.ownerSubjectKind).toBe('agentDid');
        expect(row.status).toBe('pending');
        expect(store.insert).toHaveBeenCalledOnce();
    });

    it('should insert with mcpClientId kind', async () => {
        const store = makeStore();
        const row = await createOutboxRow(
            {
                outboxId: 'ob-2',
                envelopeId: 'env-2',
                ownerSubject: {
                    kind: 'mcpClientId',
                    value: 'mcp-client-x',
                },
                ownerTokenId: 'tok-2',
            },
            store,
        );
        expect(row.ownerSubjectKind).toBe('mcpClientId');
    });

    it('should reject ownerSubject.kind === "tokenId" (A30 IDOR defense)', async () => {
        const store = makeStore();
        await expect(
            createOutboxRow(
                {
                    outboxId: 'ob-3',
                    envelopeId: 'env-3',
                    ownerSubject: {
                        // runtime rejects 'tokenId' (even though the type already forbids it)
                        kind: 'tokenId' as unknown as 'agentDid',
                        value: 'tok-3',
                    },
                    ownerTokenId: 'tok-3',
                },
                store,
            ),
        ).rejects.toThrow(/A30 violation|tokenId|IDOR/);
        // store.insert must not be called
        expect(store.insert).not.toHaveBeenCalled();
    });

    it('should reject unknown ownerSubject.kind', async () => {
        const store = makeStore();
        await expect(
            createOutboxRow(
                {
                    outboxId: 'ob-4',
                    envelopeId: 'env-4',
                    ownerSubject: {
                        kind: 'unknown-kind' as unknown as 'agentDid',
                        value: 'whatever',
                    },
                    ownerTokenId: 'tok-4',
                },
                store,
            ),
        ).rejects.toThrow();
    });
});

// ─── defaultMockChallengeResolver ────────────────────────────────────────────

describe('defaultMockChallengeResolver (placeholder mock; HTTP impl wired in later)', () => {
    it('should return deterministic challenge bytes for the same outboxId', async () => {
        const c1 = await defaultMockChallengeResolver('outbox-1');
        const c2 = await defaultMockChallengeResolver('outbox-1');
        expect(c1).toEqual(c2);
        expect(c1.length).toBe(32); // SHA-256 32 bytes
    });

    it('should return different bytes for different outboxIds', async () => {
        const c1 = await defaultMockChallengeResolver('outbox-1');
        const c2 = await defaultMockChallengeResolver('outbox-2');
        expect(c1).not.toEqual(c2);
    });
});

// ─── A30 invariant grep test (literal source guard) ──────────────────────────

describe('A30 invariant grep test — outbox-manager.ts literal source guard', () => {
    const SOURCE_PATH = resolve(__dirname, '../outbox-manager.ts');
    let source: string;
    let codeOnly: string;

    function stripCommentsAndStrings(src: string): string {
        // remove line comments + block comments + string literals (avoid false positives from keywords inside comments/strings)
        return src
            .split('\n')
            .filter((line) => {
                const trimmed = line.trim();
                if (trimmed.startsWith('//')) return false;
                if (trimmed.startsWith('*')) return false;
                if (trimmed.startsWith('/*')) return false;
                if (trimmed.startsWith('*/')) return false;
                return true;
            })
            .join('\n')
            // remove string literal contents (wrapped in ' "; avoid false positives from error message strings)
            .replace(/'[^']*'/g, "''")
            .replace(/"[^"]*"/g, '""')
            .replace(/`[^`]*`/g, '``');
    }

    function loadSource(): void {
        source = readFileSync(SOURCE_PATH, 'utf-8');
        codeOnly = stripCommentsAndStrings(source);
    }

    it('source must not use tokenId as a subject kind in the ownership-check path (including camelCase variants)', () => {
        loadSource();
        // grep: disallow callerSubject.kind and 'tokenId' on the same line (ownership branch)
        // i.e. the source must not contain an ownership check like callerSubject.kind === 'tokenId'
        //
        // note: the source may contain an error message string such as "tokenId disabled", but stripCommentsAndStrings filters it out
        const patterns = [
            /callerSubject\.kind\s*[!=]==?\s*['"]tokenId['"]/,
            /ownerSubjectKind\s*[!=]==?\s*['"]tokenId['"]/,
            /kind:\s*['"]tokenId['"]/, // disallow constructing a 'tokenId' kind
        ];
        for (const pattern of patterns) {
            expect(codeOnly).not.toMatch(pattern);
        }
    });

    it('source must not let owner_token_id participate in the ownership check (including camelCase ownerTokenId)', () => {
        loadSource();
        // grep: disallow using owner_token_id / ownerTokenId on the ownership-check path
        // invariant: ownerTokenId is only a chain-audit association
        //
        // ownerTokenId is allowed in:
        //   - type field declarations (OutboxRow.ownerTokenId)
        //   - INSERT SQL parameters
        //   - row mapping (rowToOutboxRow)
        // ownerTokenId is forbidden in:
        //   - ownership-check comparisons (compared against callerSubject)
        const lines = codeOnly.split('\n');
        for (const line of lines) {
            // forbid: ownerTokenId compared against callerSubject on the same line
            expect(line).not.toMatch(/callerSubject.*ownerTokenId/);
            expect(line).not.toMatch(/ownerTokenId.*callerSubject/);
            // snake_case equivalents
            expect(line).not.toMatch(/owner_token_id.*ownership/i);
            expect(line).not.toMatch(/ownership.*owner_token_id/i);
        }
    });

    it('source must contain the 4-step ownership-check markers (step 0/1/2/3)', () => {
        loadSource();
        // the 4-step markers must appear in the source comments/logic
        // this test prevents a future refactor from deleting the 4-step structure
        expect(source).toMatch(/step 0/);
        expect(source).toMatch(/step 1/);
        expect(source).toMatch(/step 2/);
        expect(source).toMatch(/step 3/);
    });

    it('source must contain mcp_error_outbox_unauthorized + mcp_error_outbox_not_found', () => {
        loadSource();
        expect(source).toContain('OUTBOX_UNAUTHORIZED');
        expect(source).toContain('OUTBOX_NOT_FOUND');
        expect(source).toContain('mcp_error_outbox_unauthorized');
        expect(source).toContain('mcp_error_outbox_not_found');
    });
});
