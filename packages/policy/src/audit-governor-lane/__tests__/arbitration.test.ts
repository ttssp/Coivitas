/**
 * InMemoryOperatorArbitrationStateMachine unit tests.
 *
 * Coverage:
 * - requestArbitration happy path -> ARBITRATED_PENDING_OPERATOR
 * - submitVerdict happy path -> ARBITRATED
 * - Illegal transition ARBITRATED -> * -> fail-closed
 * - Duplicate requestArbitration for the same relatedRecordId -> throw
 * - submitVerdict for a non-existent arbitrationId -> throw
 * - getState happy path + non-existent
 * - clear / size
 *
 */

import { describe, it, expect, beforeEach } from 'vitest';
import type { DID, Timestamp } from '@coivitas/types';

import { InMemoryOperatorArbitrationStateMachine } from '../arbitration.js';
import type { ArbitrationVerdict } from '../types.js';

const TIMESTAMP = '2026-05-05T10:00:00.000Z' as Timestamp;
const OPERATOR_DID = 'did:key:z6MkOperator...' as DID;

describe('InMemoryOperatorArbitrationStateMachine', () => {
    let sm: InMemoryOperatorArbitrationStateMachine;

    beforeEach(() => {
        sm = new InMemoryOperatorArbitrationStateMachine();
    });

    describe('requestArbitration', () => {
        it('should create arbitration in ARBITRATED_PENDING_OPERATOR state', async () => {
            const result = await sm.requestArbitration({
                relatedRecordId: 'rec-001',
                reason: 'Automated decision uncertain',
                timestamp: TIMESTAMP,
            });

            expect(result.state).toBe('ARBITRATED_PENDING_OPERATOR');
            expect(result.arbitrationId).toBeTruthy();
        });

        it('should generate unique arbitrationId per request', async () => {
            const r1 = await sm.requestArbitration({
                relatedRecordId: 'rec-001',
                reason: 'test',
                timestamp: TIMESTAMP,
            });
            // r1 enters ARBITRATED_PENDING_OPERATOR; submit first to complete it
            await sm.submitVerdict(r1.arbitrationId, {
                operatorDid: OPERATOR_DID,
                decision: 'approve',
                rationale: 'ok',
                timestamp: TIMESTAMP,
            });
            const r2 = await sm.requestArbitration({
                relatedRecordId: 'rec-002',
                reason: 'test',
                timestamp: TIMESTAMP,
            });

            expect(r1.arbitrationId).not.toBe(r2.arbitrationId);
        });

        it('should throw when relatedRecordId already has pending arbitration', async () => {
            await sm.requestArbitration({
                relatedRecordId: 'rec-001',
                reason: 'test',
                timestamp: TIMESTAMP,
            });

            await expect(
                sm.requestArbitration({
                    relatedRecordId: 'rec-001',
                    reason: 'duplicate',
                    timestamp: TIMESTAMP,
                }),
            ).rejects.toThrow('ARBITRATION_HALF_COMMITTED');
        });

        it('should allow new arbitration after previous is ARBITRATED', async () => {
            const r1 = await sm.requestArbitration({
                relatedRecordId: 'rec-001',
                reason: 'test',
                timestamp: TIMESTAMP,
            });
            await sm.submitVerdict(r1.arbitrationId, {
                operatorDid: OPERATOR_DID,
                decision: 'approve',
                rationale: 'ok',
                timestamp: TIMESTAMP,
            });

            // The same relatedRecordId can create a new arbitration (the previous one is done)
            const r2 = await sm.requestArbitration({
                relatedRecordId: 'rec-001',
                reason: 'new issue',
                timestamp: TIMESTAMP,
            });
            expect(r2.state).toBe('ARBITRATED_PENDING_OPERATOR');
        });
    });

    describe('submitVerdict', () => {
        it('should transition to ARBITRATED on valid verdict', async () => {
            const req = await sm.requestArbitration({
                relatedRecordId: 'rec-001',
                reason: 'test',
                timestamp: TIMESTAMP,
            });

            const verdict: ArbitrationVerdict = {
                operatorDid: OPERATOR_DID,
                decision: 'approve',
                rationale: 'Session supersede was justified',
                timestamp: TIMESTAMP,
            };

            const result = await sm.submitVerdict(req.arbitrationId, verdict);
            expect(result.state).toBe('ARBITRATED');
            expect(result.arbitrationId).toBe(req.arbitrationId);
        });

        it('should throw for non-existent arbitrationId', async () => {
            await expect(
                sm.submitVerdict('non-existent', {
                    operatorDid: OPERATOR_DID,
                    decision: 'approve',
                    rationale: 'ok',
                    timestamp: TIMESTAMP,
                }),
            ).rejects.toThrow('ARBITRATION_CHAIN_MALFORMED');
        });

        it('should throw for illegal transition ARBITRATED -> ARBITRATED', async () => {
            const req = await sm.requestArbitration({
                relatedRecordId: 'rec-001',
                reason: 'test',
                timestamp: TIMESTAMP,
            });

            await sm.submitVerdict(req.arbitrationId, {
                operatorDid: OPERATOR_DID,
                decision: 'approve',
                rationale: 'ok',
                timestamp: TIMESTAMP,
            });

            // Attempt submitVerdict again -> illegal transition
            await expect(
                sm.submitVerdict(req.arbitrationId, {
                    operatorDid: OPERATOR_DID,
                    decision: 'reject',
                    rationale: 'second attempt',
                    timestamp: TIMESTAMP,
                }),
            ).rejects.toThrow('ARBITRATION_CHAIN_MALFORMED');
        });

        it('should support reject decision', async () => {
            const req = await sm.requestArbitration({
                relatedRecordId: 'rec-001',
                reason: 'test',
                timestamp: TIMESTAMP,
            });

            const result = await sm.submitVerdict(req.arbitrationId, {
                operatorDid: OPERATOR_DID,
                decision: 'reject',
                rationale: 'Not justified',
                timestamp: TIMESTAMP,
            });

            expect(result.state).toBe('ARBITRATED');
        });
    });

    describe('getState', () => {
        it('should return null for non-existent arbitrationId', async () => {
            const state = await sm.getState('non-existent');
            expect(state).toBeNull();
        });

        it('should return ARBITRATED_PENDING_OPERATOR after request', async () => {
            const req = await sm.requestArbitration({
                relatedRecordId: 'rec-001',
                reason: 'test',
                timestamp: TIMESTAMP,
            });

            const state = await sm.getState(req.arbitrationId);
            expect(state).toBe('ARBITRATED_PENDING_OPERATOR');
        });

        it('should return ARBITRATED after verdict', async () => {
            const req = await sm.requestArbitration({
                relatedRecordId: 'rec-001',
                reason: 'test',
                timestamp: TIMESTAMP,
            });

            await sm.submitVerdict(req.arbitrationId, {
                operatorDid: OPERATOR_DID,
                decision: 'approve',
                rationale: 'ok',
                timestamp: TIMESTAMP,
            });

            const state = await sm.getState(req.arbitrationId);
            expect(state).toBe('ARBITRATED');
        });
    });

    describe('size and clear', () => {
        it('should report correct size', async () => {
            expect(sm.size).toBe(0);
            await sm.requestArbitration({
                relatedRecordId: 'rec-001',
                reason: 'test',
                timestamp: TIMESTAMP,
            });
            expect(sm.size).toBe(1);
        });

        it('should clear all records', async () => {
            await sm.requestArbitration({
                relatedRecordId: 'rec-001',
                reason: 'test',
                timestamp: TIMESTAMP,
            });
            sm.clear();
            expect(sm.size).toBe(0);
        });
    });

    describe('fail-closed error codes', () => {
        it('should throw ProtocolError with INTERNAL_ERROR code', async () => {
            try {
                await sm.submitVerdict('bogus', {
                    operatorDid: OPERATOR_DID,
                    decision: 'approve',
                    rationale: 'ok',
                    timestamp: TIMESTAMP,
                });
                expect.fail('should have thrown');
            } catch (err: unknown) {
                expect((err as { code: string }).code).toBe('INTERNAL_ERROR');
            }
        });
    });
});
