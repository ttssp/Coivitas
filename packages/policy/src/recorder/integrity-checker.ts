import { detectEncoding } from '@coivitas/crypto';
import { type DatabasePool } from '@coivitas/shared';
import type { DID } from '@coivitas/types';
import { ProtocolError, SESSION_GOVERNOR_DID } from '@coivitas/types';

import type {
    ActionRecordQueryFilters,
    IntegrityCheckResult,
    ResolveAgentPublicKey,
    ResolveControlPlanePublicKey,
} from '../types.js';
import { ActionRecorder } from './action-recorder.js';
import {
    buildUnsignedRecordPayload,
    computeRecordHash,
    verifyRecordSignature,
} from './shared.js';

// record_hash valid character set self-check: detectEncoding defaults invalid strings to base64url without throwing,
// so a shape check is done explicitly before the call, separating DB data corruption from normal encoding-detection semantics.
const RECORD_HASH_CHARSET_RE = /^[A-Za-z0-9_-]+$/;

// ── IntegrityChecker shared options (fields common to both kinds) ──────────────────────
interface IntegrityCheckerBaseOptions {
    ledgerPrivateKey?: string;
    ledgerPublicKey?: string;
}

/**
 * IntegrityChecker constructor options (discriminated union).
 *
 * Design: a discriminated union is introduced to enforce, at the type level, that the standard / control-plane mode parameters are mutually exclusive;
 * control-plane mode requires resolveControlPlanePublicKey.
 *
 * kind='standard':
 *   Business mode. resolveIdentity is required (corresponds to the former resolveAgentPublicKey).
 *   Fails closed on encountering a governor DID (SESSION_GOVERNOR_DID)
 *   (reason='agent public key unavailable').
 *
 * kind='control-plane':
 *   Governance channel mode. resolveControlPlanePublicKey is required.
 *   Validates only the governor chain; fails closed on encountering a regular agent DID.
 */
export type IntegrityCheckerOptions =
    | (IntegrityCheckerBaseOptions & {
          kind: 'standard';
          /** Business agent public key resolver (federated DID resolution). */
          resolveIdentity: ResolveAgentPublicKey;
          /** Forbidden at compile time: standard mode does not accept the control-plane resolver. */
          resolveControlPlanePublicKey?: never;
      })
    | (IntegrityCheckerBaseOptions & {
          kind: 'control-plane';
          /** Control-plane public key resolver (governor DID does not enter federated DID resolution). */
          resolveControlPlanePublicKey: ResolveControlPlanePublicKey;
          /** Forbidden at compile time: control-plane mode does not accept the business agent resolver. */
          resolveIdentity?: never;
      });

export class IntegrityChecker {
    private readonly recorder: ActionRecorder;
    private readonly ledgerPublicKey: string;
    private readonly kind: 'standard' | 'control-plane';
    private readonly resolvePublicKey: (did: DID) => Promise<string | null>;

    public constructor(dbPool: DatabasePool, options: IntegrityCheckerOptions) {
        this.kind = options.kind;

        // Set up a unified resolvePublicKey callback based on kind:
        // - in standard mode, fail closed for the governor DID (return null)
        // - in control-plane mode, fail closed for a regular agent DID (return null)
        if (options.kind === 'standard') {
            const resolveIdentity = options.resolveIdentity;
            this.resolvePublicKey = async (did: DID) => {
                if ((did as string) === SESSION_GOVERNOR_DID) {
                    // standard mode: governor DID fail-closed
                    return null;
                }
                return resolveIdentity(did);
            };
        } else {
            // control-plane mode
            const resolveCP = options.resolveControlPlanePublicKey;
            this.resolvePublicKey = async (did: DID) => {
                if ((did as string) !== SESSION_GOVERNOR_DID) {
                    // control-plane mode: regular agent DID fail-closed
                    return null;
                }
                return resolveCP(did);
            };
        }

        // The ActionRecorder inside IntegrityChecker is used only for query() (read-only),
        // it does not call record(). kind='standard' is used to avoid the control-plane constructor
        // requiring injection of sessionOwnerResolver/assertSchemaCompliant
        // (these write-path deps do not apply to a read-only scenario).
        this.recorder = new ActionRecorder(dbPool, {
            kind: 'standard',
            ledgerPrivateKey: options.ledgerPrivateKey,
        });
        this.ledgerPublicKey =
            options.ledgerPublicKey ?? this.recorder.ledgerPublicKey;
    }

    public async verifyIntegrity(
        agentDid: DID,
        filters: Omit<ActionRecordQueryFilters, 'agentDid'> = {},
    ): Promise<IntegrityCheckResult> {
        const { records } = await this.recorder.query({
            ...filters,
            agentDid,
            limit: filters.limit ?? 10_000,
        });

        if (records.length === 0) {
            return { valid: true };
        }

        for (const [index, record] of records.entries()) {
            const expectedPreviousRecordHash =
                index === 0 ? '' : records[index - 1]!.recordHash;
            if (record.previousRecordHash !== expectedPreviousRecordHash) {
                return {
                    valid: false,
                    brokenAt: record.recordId,
                    reason: 'previous_record_hash mismatch',
                };
            }

            const payload = buildUnsignedRecordPayload({
                recordId: record.recordId,
                agentDid: record.agentDid,
                principalDid: record.principalDid,
                actionType: record.actionType,
                parametersSummary: record.parametersSummary,
                authorizationRef: record.authorizationRef,
                resultSummary: record.resultSummary,
                previousRecordHash: record.previousRecordHash,
                createdAt: record.createdAt,
                delegationDepth: record.delegationDepth,
                sessionId: record.sessionId,
            });
            // Encoding detection: reuse canonical detectEncoding;
            // DB data corruption is thrown as INTERNAL_ERROR, not degraded to valid:false.
            if (!RECORD_HASH_CHARSET_RE.test(record.recordHash)) {
                throw new ProtocolError(
                    'INTERNAL_ERROR',
                    `record ${record.recordId} has unrecognized record_hash encoding`,
                );
            }
            const outputEncoding = detectEncoding(record.recordHash);
            const expectedHash = computeRecordHash(
                payload,
                record.previousRecordHash,
                outputEncoding,
            );
            if (record.recordHash !== expectedHash) {
                return {
                    valid: false,
                    brokenAt: record.recordId,
                    reason: 'record_hash mismatch',
                };
            }

            // The unified resolvePublicKey callback dispatches automatically based on kind
            // standard mode fails closed for the governor DID; control-plane mode fails closed for a regular agent DID
            const agentPublicKey = await this.resolvePublicKey(record.agentDid);
            if (!agentPublicKey) {
                return {
                    valid: false,
                    brokenAt: record.recordId,
                    reason: 'agent public key unavailable',
                };
            }

            if (
                !verifyRecordSignature(
                    payload,
                    record.actorSignature,
                    agentPublicKey,
                )
            ) {
                return {
                    valid: false,
                    brokenAt: record.recordId,
                    reason: 'actor_signature invalid',
                };
            }

            if (
                !verifyRecordSignature(
                    payload,
                    record.ledgerSignature,
                    this.ledgerPublicKey,
                )
            ) {
                return {
                    valid: false,
                    brokenAt: record.recordId,
                    reason: 'ledger_signature invalid',
                };
            }
        }

        return { valid: true };
    }
}
