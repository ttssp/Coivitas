/**
 * settle payload construction utilities
 *
 * buildSettlePayload produces a deterministic JSON string used for Ed25519 signing and verification.
 * Keys are sorted in ASCII order so the signature payload can be reconstructed across implementations.
 *
 * toISOString background: the PG node driver returns a Date object for TIMESTAMPTZ;
 * using String() would produce a locale format instead of ISO 8601, causing the signature payload
 * reconstruction to mismatch. The shared helper is extracted into the policy package-level _shared/timestamp.ts;
 * this file's toISOString becomes a re-export, keeping the existing settle-handler / settle-tracker
 * call sites intact.
 */

/**
 * Build the settle signing payload (deterministic JSON serialization, keys sorted in ASCII order)
 */
export function buildSettlePayload(req: {
    settleId: string;
    senderDomain: string;
    recipientDomain: string;
    agentDid: string;
    metric: string;
    amount: number;
    window: string;
    windowStart: string;
}): string {
    // bottom line: keys sorted in ASCII order so the signature payload can be reconstructed across implementations
    return JSON.stringify({
        agentDid: req.agentDid,
        amount: req.amount,
        metric: req.metric,
        recipientDomain: req.recipientDomain,
        senderDomain: req.senderDomain,
        settleId: req.settleId,
        window: req.window,
        windowStart: req.windowStart,
    });
}

// re-export the package-level helper (_shared/timestamp.ts),
// keeping the settle-handler / settle-tracker call sites intact.
export { toISOString } from '../_shared/timestamp.js';
