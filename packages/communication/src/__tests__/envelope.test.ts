import { describe, expect, it, vi } from 'vitest';

import { generateKeyPair } from '@coivitas/crypto';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
} from '@coivitas/identity';
import type { NegotiationEnvelope } from '@coivitas/types';

import { buildEnvelope, parseEnvelope, verifyEnvelope } from '../index.js';

function createIdentities() {
    const principal = generateKeyPair();
    const principalDid = didKeyFromPublicKey(
        Buffer.from(principal.publicKey, 'hex'),
    );

    const sender = createAgentIdentity({
        principalDid,
        principalPrivateKey: principal.privateKey,
    });
    const recipient = createAgentIdentity({
        principalDid,
        principalPrivateKey: principal.privateKey,
    });

    return { sender, recipient };
}

describe('envelope', () => {
    it('builds, parses, and verifies a signed envelope', async () => {
        const { sender, recipient } = createIdentities();
        const envelope = buildEnvelope({
            senderDid: sender.document.id,
            senderPrivateKey: sender.privateKey,
            recipientDid: recipient.document.id,
            sessionId: null,
            messageType: 'NEGOTIATION_REQUEST',
            body: {
                action: 'INQUIRY',
                params: { sku: 'SKU-001' },
                requestId: 'req-001',
            },
            sequenceNumber: 1,
        });

        expect(parseEnvelope(JSON.parse(JSON.stringify(envelope)))).toEqual(
            envelope,
        );
        await expect(
            verifyEnvelope(envelope, {
                resolvePublicKey: (did) =>
                    Promise.resolve(
                        did === sender.document.id
                            ? sender.document.publicKey
                            : null,
                    ),
                now: () => new Date(envelope.timestamp).getTime(),
            }),
        ).resolves.toEqual({ valid: true });
    });

    it('rejects malformed payloads during parse', () => {
        expect(() => parseEnvelope(null)).toThrow('[INVALID_MESSAGE]');
        expect(() =>
            parseEnvelope({
                id: 'env-001',
                specVersion: '0.1.0',
                header: {
                    senderDid: 'did:agent:a1',
                    recipientDid: 'did:agent:b2',
                    sessionId: null,
                },
                messageType: 'NOT_A_MESSAGE',
                body: {},
                signature: 'a'.repeat(128),
                timestamp: '2026-04-03T00:00:00.000Z',
            }),
        ).toThrow('[INVALID_MESSAGE]');
        expect(() =>
            parseEnvelope({
                id: '550e8400-e29b-41d4-a716-446655440010',
                specVersion: 'abc',
                header: {
                    senderDid:
                        'did:agent:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0',
                    recipientDid:
                        'did:agent:00112233445566778899aabbccddeeff00112233',
                    sessionId: null,
                },
                messageType: 'HANDSHAKE_INIT',
                body: {},
                signature: 'a'.repeat(128),
                timestamp: '2026-04-03T00:00:00.000Z',
            }),
        ).toThrow('[SPEC_VERSION_MISMATCH]');
        expect(() =>
            parseEnvelope({
                id: '550e8400-e29b-41d4-a716-446655440011',
                specVersion: '0.1.0',
                header: {
                    senderDid: 'not-a-did',
                    recipientDid:
                        'did:agent:00112233445566778899aabbccddeeff00112233',
                    sessionId: null,
                },
                messageType: 'HANDSHAKE_INIT',
                body: {},
                signature: 'a'.repeat(128),
                timestamp: '2026-04-03T00:00:00.000Z',
            }),
        ).toThrow('[INVALID_MESSAGE]');
    });

    it('detects payload tampering after signing', async () => {
        const { sender, recipient } = createIdentities();
        const envelope = buildEnvelope({
            senderDid: sender.document.id,
            senderPrivateKey: sender.privateKey,
            recipientDid: recipient.document.id,
            sessionId: 'session-001',
            messageType: 'NEGOTIATION_RESPONSE',
            body: {
                requestId: 'req-001',
                status: 'SUCCESS',
            },
        });

        const tampered: NegotiationEnvelope = {
            ...envelope,
            body: {
                requestId: 'req-001',
                status: 'REJECTED',
            },
        };

        await expect(
            verifyEnvelope(tampered, {
                resolvePublicKey: (did) =>
                    Promise.resolve(
                        did === sender.document.id
                            ? sender.document.publicKey
                            : null,
                    ),
                now: () => new Date(envelope.timestamp).getTime(),
            }),
        ).resolves.toEqual({
            valid: false,
            reason: 'Signature verification failed',
        });
    });

    it('rejects incompatible versions, clock skew, and unknown sender keys', async () => {
        const { sender, recipient } = createIdentities();
        const envelope = buildEnvelope({
            senderDid: sender.document.id,
            senderPrivateKey: sender.privateKey,
            recipientDid: recipient.document.id,
            sessionId: null,
            messageType: 'NEGOTIATION_CONFIRM',
            body: {
                requestId: 'req-002',
                acknowledged: true,
            },
        });

        await expect(
            verifyEnvelope(
                {
                    ...envelope,
                    specVersion: '1.0.0',
                },
                {
                    resolvePublicKey: () =>
                        Promise.resolve(sender.document.publicKey),
                    now: () => new Date(envelope.timestamp).getTime(),
                },
            ),
        ).resolves.toMatchObject({
            valid: false,
        });

        await expect(
            verifyEnvelope(envelope, {
                resolvePublicKey: () => Promise.resolve(null),
                now: () => new Date(envelope.timestamp).getTime(),
            }),
        ).resolves.toEqual({
            valid: false,
            reason: `Unable to resolve the public key for senderDid: ${sender.document.id}`,
        });

        await expect(
            verifyEnvelope(envelope, {
                resolvePublicKey: () =>
                    Promise.resolve(sender.document.publicKey),
                now: () => new Date(envelope.timestamp).getTime() + 600_001,
            }),
        ).resolves.toMatchObject({
            valid: false,
        });
    });
});

describe('envelope — dual-format signature encoding support', () => {
    it('should build envelope with hex signature by default for v0.1.0 envelope when no signatureEncoding given', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const sender = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });
        const recipient = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });

        const envelope = buildEnvelope({
            senderDid: sender.document.id,
            senderPrivateKey: sender.privateKey,
            recipientDid: recipient.document.id,
            sessionId: null,
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY' },
        });

        // specVersion compatibility matrix:
        // v0.1.0 defaults to hex (the frozen wire format baseline is unchanged)
        // v0.2.0 / v0.3.0 default to base64url
        // no capabilityTokenRef → specVersion = '0.1.0' → defaults to hex, 64-byte signature → 128 hex chars
        expect(envelope.specVersion).toBe('0.1.0');
        expect(envelope.signature).toMatch(/^[0-9a-f]{128}$/);
        const result = await verifyEnvelope(envelope, {
            resolvePublicKey: (did) =>
                Promise.resolve(
                    did === sender.document.id
                        ? sender.document.publicKey
                        : null,
                ),
            now: () => new Date(envelope.timestamp).getTime(),
        });
        expect(result).toEqual({ valid: true });
    });

    it('should build envelope with base64url signature when signatureEncoding is explicitly base64url (no capabilityTokenRef)', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const sender = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });
        const recipient = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });

        // signatureEncoding='base64url' always takes effect; it is no longer downgraded when capabilityTokenRef is absent
        const envelope = buildEnvelope({
            senderDid: sender.document.id,
            senderPrivateKey: sender.privateKey,
            recipientDid: recipient.document.id,
            sessionId: null,
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY' },
            signatureEncoding: 'base64url',
        });

        // base64url: 86 chars, valid per schema
        expect(envelope.signature).toMatch(/^[A-Za-z0-9_-]{86}$/);
        expect(envelope.specVersion).toBe('0.1.0');
        const result = await verifyEnvelope(envelope, {
            resolvePublicKey: (did) =>
                Promise.resolve(
                    did === sender.document.id
                        ? sender.document.publicKey
                        : null,
                ),
            now: () => new Date(envelope.timestamp).getTime(),
        });
        expect(result).toEqual({ valid: true });
    });

    it('should build envelope with base64url signature when signatureEncoding is base64url and capabilityTokenRef is present', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const sender = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });
        const recipient = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });

        // 0.2.0 envelope: has capabilityTokenRef, with explicit signatureEncoding = base64url
        const envelope = buildEnvelope({
            senderDid: sender.document.id,
            senderPrivateKey: sender.privateKey,
            recipientDid: recipient.document.id,
            sessionId: null,
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY' },
            capabilityTokenRef: 'cap-token-001',
            signatureEncoding: 'base64url',
        });

        // base64url: 64 bytes → 86 chars, containing only [A-Za-z0-9_-]
        expect(envelope.signature).toMatch(/^[A-Za-z0-9_-]{86}$/);
        expect(envelope.specVersion).toBe('0.2.0');
        const result = await verifyEnvelope(envelope, {
            resolvePublicKey: (did) =>
                Promise.resolve(
                    did === sender.document.id
                        ? sender.document.publicKey
                        : null,
                ),
            now: () => new Date(envelope.timestamp).getTime(),
        });
        expect(result).toEqual({ valid: true });
    });

    it('should build v0.3.0 envelope when params.specVersion is explicitly 0.3.0', async () => {
        // If buildEnvelope only emits 0.1.0 / 0.2.0, it cannot construct v0.3.0-only message
        // types such as DISCOVERY_REQUEST/RESPONSE; an envelope built by the caller via buildEnvelope
        // would be rejected as INVALID_MESSAGE by its own EnvelopeDiscoveryDispatcher.
        // Correct implementation: add an optional specVersion explicit override to BuildEnvelopeParams.
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const sender = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });
        const recipient = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });

        const envelope = buildEnvelope({
            senderDid: sender.document.id,
            senderPrivateKey: sender.privateKey,
            recipientDid: recipient.document.id,
            sessionId: null,
            messageType: 'DISCOVERY_REQUEST',
            body: {
                targetDid: 'did:agent:0000000000000000000000000000000000000001',
                requestedAt: new Date().toISOString(),
            },
            specVersion: '0.3.0',
        });

        expect(envelope.specVersion).toBe('0.3.0');
        // v0.3.0 defaults to base64url
        expect(envelope.signature).toMatch(/^[A-Za-z0-9_-]{86}$/);
        const result = await verifyEnvelope(envelope, {
            resolvePublicKey: (did) =>
                Promise.resolve(
                    did === sender.document.id
                        ? sender.document.publicKey
                        : null,
                ),
            now: () => new Date(envelope.timestamp).getTime(),
        });
        expect(result).toEqual({ valid: true });
    });

    it('should default v0.2.0 envelope signature to base64url when signatureEncoding is omitted', async () => {
        // Hard matrix requirement: from v0.2.0 onward, all NegotiationEnvelope.signature values default to base64url.
        // If buildEnvelope switches to base64url only when specVersion === 0.3.0,
        // v0.2.0 envelopes still emit hex, so the encoding switch never takes effect on the default send path.
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const sender = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });
        const recipient = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });

        // capabilityTokenRef → specVersion = '0.2.0', no signatureEncoding passed
        const envelope = buildEnvelope({
            senderDid: sender.document.id,
            senderPrivateKey: sender.privateKey,
            recipientDid: recipient.document.id,
            sessionId: null,
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY' },
            capabilityTokenRef: 'cap-token-w28-f3',
        });

        expect(envelope.specVersion).toBe('0.2.0');
        // The default must be base64url (86 chars containing only [A-Za-z0-9_-]); it must not be hex (128 chars [0-9a-f])
        expect(envelope.signature).toMatch(/^[A-Za-z0-9_-]{86}$/);
        expect(envelope.signature).not.toMatch(/^[0-9a-f]{128}$/);

        const result = await verifyEnvelope(envelope, {
            resolvePublicKey: (did) =>
                Promise.resolve(
                    did === sender.document.id
                        ? sender.document.publicKey
                        : null,
                ),
            now: () => new Date(envelope.timestamp).getTime(),
        });
        expect(result).toEqual({ valid: true });
    });

    it('should verify both hex and base64url signed envelopes when mixed format compatibility used', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const sender = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });
        const recipient = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });

        const resolveKey = (did: string) =>
            Promise.resolve(
                did === sender.document.id ? sender.document.publicKey : null,
            );

        const hexEnvelope = buildEnvelope({
            senderDid: sender.document.id,
            senderPrivateKey: sender.privateKey,
            recipientDid: recipient.document.id,
            sessionId: null,
            messageType: 'NEGOTIATION_REQUEST',
            body: { format: 'hex' },
        });
        // 0.2.0 envelopes use base64url; verifyEnvelope auto-detects both formats
        const b64Envelope = buildEnvelope({
            senderDid: sender.document.id,
            senderPrivateKey: sender.privateKey,
            recipientDid: recipient.document.id,
            sessionId: null,
            messageType: 'NEGOTIATION_REQUEST',
            body: { format: 'base64url' },
            capabilityTokenRef: 'cap-token-002',
            signatureEncoding: 'base64url',
        });

        const [r1, r2] = await Promise.all([
            verifyEnvelope(hexEnvelope, {
                resolvePublicKey: resolveKey,
                now: () => new Date(hexEnvelope.timestamp).getTime(),
            }),
            verifyEnvelope(b64Envelope, {
                resolvePublicKey: resolveKey,
                now: () => new Date(b64Envelope.timestamp).getTime(),
            }),
        ]);
        expect(r1).toEqual({ valid: true });
        expect(r2).toEqual({ valid: true });
    });
});

// ─── specVersion fail-closed ─────────────────────────────

// Background: specVersion 0.2.0 introduced new fields such as capabilityTokenRef. If the
// implementation only compares the major version number, it wrongly treats 0.1.0 as equivalent to 0.2.0.

// Requirement: specVersion ∉ {"0.1.0", "0.2.0"} is always fail-closed rejected
// (SPEC_VERSION_MISMATCH). Versions not in SUPPORTED_SPEC_VERSIONS must not be passed —
// "future minor passes + warning" forward compatibility would bypass the wire trust boundary.

// Expected semantics:
// 1) specVersion must equal one of SUPPORTED_SPEC_VERSIONS (exact match)
// 2) Any version not in the supported set (whether a different major or a future minor) → reject
// 3) specVersion missing/malformed → reject

describe('envelope — specVersion fail-closed', () => {
    async function buildEnvelopeWithSpecVersion(specVersion: string): Promise<{
        envelope: NegotiationEnvelope;
        sender: ReturnType<typeof createAgentIdentity>;
    }> {
        const { canonicalize, sign } = await import('@coivitas/crypto');
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const sender = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });
        const recipient = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });

        const id = '550e8400-e29b-41d4-a716-446655440099';
        const timestamp = new Date().toISOString();
        const signedPayload = {
            id,
            specVersion,
            header: {
                senderDid: sender.document.id,
                recipientDid: recipient.document.id,
                sessionId: null as string | null,
            },
            messageType: 'NEGOTIATION_REQUEST' as const,
            body: { action: 'INQUIRY' },
            timestamp,
        };
        const canonical = canonicalize(signedPayload);
        const bytes = new TextEncoder().encode(canonical);
        const signature = sign(bytes, sender.privateKey, 'hex');
        const envelope = {
            ...signedPayload,
            signature,
        } as unknown as NegotiationEnvelope;
        return { envelope, sender };
    }

    it('accepts specVersion 0.1.0', async () => {
        const { envelope, sender } =
            await buildEnvelopeWithSpecVersion('0.1.0');
        const result = await verifyEnvelope(envelope, {
            resolvePublicKey: (did) =>
                Promise.resolve(
                    did === sender.document.id
                        ? sender.document.publicKey
                        : null,
                ),
            now: () => new Date(envelope.timestamp).getTime(),
        });
        expect(result).toEqual({ valid: true });
    });

    it('accepts specVersion 0.2.0', async () => {
        const { envelope, sender } =
            await buildEnvelopeWithSpecVersion('0.2.0');
        const result = await verifyEnvelope(envelope, {
            resolvePublicKey: (did) =>
                Promise.resolve(
                    did === sender.document.id
                        ? sender.document.publicKey
                        : null,
                ),
            now: () => new Date(envelope.timestamp).getTime(),
        });
        expect(result).toEqual({ valid: true });
    });

    it('accepts specVersion 0.3.0 (in SUPPORTED_SPEC_VERSIONS)', async () => {
        // 0.3.0 has been added to the three-way coexistence set of SUPPORTED_SPEC_VERSIONS.
        // This test verifies that verifyEnvelope accepts a 0.3.0 envelope (when there is no capabilityTokenRef).
        // The fail-closed path for capabilityTokenRef + non-0.2.0 is covered in the
        // separate capabilityTokenRef gate describe block.
        const { envelope, sender } =
            await buildEnvelopeWithSpecVersion('0.3.0');
        const result = await verifyEnvelope(envelope, {
            resolvePublicKey: (did) =>
                Promise.resolve(
                    did === sender.document.id
                        ? sender.document.publicKey
                        : null,
                ),
            now: () => new Date(envelope.timestamp).getTime(),
        });
        expect(result).toEqual({ valid: true });
    });

    it('rejects unsupported future minor specVersion 0.4.0 (not in SUPPORTED_SPEC_VERSIONS)', async () => {
        // specVersion ∉ SUPPORTED_SPEC_VERSIONS must be fail-closed rejected.
        // 0.4.0 stands in for "a future minor whose support set has not been upgraded".
        const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        try {
            const { envelope, sender } =
                await buildEnvelopeWithSpecVersion('0.4.0');
            const result = await verifyEnvelope(envelope, {
                resolvePublicKey: (did) =>
                    Promise.resolve(
                        did === sender.document.id
                            ? sender.document.publicKey
                            : null,
                    ),
                now: () => new Date(envelope.timestamp).getTime(),
            });
            expect(result.valid).toBe(false);
            expect(result.reason).toMatch(/specVersion/);
            expect(result.reason).toMatch(/0\.4\.0/);
            // fail-closed: must not emit a warning (a warning implies "passed through")
            expect(warnSpy).not.toHaveBeenCalled();
        } finally {
            warnSpy.mockRestore();
        }
    });

    it('rejects specVersion 1.0.0 (not in SUPPORTED_SPEC_VERSIONS)', async () => {
        const { envelope, sender } =
            await buildEnvelopeWithSpecVersion('1.0.0');
        const result = await verifyEnvelope(envelope, {
            resolvePublicKey: (did) =>
                Promise.resolve(
                    did === sender.document.id
                        ? sender.document.publicKey
                        : null,
                ),
            now: () => new Date(envelope.timestamp).getTime(),
        });
        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/specVersion/);
    });

    it('rejects when specVersion has malformed format (verifyEnvelope guard)', async () => {
        const { envelope, sender } =
            await buildEnvelopeWithSpecVersion('0.1.0');
        const broken = {
            ...envelope,
            specVersion: 'not-a-version',
        } as unknown as NegotiationEnvelope;
        const result = await verifyEnvelope(broken, {
            resolvePublicKey: (did) =>
                Promise.resolve(
                    did === sender.document.id
                        ? sender.document.publicKey
                        : null,
                ),
            now: () => new Date(envelope.timestamp).getTime(),
        });
        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/specVersion/);
    });

    it('rejects when specVersion is missing', async () => {
        const { envelope, sender } =
            await buildEnvelopeWithSpecVersion('0.1.0');
        const broken = { ...envelope } as Record<string, unknown>;
        delete broken['specVersion'];
        const result = await verifyEnvelope(
            broken as unknown as NegotiationEnvelope,
            {
                resolvePublicKey: (did) =>
                    Promise.resolve(
                        did === sender.document.id
                            ? sender.document.publicKey
                            : null,
                    ),
                now: () => new Date(envelope.timestamp).getTime(),
            },
        );
        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/specVersion/);
    });
});

// ─── capabilityTokenRef × specVersion gate ──────────────
// Background: capabilityTokenRef is a breaking-format-change field that must ride on
// specVersion 0.2.0 (the version that binds the capability token to the envelope signature).
// If parseEnvelope wrongly uses `=== SPEC_VERSION` (= '0.1.0') as the rejection condition,
// 0.3.0 + capabilityTokenRef slips through. With the correct implementation, all non-0.2.0 versions are fail-closed rejected.
describe('envelope — capabilityTokenRef × specVersion gate', () => {
    function makeRawEnvelope(
        specVersion: string,
        opts: { withCapabilityTokenRef: boolean },
    ): Record<string, unknown> {
        const header: Record<string, unknown> = {
            senderDid: 'did:agent:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0',
            recipientDid: 'did:agent:00112233445566778899aabbccddeeff00112233',
            sessionId: null,
        };
        if (opts.withCapabilityTokenRef) {
            header['capabilityTokenRef'] = 'cap-token-test';
        }
        return {
            id: '550e8400-e29b-41d4-a716-446655440f5a',
            specVersion,
            header,
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY' },
            signature: 'a'.repeat(128),
            timestamp: '2026-04-28T00:00:00.000Z',
        };
    }

    it('parseEnvelope rejects 0.3.0 + capabilityTokenRef (core regression)', () => {
        const raw = makeRawEnvelope('0.3.0', { withCapabilityTokenRef: true });
        expect(() => parseEnvelope(raw)).toThrow('[SPEC_VERSION_MISMATCH]');
    });

    it('parseEnvelope rejects 0.1.0 + capabilityTokenRef', () => {
        const raw = makeRawEnvelope('0.1.0', { withCapabilityTokenRef: true });
        expect(() => parseEnvelope(raw)).toThrow('[SPEC_VERSION_MISMATCH]');
    });

    it('parseEnvelope accepts 0.2.0 + capabilityTokenRef', () => {
        const raw = makeRawEnvelope('0.2.0', { withCapabilityTokenRef: true });
        expect(() => parseEnvelope(raw)).not.toThrow();
    });

    it('parseEnvelope accepts 0.3.0 without capabilityTokenRef (the gate triggers only when the field is present)', () => {
        const raw = makeRawEnvelope('0.3.0', {
            withCapabilityTokenRef: false,
        });
        expect(() => parseEnvelope(raw)).not.toThrow();
    });
});

// ─── Defensive path coverage ─────────────────────────────────────────────────────────────
// envelope.ts still contains two defensive branches that lack direct assertions:
// • parseEnvelope: timestamp/signature missing or wrong type (lines 190-202)
// • verifyEnvelope: timestamp non-numeric / outside clockSkew / crypto.verify throws (lines 255, 290-295)
// The 5 negative tests below pull these two through the project's ≥95% lines / ≥90% branches gate.
describe('envelope — defensive path coverage', () => {
    function makeBaseEnvelope(): Record<string, unknown> {
        const { sender, recipient } = createIdentities();
        const envelope = buildEnvelope({
            senderDid: sender.document.id,
            senderPrivateKey: sender.privateKey,
            recipientDid: recipient.document.id,
            sessionId: null,
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY' },
        });
        return JSON.parse(JSON.stringify(envelope)) as Record<string, unknown>;
    }

    it('parseEnvelope rejects when timestamp is undefined', () => {
        const raw = makeBaseEnvelope();
        delete raw['timestamp'];
        expect(() => parseEnvelope(raw)).toThrow(/timestamp/);
    });

    it('parseEnvelope rejects when signature is empty string', () => {
        // signature='' triggers !obj['signature'] at line 190 (empty string is falsy);
        // it is a separate case because parseEnvelope's rejection paths for signature and timestamp
        // go through different throw statements, both of which must be covered to fully exercise the branches.
        const raw = makeBaseEnvelope();
        raw['signature'] = '';
        expect(() => parseEnvelope(raw)).toThrow(/signature/);
    });

    it('verifyEnvelope rejects when timestamp is a non-numeric string', async () => {
        // A non-numeric string parses to Date → NaN → line 255 short-circuits into the !isFinite branch;
        // this corresponds to "syntactically valid but semantically invalid" input, a different code path from a missing timestamp.
        const { sender, recipient } = createIdentities();
        const envelope = buildEnvelope({
            senderDid: sender.document.id,
            senderPrivateKey: sender.privateKey,
            recipientDid: recipient.document.id,
            sessionId: null,
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY' },
        });
        const broken = {
            ...envelope,
            timestamp: 'not-a-date',
        } as unknown as NegotiationEnvelope;
        const result = await verifyEnvelope(broken, {
            resolvePublicKey: (did) =>
                Promise.resolve(
                    did === sender.document.id
                        ? sender.document.publicKey
                        : null,
                ),
            now: () => new Date(envelope.timestamp).getTime(),
        });
        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/Clock skew/);
    });

    it('verifyEnvelope rejects when timestamp is far in the past (negative epoch beyond clockSkew)', async () => {
        // A negative epoch (1900-01-01) parses to a finite value, but its difference from now far exceeds clockSkewMs
        // → line 255 hits the Math.abs(...) > clockSkewMs branch; together with the previous case, this
        // covers the short-circuit paths on both sides of the "OR" expression.
        const { sender, recipient } = createIdentities();
        const envelope = buildEnvelope({
            senderDid: sender.document.id,
            senderPrivateKey: sender.privateKey,
            recipientDid: recipient.document.id,
            sessionId: null,
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY' },
        });
        const broken = {
            ...envelope,
            timestamp: '1900-01-01T00:00:00.000Z',
        } as unknown as NegotiationEnvelope;
        const result = await verifyEnvelope(broken, {
            resolvePublicKey: (did) =>
                Promise.resolve(
                    did === sender.document.id
                        ? sender.document.publicKey
                        : null,
                ),
            now: () => Date.parse('2026-04-25T00:00:00.000Z'),
        });
        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/Clock skew/);
    });

    // ── Supplement: the remaining defensive branches of parseEnvelope ──
    // The first round of 5 tests covered timestamp(190-202) + signature catch(290-295);
    // but the project-level coverage shows a truncated "...98-202" that actually points to the entire
    // parse defensive region of lines 99-202. To pull file-level coverage past 95%/90%, these must be completed too.
    // Each test targets a distinct throw path,
    // rather than piling up "small variants that test the happy path".
    it('parseEnvelope rejects when id is missing', () => {
        const raw = makeBaseEnvelope();
        delete raw['id'];
        expect(() => parseEnvelope(raw)).toThrow(/id/);
    });

    it('parseEnvelope rejects when specVersion is missing', () => {
        const raw = makeBaseEnvelope();
        delete raw['specVersion'];
        expect(() => parseEnvelope(raw)).toThrow(/specVersion/);
    });

    it('parseEnvelope rejects when header is missing', () => {
        const raw = makeBaseEnvelope();
        delete raw['header'];
        expect(() => parseEnvelope(raw)).toThrow(/header/);
    });

    it('parseEnvelope rejects when header.senderDid is missing', () => {
        const raw = makeBaseEnvelope();
        const header = raw['header'] as Record<string, unknown>;
        delete header['senderDid'];
        expect(() => parseEnvelope(raw)).toThrow(/senderDid/);
    });

    it('parseEnvelope rejects when header.recipientDid is missing', () => {
        const raw = makeBaseEnvelope();
        const header = raw['header'] as Record<string, unknown>;
        delete header['recipientDid'];
        expect(() => parseEnvelope(raw)).toThrow(/recipientDid/);
    });

    it('parseEnvelope rejects when header.recipientDid is malformed (not a DID)', () => {
        const raw = makeBaseEnvelope();
        const header = raw['header'] as Record<string, unknown>;
        header['recipientDid'] = 'not-a-did';
        expect(() => parseEnvelope(raw)).toThrow(/recipientDid/);
    });

    it('parseEnvelope rejects when body is missing', () => {
        const raw = makeBaseEnvelope();
        delete raw['body'];
        expect(() => parseEnvelope(raw)).toThrow(/body/);
    });

    it('verifyEnvelope returns invalid when underlying crypto.verify throws', async () => {
        // Mock @coivitas/crypto's verify() to throw synchronously,
        // triggering the try/catch fallback at lines 290-295. That catch is the safety net for signature-layer exceptions
        // (e.g. an invalid public-key length, or an internal throw from @noble/curves), preventing the exception from escaping the call stack.
        vi.resetModules();
        vi.doMock('@coivitas/crypto', async () => {
            const actual = await vi.importActual<
                typeof import('@coivitas/crypto')
            >('@coivitas/crypto');
            return {
                ...actual,
                verify: () => {
                    throw new Error('mocked crypto failure');
                },
            };
        });
        try {
            const { sender, recipient } = createIdentities();
            const envelope = buildEnvelope({
                senderDid: sender.document.id,
                senderPrivateKey: sender.privateKey,
                recipientDid: recipient.document.id,
                sessionId: null,
                messageType: 'NEGOTIATION_REQUEST',
                body: { action: 'INQUIRY' },
            });
            // Reload the envelope module so it picks up the mocked verify.
            const { verifyEnvelope: verifyEnvelopeMocked } =
                await import('../envelope.js');
            const result = await verifyEnvelopeMocked(envelope, {
                resolvePublicKey: (did) =>
                    Promise.resolve(
                        did === sender.document.id
                            ? sender.document.publicKey
                            : null,
                    ),
                now: () => new Date(envelope.timestamp).getTime(),
            });
            expect(result.valid).toBe(false);
            expect(result.reason).toMatch(/Signature verification error/);
            expect(result.reason).toMatch(/mocked crypto failure/);
        } finally {
            vi.doUnmock('@coivitas/crypto');
            vi.resetModules();
        }
    });
});
