import { randomUUID, randomBytes } from 'node:crypto';

import type {
    DID,
    NegotiationEnvelope,
    Timestamp,
} from '@coivitas/types';
import {
    HANDSHAKE_CAPABILITY_VOCABULARY,
    ProtocolError,
    validateAgainstSchema,
} from '@coivitas/types';
import {
    computeTranscriptHash,
    computeX25519SharedSecret,
    deriveSessionKeys,
    fromHex,
    generateEphemeralX25519KeyPair,
    toHex,
} from '@coivitas/crypto';

import { buildEnvelope, parseEnvelope, verifyEnvelope } from '../envelope.js';
import type {
    EncryptionPreference,
    HandshakeChallenge,
    HandshakeAckBody,
    HandshakeResult,
    HandshakeInitiatorOptions,
    InitiateParams,
} from './types.js';

/**
 * Handshake initiator
 *
 * Flow:
 * 1. Generate a HandshakeChallenge (with a random nonce + expiresAt)
 * 2. Build and sign the HANDSHAKE_INIT envelope
 * 3. Send it to responderEndpoint via transport.send()
 * 4. Parse the received HANDSHAKE_ACK envelope
 * 5. Verify the ACK signature + nonce consistency
 * 6. Return sessionId + negotiatedCapabilities
 */
export class HandshakeInitiator {
    private readonly initiatorDid: DID;
    private readonly initiatorPrivateKey: string;
    private readonly transport: HandshakeInitiatorOptions['transport'];
    private readonly resolvePublicKey: HandshakeInitiatorOptions['resolvePublicKey'];
    private readonly challengeExpiryMs: number;
    private readonly capabilities: string[];
    private readonly maxRetries: number;
    private readonly encryptionPreference: EncryptionPreference;
    private readonly pendingChallenges: Map<
        string,
        {
            nonce: string;
            iEphemeralSecretKey?: Uint8Array;
            iEphemeralPublicKeyHex?: string;
        }
    > = new Map();

    public constructor(options: HandshakeInitiatorOptions) {
        this.initiatorDid = options.initiatorDid;
        this.initiatorPrivateKey = options.initiatorPrivateKey;
        this.transport = options.transport;
        this.resolvePublicKey = options.resolvePublicKey;
        this.challengeExpiryMs = options.challengeExpiryMs ?? 60_000;
        this.capabilities = options.capabilities ?? [];
        this.maxRetries = options.maxRetries ?? 2;
        this.encryptionPreference = options.encryptionPreference ?? 'OFF';
    }

    /**
     * Initiates a handshake to the responder, retrying automatically on failure (only for HANDSHAKE_TIMEOUT)
     *
     * @throws ProtocolError('HANDSHAKE_REJECTED', ...) if the peer rejects (no retry)
     * @throws ProtocolError('HANDSHAKE_TIMEOUT', ...) if all retries time out
     * @throws ProtocolError('INVALID_HANDSHAKE', ...) if the nonce does not match or the signature is invalid
     */
    public async initiate(params: InitiateParams): Promise<HandshakeResult> {
        let lastError: ProtocolError | undefined;
        const attemptsTotal = 1 + this.maxRetries;

        for (let attempt = 0; attempt < attemptsTotal; attempt++) {
            try {
                return await this.attemptHandshake(params);
            } catch (error) {
                if (
                    error instanceof ProtocolError &&
                    error.code === 'HANDSHAKE_TIMEOUT' &&
                    attempt < attemptsTotal - 1
                ) {
                    lastError = error;
                    continue;
                }
                throw error;
            }
        }

        throw lastError!;
    }

    /**
     * A single handshake attempt; cleans up pendingChallenges in finally
     */
    private async attemptHandshake(
        params: InitiateParams,
    ): Promise<HandshakeResult> {
        const nonce = randomBytes(32).toString('hex');
        const now = new Date();
        const expiresAt = new Date(now.getTime() + this.challengeExpiryMs);
        const challengeId = randomUUID();

        // If OPT_IN or REQUIRED, pre-generate the Initiator ephemeral X25519 key pair
        // The private key is held in pendingChallenges (in-memory, not persisted)
        let iEphemeralSecretKey: Uint8Array | undefined;
        let iEphemeralPublicKeyHex: string | undefined;
        if (this.encryptionPreference !== 'OFF') {
            const kp = generateEphemeralX25519KeyPair();
            iEphemeralSecretKey = kp.secretKey;
            iEphemeralPublicKeyHex = toHex(kp.publicKey);
        }

        // Register the challenge to track the in-flight handshake (including ephemeral key material)
        this.pendingChallenges.set(challengeId, {
            nonce,
            iEphemeralSecretKey,
            iEphemeralPublicKeyHex,
        });

        try {
            const challenge: HandshakeChallenge = {
                challengeId,
                initiatorDid: this.initiatorDid,
                responderDid: params.responderDid,
                nonce,
                timestamp: now.toISOString() as Timestamp,
                expiresAt: expiresAt.toISOString() as Timestamp,
                initiatorCapabilities: this.capabilities,
                // Pass through principalDid / capabilityTokenId to the challenge
                // (the responder REQUIRED rows need these two fields, otherwise ENCRYPTION_REQUIRES_CAPABILITY_TOKEN is thrown)
                ...(params.principalDid !== undefined
                    ? { principalDid: params.principalDid }
                    : {}),
                ...(params.capabilityTokenId !== undefined
                    ? { capabilityTokenId: params.capabilityTokenId }
                    : {}),
                // If OPT_IN or REQUIRED, carry the encryption field
                ...(this.encryptionPreference !== 'OFF' &&
                iEphemeralPublicKeyHex
                    ? {
                          encryption: {
                              preference: this.encryptionPreference,
                              initiatorEphemeralPublicKey:
                                  iEphemeralPublicKeyHex,
                              encryptionProtocolVersion: 'ap/e2e/v1' as const,
                          },
                      }
                    : {}),
            };

            const initEnvelope = buildEnvelope({
                senderDid: this.initiatorDid,
                senderPrivateKey: this.initiatorPrivateKey,
                recipientDid: params.responderDid,
                sessionId: null,
                messageType: 'HANDSHAKE_INIT',
                body: { challenge },
            });

            const timeoutMs = params.timeoutMs ?? 30_000;
            let ackEnvelope: NegotiationEnvelope | null;
            let timeoutHandle: ReturnType<typeof setTimeout> | undefined;

            // Sentinel object: resolve this value on timeout to avoid leaking a Promise rejection (fake-timer friendly)
            const TIMEOUT_SENTINEL = Symbol('HANDSHAKE_TIMEOUT');

            try {
                const timeoutPromise = new Promise<typeof TIMEOUT_SENTINEL>(
                    (resolve) =>
                        (timeoutHandle = setTimeout(
                            () => resolve(TIMEOUT_SENTINEL),
                            timeoutMs,
                        )),
                );

                const raceResult = await Promise.race([
                    this.transport.send(initEnvelope, params.responderEndpoint),
                    timeoutPromise,
                ]);

                if (raceResult === TIMEOUT_SENTINEL) {
                    throw new ProtocolError(
                        'HANDSHAKE_TIMEOUT',
                        `Handshake timed out (${timeoutMs}ms)`,
                    );
                }

                ackEnvelope = raceResult;
            } catch (error) {
                if (error instanceof ProtocolError) {
                    throw error;
                }
                throw new ProtocolError(
                    'HANDSHAKE_TIMEOUT',
                    `Handshake transport failed: ${error instanceof Error ? error.message : String(error)}`,
                );
            } finally {
                if (timeoutHandle) {
                    clearTimeout(timeoutHandle);
                }
            }

            if (!ackEnvelope) {
                throw new ProtocolError('INVALID_HANDSHAKE', 'Handshake ACK is empty');
            }

            const parsed = parseEnvelope(ackEnvelope);
            const verification = await verifyEnvelope(parsed, {
                resolvePublicKey: this.resolvePublicKey,
            });

            if (parsed.messageType !== 'HANDSHAKE_ACK') {
                throw new ProtocolError(
                    'INVALID_HANDSHAKE',
                    `Expected HANDSHAKE_ACK, received ${parsed.messageType}`,
                );
            }

            if (!verification.valid) {
                throw new ProtocolError(
                    'SIGNATURE_INVALID',
                    `HANDSHAKE_ACK signature verification failed: ${verification.reason ?? 'unknown'}`,
                );
            }

            if (parsed.header.senderDid !== params.responderDid) {
                throw new ProtocolError(
                    'INVALID_HANDSHAKE',
                    `ACK sender ${parsed.header.senderDid} does not match the expected responderDid ${params.responderDid}`,
                );
            }

            const ackBody = parsed.body as unknown as HandshakeAckBody;

            // Call packages/types validateAgainstSchema('handshakeAckBody')
            // for a one-shot exhaustive check of the overall ackBody shape:
            // - required: accepted (boolean) + response (handshakeResponse)
            // - the response sub-object schema enforces challengeId(uuid) / sessionId /
            // responderDid(didAgent) / responderCapabilities(business action enum) /
            // nonce(hash) / timestamp(ISO8601)
            // - if/then conditional branch: accepted=true → response.sessionId minLength≥1
            // (prevents sessionId='' from making the initiator believe a session was established)
            // Business-layer rules not covered by the schema (error message containing the
            // SESSION_SUPERSEDED literal) wrap the error message via a secondary vocabulary check.
            const ackBodyValidation = validateAgainstSchema(
                ackBody,
                'handshakeAckBody',
            );
            if (!ackBodyValidation.valid) {
                const firstError = ackBodyValidation.errors[0];
                const path = firstError?.instancePath ?? '/';
                // Business-layer error message wrap: when the schema hits an enum
                // failure on a response.responderCapabilities array element, pull the
                // actual out-of-range value from ackBody and emit a friendly error
                // message containing the SESSION_SUPERSEDED literal.
                const enumMatch =
                    /^\/response\/responderCapabilities\/(\d+)$/.exec(path);
                if (enumMatch && firstError?.keyword === 'enum') {
                    const idx = Number(enumMatch[1]);
                    const offendingCap = (
                        ackBody as {
                            response?: { responderCapabilities?: unknown[] };
                        }
                    ).response?.responderCapabilities?.[idx];
                    throw new ProtocolError(
                        'INVALID_HANDSHAKE',
                        `responderCapabilities contains the forbidden value "${String(offendingCap)}"; ` +
                            `only allowed: ${HANDSHAKE_CAPABILITY_VOCABULARY.join(', ')}`,
                    );
                }
                throw new ProtocolError(
                    'INVALID_HANDSHAKE',
                    `ACK body schema validation failed ${path}: ${firstError?.message ?? 'unknown'}`,
                );
            }

            if (!ackBody.accepted) {
                throw new ProtocolError(
                    'HANDSHAKE_REJECTED',
                    ackBody.reason ?? 'Peer rejected the handshake',
                );
            }

            if (ackBody.response.nonce !== nonce) {
                throw new ProtocolError(
                    'INVALID_HANDSHAKE',
                    'The nonce in the ACK does not match the challenge',
                );
            }

            if (ackBody.response.challengeId !== challengeId) {
                throw new ProtocolError(
                    'INVALID_HANDSHAKE',
                    'The challengeId in the ACK does not match the challenge that was sent',
                );
            }

            if (ackBody.response.responderDid !== params.responderDid) {
                throw new ProtocolError(
                    'INVALID_HANDSHAKE',
                    'The responderDid in the ACK does not match the target responderDid',
                );
            }

            const negotiatedCapabilities =
                ackBody.response.responderCapabilities.filter((cap) =>
                    this.capabilities.includes(cap),
                );

            // Encrypted handshake result verification
            const pending = this.pendingChallenges.get(challengeId);
            const respEncryption = ackBody.response.encryption;

            let encryptionResult:
                | {
                      negotiatedMode: 'OFF' | 'REQUIRED';
                      derivedKeys?: {
                          initiatorEphemeralPublicKeyHex: string;
                          responderEphemeralPublicKeyHex: string;
                          transcriptHash: Uint8Array;
                      };
                  }
                | undefined;

            if (
                pending?.iEphemeralSecretKey &&
                pending.iEphemeralPublicKeyHex
            ) {
                // This side initiated encryption negotiation
                const negotiatedMode = respEncryption?.negotiatedMode ?? 'OFF';

                if (negotiatedMode === 'REQUIRED') {
                    // Responder agreed to encryption: verify transcriptHashConfirmation
                    const rEphemeralPubKeyHex =
                        respEncryption?.responderEphemeralPublicKey;
                    if (!rEphemeralPubKeyHex) {
                        throw new ProtocolError(
                            'INVALID_HANDSHAKE',
                            'responder declared REQUIRED but did not provide responderEphemeralPublicKey',
                        );
                    }
                    if (!respEncryption?.transcriptHashConfirmation) {
                        throw new ProtocolError(
                            'INVALID_HANDSHAKE',
                            'responder declared REQUIRED but did not provide transcriptHashConfirmation',
                        );
                    }

                    // When negotiatedMode='REQUIRED' and challenge.capabilityTokenId !== null,
                    // the wire must carry authorizedTokenFingerprint; a missing one is treated as a
                    // protocol violation (the "both-empty-or-both-non-empty contract").
                    const challengeHasToken =
                        challenge.capabilityTokenId !== null &&
                        challenge.capabilityTokenId !== undefined;
                    if (
                        challengeHasToken &&
                        !respEncryption.authorizedTokenFingerprint
                    ) {
                        throw new ProtocolError(
                            'INVALID_HANDSHAKE',
                            'responder declared REQUIRED and challenge contains capabilityTokenId but did not provide authorizedTokenFingerprint',
                        );
                    }

                    const rEphemeralPubKey = fromHex(rEphemeralPubKeyHex);
                    const sharedSecret = computeX25519SharedSecret(
                        pending.iEphemeralSecretKey,
                        rEphemeralPubKey,
                    );

                    // This side rebuilds transcript_hash (16 fields)
                    // requires ackBody.response.timestamp as responseTimestamp
                    const localTranscriptHash = computeTranscriptHash({
                        protocolVersion: 'ap/e2e/v1',
                        initiatorDid: this.initiatorDid,
                        responderDid: params.responderDid,
                        initiatorCapabilities: this.capabilities,
                        responderCapabilities: negotiatedCapabilities,
                        initiatorPreference: this.encryptionPreference,
                        responderPreference: respEncryption.responderPreference,
                        negotiatedEncryptionMode: negotiatedMode,
                        I_epk: pending.iEphemeralPublicKeyHex,
                        R_epk: rEphemeralPubKeyHex,
                        nonce,
                        initTimestamp: challenge.timestamp,
                        responseTimestamp: ackBody.response.timestamp,
                        // For the initiator, authorizedPrincipalDid / authorizedTokenId
                        // are taken from the challenge (same source as the responder HAV.validate input;
                        // the HAV row 4 SHOULD equality already ensures the validator return value matches the challenge)
                        authorizedPrincipalDid:
                            challenge.principalDid ?? this.initiatorDid,
                        authorizedTokenId: challenge.capabilityTokenId ?? null,
                        // fingerprint comes from the wire (written back from the responder HAV output)
                        // In the missing case (capabilityTokenId === null or negotiatedMode='OFF'),
                        // falling back to an empty string aligns with "null token → empty fingerprint".
                        authorizedTokenFingerprint:
                            respEncryption.authorizedTokenFingerprint ?? '',
                    });

                    // Verify the first 16 bytes (32 hex chars)
                    const localConfirmation = toHex(
                        localTranscriptHash.slice(0, 16),
                    );
                    if (
                        localConfirmation !==
                        respEncryption.transcriptHashConfirmation
                    ) {
                        throw new ProtocolError(
                            'ENCRYPTION_DOWNGRADE_DETECTED',
                            `transcript_hash confirmation mismatch: expected ${localConfirmation}, received ${respEncryption.transcriptHashConfirmation}`,
                        );
                    }

                    // Derive session keys
                    const sessionDerivedKeys = deriveSessionKeys(
                        sharedSecret,
                        localTranscriptHash,
                    );
                    void sessionDerivedKeys; // for use by upper layers

                    encryptionResult = {
                        negotiatedMode: 'REQUIRED',
                        derivedKeys: {
                            initiatorEphemeralPublicKeyHex:
                                pending.iEphemeralPublicKeyHex,
                            responderEphemeralPublicKeyHex: rEphemeralPubKeyHex,
                            transcriptHash: localTranscriptHash,
                        },
                    };
                } else {
                    // Negotiation result OFF (responder downgraded)
                    encryptionResult = { negotiatedMode: 'OFF' };

                    // If this side is REQUIRED but the responder downgraded to OFF, treat it as a rejection
                    // but here the responder already sent accepted=true; defensive check
                    if (this.encryptionPreference === 'REQUIRED') {
                        throw new ProtocolError(
                            'ENCRYPTION_REQUIRED',
                            'This side requires encryption but the peer negotiated OFF',
                        );
                    }
                }
            }

            return {
                sessionId: ackBody.response.sessionId,
                negotiatedCapabilities,
                ...(encryptionResult ? { encryption: encryptionResult } : {}),
            };
        } finally {
            // Whether it succeeds or fails, clean up the in-flight challenge record (including the ephemeral private key)
            this.pendingChallenges.delete(challengeId);
        }
    }
}
