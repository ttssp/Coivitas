import { randomUUID } from 'node:crypto';

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
    HandshakeInitBody,
    HandshakeResponse,
    HandshakeResult,
    HandshakeResponderOptions,
    NonceStore,
} from './types.js';

class InMemoryNonceStore implements NonceStore {
    private readonly store = new Set<string>();

    claim(nonce: string, _: Date): Promise<boolean> {
        if (this.store.has(nonce)) return Promise.resolve(false);
        this.store.add(nonce);
        return Promise.resolve(true);
    }
}

/**
 * Handshake responder
 *
 * Flow:
 * 1. Verify the HANDSHAKE_INIT envelope signature (using resolvePublicKey)
 * 2. Verify challenge.expiresAt > now (not expired)
 * 3. Check whether the nonce has been seen before (replay protection)
 * 4. Call verifyInitiator(initiatorDid) (business-layer authorization)
 * 5. Generate a sessionId (UUID v4) + build the HandshakeResponse
 * 6. Build and sign the HANDSHAKE_ACK envelope
 * 7. Record the nonce in the nonceStore
 */
export class HandshakeResponder {
    private readonly responderDid: DID;
    private readonly responderPrivateKey: string;
    private readonly verifyInitiator: HandshakeResponderOptions['verifyInitiator'];
    private readonly resolvePublicKey: HandshakeResponderOptions['resolvePublicKey'];
    private readonly capabilities: string[];
    private readonly nonceStore: NonceStore;
    private readonly sessionStore: HandshakeResponderOptions['sessionStore'];
    private readonly authorizationValidator: HandshakeResponderOptions['authorizationValidator'];
    private readonly encryptionPreference: EncryptionPreference;
    private lastHandshakeResult: HandshakeResult | null = null;

    public constructor(options: HandshakeResponderOptions) {
        this.responderDid = options.responderDid;
        this.responderPrivateKey = options.responderPrivateKey;
        this.verifyInitiator = options.verifyInitiator;
        this.resolvePublicKey = options.resolvePublicKey;
        this.capabilities = options.capabilities ?? [];
        this.nonceStore = options.nonceStore ?? new InMemoryNonceStore();
        this.sessionStore = options.sessionStore;
        this.authorizationValidator = options.authorizationValidator;
        this.encryptionPreference = options.encryptionPreference ?? 'OFF';
    }

    /**
     * Processes the received HANDSHAKE_INIT envelope and returns a HANDSHAKE_ACK envelope
     *
     * @throws ProtocolError('SIGNATURE_INVALID', ...) if the INIT signature is invalid
     * @throws ProtocolError('INVALID_HANDSHAKE', ...) if the challenge format is invalid
     */
    public async respond(
        initEnvelope: NegotiationEnvelope,
    ): Promise<NegotiationEnvelope> {
        if (initEnvelope.messageType !== 'HANDSHAKE_INIT') {
            throw new ProtocolError(
                'INVALID_HANDSHAKE',
                `Expected HANDSHAKE_INIT, received ${initEnvelope.messageType}`,
            );
        }

        // Run the schema gate before signature verification
        // (parseEnvelope) + the handshake capability vocabulary check. The former triggers
        // the capabilityTokenRef specVersion gate; the latter acts as the runtime mirror of
        // the communication.schema.json initiatorCapabilities enum ban
        // — the communication package has no AJV path, so it must explicitly reject control-plane
        // actions such as SESSION_SUPERSEDED from appearing in handshake negotiation here.
        parseEnvelope(initEnvelope);

        // Call packages/types validateAgainstSchema('handshakeChallenge')
        // for a one-shot exhaustive check: required + type + format + pattern + enum + additionalProperties.
        // The schema already covers: challengeId(uuid) / initiatorDid(didAgent) / responderDid(didAgent)
        // / nonce(hash) / timestamp(ISO8601) / expiresAt(ISO8601) /
        // initiatorCapabilities(array of BUSINESS_ACTION_VOCABULARY enum).
        // Business-layer rules not covered by the schema (error message containing the
        // SESSION_SUPERSEDED literal) wrap the error message via a secondary vocabulary check.
        const body = initEnvelope.body as unknown as HandshakeInitBody;
        const challenge = body?.challenge;
        const challengeValidation = validateAgainstSchema(
            challenge,
            'handshakeChallenge',
        );
        if (!challengeValidation.valid) {
            const firstError = challengeValidation.errors[0];
            const path = firstError?.instancePath ?? '/';
            // Business-layer error message wrap: when the schema hits an enum failure
            // on an initiatorCapabilities array element, pull the actual out-of-range value
            // from the challenge and emit a friendly error message containing the SESSION_SUPERSEDED literal.
            // This is a diagnostic layer on top of the schema, not a redundant check (the schema remains the exhaustive source).
            const enumMatch = /^\/initiatorCapabilities\/(\d+)$/.exec(path);
            if (enumMatch && firstError?.keyword === 'enum') {
                const idx = Number(enumMatch[1]);
                const offendingCap = (
                    challenge as { initiatorCapabilities?: unknown[] }
                ).initiatorCapabilities?.[idx];
                throw new ProtocolError(
                    'INVALID_HANDSHAKE',
                    `initiatorCapabilities contains the forbidden value "${String(offendingCap)}"; ` +
                        `only allowed: ${HANDSHAKE_CAPABILITY_VOCABULARY.join(', ')}`,
                );
            }
            throw new ProtocolError(
                'INVALID_HANDSHAKE',
                `challenge schema validation failed ${path}: ${firstError?.message ?? 'unknown'}`,
            );
        }

        const verification = await verifyEnvelope(initEnvelope, {
            resolvePublicKey: this.resolvePublicKey,
        });

        if (!verification.valid) {
            throw new ProtocolError(
                'SIGNATURE_INVALID',
                `HANDSHAKE_INIT signature verification failed: ${verification.reason}`,
            );
        }

        // The schema already enforces challenge.challengeId / nonce / expiresAt / responderDid /
        // initiatorDid as required + format validation (uuid / hash / ISO8601 / didAgent);
        // the old "!challenge || !challengeId || !nonce || !expiresAt" degenerate check has been
        // replaced by the schema. What still needs an inline check is identity-binding consistency:
        // challenge.initiatorDid must equal envelope.header.senderDid (this is a business-layer
        // cross-field invariant that a standalone schema def cannot express).
        if (challenge.initiatorDid !== initEnvelope.header.senderDid) {
            throw new ProtocolError(
                'INVALID_HANDSHAKE',
                'challenge.initiatorDid does not match envelope.header.senderDid',
            );
        }

        if (challenge.responderDid !== this.responderDid) {
            throw new ProtocolError(
                'INVALID_HANDSHAKE',
                'challenge.responderDid does not match the current responderDid',
            );
        }

        if (new Date(challenge.expiresAt).getTime() <= Date.now()) {
            return this.buildAck(
                initEnvelope.header.senderDid,
                challenge,
                'Challenge expired',
            );
        }

        const initiatorDid = initEnvelope.header.senderDid;
        const accepted = await this.verifyInitiator(initiatorDid);

        if (!accepted) {
            return this.buildAck(initiatorDid, challenge, 'Initiator not authorized');
        }

        // claim() consumes the nonce slot only after authorization passes, preventing unauthorized parties from polluting the nonce store
        const claimed = await this.nonceStore.claim(
            challenge.nonce,
            new Date(challenge.expiresAt),
        );

        if (!claimed) {
            return this.buildAck(
                initiatorDid,
                challenge,
                'Duplicate nonce (suspected replay attack)',
            );
        }

        const sessionId = randomUUID();
        const negotiatedCapabilities = challenge.initiatorCapabilities.filter(
            (cap) => this.capabilities.includes(cap),
        );

        // HAV validation + session persistence (only takes effect when injected; without injection, behavior matches the baseline path)
        let validatedPrincipalDid: DID = challenge.principalDid ?? initiatorDid;
        let validatedCapabilityTokenId: string | null =
            challenge.capabilityTokenId ?? null;
        let validatedCapabilityTokenFingerprint: string | null = null;

        if (this.authorizationValidator) {
            const havResult = await this.authorizationValidator.validate({
                initiatorDid,
                principalDid: validatedPrincipalDid,
                capabilityTokenId: validatedCapabilityTokenId,
            });
            if (!havResult.accepted) {
                return this.buildAck(initiatorDid, challenge, 'Authorization validation failed');
            }
            // Consistency fix:
            // the initiator side rebuilds the transcript with challenge.principalDid / capabilityTokenId,
            // the responder side uses the HAV return values; by default the two are equal (HAV row 4 SHOULD), but if
            // the L3 HAV implementation performs canonicalization / correction, the two sides' transcripts diverge.
            // Fail-closed here: HAV output inconsistent with the challenge → reject the handshake.
            // (The challenge body is already covered by the envelope signature, so there is no silent divergence between the challenge and the HAV input.)
            if (
                havResult.principalDid !== validatedPrincipalDid ||
                havResult.capabilityTokenId !== validatedCapabilityTokenId
            ) {
                return this.buildAck(
                    initiatorDid,
                    challenge,
                    'Authorization fields inconsistent with the challenge (post-HAV values diverge from the challenge input)',
                );
            }
            validatedPrincipalDid = havResult.principalDid;
            validatedCapabilityTokenId = havResult.capabilityTokenId;
            validatedCapabilityTokenFingerprint =
                havResult.capabilityTokenFingerprint;
        }

        // ─── 12-row compatibility matrix ───────────────────────────────────────
        // Input: challenge.encryption (default = initiatorPreference OFF) + this.encryptionPreference
        // Output: negotiatedMode + optional responderEphemeralPublicKey + derivedKeys
        const initiatorEncryption = challenge.encryption;
        const initiatorPreference: EncryptionPreference =
            initiatorEncryption?.preference ?? 'OFF';
        const responderPreference = this.encryptionPreference;

        // Invariant 11: the following combinations are impossible wire states and must be rejected
        // Row 3: no challenge.encryption + responder REQUIRED → ENCRYPTION_REQUIRED
        // Row 8: REQUIRED initiator + responder OFF → ENCRYPTION_REQUIRED
        if (
            (initiatorPreference === 'OFF' &&
                responderPreference === 'REQUIRED') ||
            (initiatorPreference === 'REQUIRED' &&
                responderPreference === 'OFF')
        ) {
            throw new ProtocolError(
                'ENCRYPTION_REQUIRED',
                `Encryption negotiation failed: initiator=${initiatorPreference} responder=${responderPreference}`,
            );
        }

        // Row 9/11: REQUIRED initiator or REQUIRED responder + null tokenId → reject
        // A capabilityToken is required only when either side forces encryption
        const encryptionWouldBeRequired =
            initiatorPreference === 'REQUIRED' ||
            responderPreference === 'REQUIRED';
        if (encryptionWouldBeRequired && validatedCapabilityTokenId === null) {
            throw new ProtocolError(
                'ENCRYPTION_REQUIRES_CAPABILITY_TOKEN',
                'Encryption mode requires a capabilityToken, but the current request carries no valid token',
            );
        }

        // fail-closed fix:
        // When negotiation is REQUIRED + capabilityTokenId is non-null, HAV must return a non-empty fingerprint;
        // otherwise the responder persists ACTIVE/REQUIRED while the initiator wire lacks the fingerprint
        // and must fail-closed → the two sides split, orphan sessions form, and the resume/revoke path is polluted.
        // Fail-closed before computing transcript / sessionStore.create.
        if (
            encryptionWouldBeRequired &&
            validatedCapabilityTokenId !== null &&
            (!validatedCapabilityTokenFingerprint ||
                validatedCapabilityTokenFingerprint.length === 0)
        ) {
            throw new ProtocolError(
                'ENCRYPTION_REQUIRES_CAPABILITY_TOKEN',
                'Encryption mode requires a capabilityToken fingerprint: HAV returned a non-null tokenId but an empty fingerprint',
            );
        }

        // Negotiation result:
        // OFF + OFF / OPT_IN → OFF (rows 1,2,4,5)
        // OPT_IN + REQUIRED (row 6 - OPT_IN upgrades to REQUIRED) → REQUIRED
        // REQUIRED + OPT_IN (row 10) → REQUIRED
        // REQUIRED + REQUIRED (row 12) → REQUIRED
        const negotiatedMode: 'OFF' | 'REQUIRED' =
            initiatorPreference === 'REQUIRED' ||
            responderPreference === 'REQUIRED'
                ? 'REQUIRED'
                : 'OFF';

        // Encryption result construction
        let responderEphemeralPublicKeyHex: string | undefined;
        let derivedKeys:
            | {
                  initiatorEphemeralPublicKeyHex: string;
                  responderEphemeralPublicKeyHex: string;
                  transcriptHash: Uint8Array;
              }
            | undefined;

        const responseTimestamp = new Date().toISOString() as Timestamp;

        if (negotiatedMode === 'REQUIRED') {
            // Generate the Responder ephemeral key pair (the private key must not be persisted)
            const rKeyPair = generateEphemeralX25519KeyPair();
            responderEphemeralPublicKeyHex = toHex(rKeyPair.publicKey);

            // The Initiator public key is already in challenge.encryption (must exist when REQUIRED)
            const iEphemeralPubKeyHex =
                initiatorEncryption!.initiatorEphemeralPublicKey;
            const iEphemeralPubKey = fromHex(iEphemeralPubKeyHex);

            // Small-subgroup attack defense: reject an all-zero public key
            if (iEphemeralPubKey.every((b) => b === 0)) {
                throw new ProtocolError(
                    'INVALID_ENCRYPTION_OFFER',
                    'initiatorEphemeralPublicKey is all zeros, suspected small-subgroup attack',
                );
            }

            const sharedSecret = computeX25519SharedSecret(
                rKeyPair.secretKey,
                iEphemeralPubKey,
            );

            // transcript_hash 16 fields
            const transcriptHash = computeTranscriptHash({
                protocolVersion: 'ap/e2e/v1',
                initiatorDid: challenge.initiatorDid,
                responderDid: this.responderDid,
                initiatorCapabilities: challenge.initiatorCapabilities,
                responderCapabilities: negotiatedCapabilities,
                initiatorPreference,
                responderPreference,
                negotiatedEncryptionMode: negotiatedMode,
                I_epk: iEphemeralPubKeyHex,
                R_epk: responderEphemeralPublicKeyHex,
                nonce: challenge.nonce,
                initTimestamp: challenge.timestamp,
                responseTimestamp,
                authorizedPrincipalDid: validatedPrincipalDid,
                authorizedTokenId: validatedCapabilityTokenId,
                authorizedTokenFingerprint:
                    validatedCapabilityTokenFingerprint ?? '',
            });

            // Derive session keys (for use by the upper-layer SessionCryptoHandle)
            const sessionDerivedKeys = deriveSessionKeys(
                sharedSecret,
                transcriptHash,
            );
            void sessionDerivedKeys; // for now, only the raw material is returned to upper layers

            derivedKeys = {
                initiatorEphemeralPublicKeyHex: iEphemeralPubKeyHex,
                responderEphemeralPublicKeyHex,
                transcriptHash,
            };
        }

        // ─── Build transcriptHashConfirmation ─────────────────────────────────
        // Regardless of negotiatedMode, the response always includes the encryption structure (the negotiation result may be OFF)
        // but transcriptHashConfirmation only has substantive content when REQUIRED; for OFF it is filled with an empty-string placeholder
        // (the encryption field may be omitted when OFF, but it is kept here for response consistency)
        const encryptionForResponse =
            negotiatedMode === 'REQUIRED' && derivedKeys
                ? {
                      negotiatedMode: 'REQUIRED' as const,
                      responderPreference,
                      responderEphemeralPublicKey:
                          responderEphemeralPublicKeyHex,
                      encryptionProtocolVersion: 'ap/e2e/v1' as const,
                      // Take the first 16 bytes of transcript_hash = 32 hex chars
                      transcriptHashConfirmation: toHex(
                          derivedKeys.transcriptHash.slice(0, 16),
                      ),
                      // Only when capabilityTokenId !== null (HAV already returned a non-empty fingerprint)
                      // write it to the wire so the initiator can rebuild the 16th transcript field consistently;
                      // when capabilityTokenId === null the fingerprint is null/empty, so omit the field.
                      ...(validatedCapabilityTokenFingerprint
                          ? {
                                authorizedTokenFingerprint:
                                    validatedCapabilityTokenFingerprint,
                            }
                          : {}),
                  }
                : initiatorPreference !== 'OFF'
                  ? {
                        // The initiator initiated negotiation (OPT_IN), but the responder downgraded to OFF
                        negotiatedMode: 'OFF' as const,
                        responderPreference,
                        encryptionProtocolVersion: 'ap/e2e/v1' as const,
                        transcriptHashConfirmation: '',
                    }
                  : undefined;

        if (this.sessionStore) {
            try {
                // Pass encryptionState so the session metadata
                // reflects the true negotiation result. Before the fix it defaulted to 'OFF', causing
                // EncryptionSessionMetaService.isEncryptedSession() / aggregateByDidPair()
                // to misclassify an encrypted session as plaintext.
                // sessionKeyFingerprint is written later when the upper-layer SessionRegistry registers after the handshake completes
                // (in-memory-store accepts REQUIRED + null fingerprint, filled by update after rekey).
                await this.sessionStore.create({
                    sessionId,
                    initiatorDid,
                    responderDid: this.responderDid,
                    principalDid: validatedPrincipalDid,
                    capabilityTokenId: validatedCapabilityTokenId ?? undefined,
                    capabilityTokenFingerprint:
                        validatedCapabilityTokenFingerprint ?? undefined,
                    negotiatedCapabilities,
                    initialState: 'ACTIVE',
                    encryptionState:
                        negotiatedMode === 'REQUIRED' ? 'REQUIRED' : 'OFF',
                });
            } catch {
                return this.buildAck(initiatorDid, challenge, 'Session persistence failed');
            }
        }

        this.lastHandshakeResult = {
            sessionId,
            negotiatedCapabilities,
            ...(derivedKeys
                ? { encryption: { negotiatedMode: 'REQUIRED', derivedKeys } }
                : {}),
        };

        const response: HandshakeResponse = {
            challengeId: challenge.challengeId,
            sessionId,
            responderDid: this.responderDid,
            responderCapabilities: negotiatedCapabilities,
            nonce: challenge.nonce,
            timestamp: responseTimestamp,
            ...(encryptionForResponse
                ? { encryption: encryptionForResponse }
                : {}),
        };

        return buildEnvelope({
            senderDid: this.responderDid,
            senderPrivateKey: this.responderPrivateKey,
            recipientDid: initiatorDid,
            sessionId,
            messageType: 'HANDSHAKE_ACK',
            body: { response, accepted: true },
        });
    }

    /** Returns the result of the most recent successful handshake*/
    public getLastHandshakeResult(): HandshakeResult | null {
        return this.lastHandshakeResult;
    }

    private buildAck(
        recipientDid: DID,
        challenge: HandshakeChallenge,
        reason?: string,
    ): NegotiationEnvelope {
        const response: HandshakeResponse = {
            challengeId: challenge.challengeId,
            sessionId: '',
            responderDid: this.responderDid,
            responderCapabilities: [],
            nonce: challenge.nonce,
            timestamp: new Date().toISOString() as Timestamp,
        };

        return buildEnvelope({
            senderDid: this.responderDid,
            senderPrivateKey: this.responderPrivateKey,
            recipientDid,
            sessionId: null,
            messageType: 'HANDSHAKE_ACK',
            body: { response, accepted: false, ...(reason ? { reason } : {}) },
        });
    }
}
