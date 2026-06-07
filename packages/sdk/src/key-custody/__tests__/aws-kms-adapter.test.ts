/**
 * AwsKmsAdapter unit tests
 *
 * Coverage:
 *   - KMSError construction + properties (code / retryable / cause)
 *   - mapAwsError across all error-code paths (triggered via AwsKmsAdapter)
 *   - withTimeout timeout path
 *   - AwsKmsAdapter.generateKey / sign / decrypt / getKeyMetadata happy paths
 *   - AwsKmsAdapter error paths (each KMSErrorCode)
 *
 * Mocking strategy:
 *   - Inject an AwsKmsClientPort mock (without instantiating the AWS SDK)
 *   - mock.send() returns Promise.resolve(<mock_response>) or Promise.reject(<aws_error>)
 *
 */

import { describe, it, expect, vi } from 'vitest';
import { AwsKmsAdapter, makeTestCommandFactory } from '../aws-kms-adapter.js';
import type { AwsKmsClientPort } from '../aws-kms-adapter.js';
import { KMSError } from '../types.js';

// ── Mock AwsKmsClientPort ─────────────────────────────────────────────────────

/**
 * Build a mock client + inject makeTestCommandFactory()
 *
 * All tests inject makeTestCommandFactory() via commandFactory,
 * preventing AwsKmsAdapter from attempting to dynamically import @aws-sdk/client-kms (not installed; test environment).
 * makeTestCommandFactory returns a plain object, and mock client.send() accepts unknown.
 */
function makeMockClient(
    sendImpl: (command: unknown) => unknown,
): AwsKmsClientPort {
    // Wrap sendImpl: allow a synchronous throw or synchronous return value, uniformly converted to Promise<unknown>
    // options (including abortSignal) is accepted but ignored by the test mock (behavior is controlled by sendImpl)
    return { send: (cmd, _options) => Promise.resolve(sendImpl(cmd)) };
}

// ── KMSError unit ─────────────────────────────────────────────────────────────

describe('KMSError', () => {
    it('should construct with correct code and retryable when non-retryable', () => {
        const err = new KMSError({
            code: 'KMS_AUTH_FAILED',
            message: 'test auth failure',
            retryable: false,
        });
        expect(err.code).toBe('KMS_AUTH_FAILED');
        expect(err.retryable).toBe(false);
        expect(err.message).toBe('test auth failure');
        expect(err.name).toBe('KMSError');
        expect(err).toBeInstanceOf(KMSError);
        expect(err).toBeInstanceOf(Error);
    });

    it('should construct with retryable=true and cause when retryable', () => {
        const cause = new Error('underlying network error');
        const err = new KMSError({
            code: 'KMS_THROTTLED',
            message: 'throttled',
            retryable: true,
            cause,
        });
        expect(err.code).toBe('KMS_THROTTLED');
        expect(err.retryable).toBe(true);
        expect(err.cause).toBe(cause);
    });

    it('should have undefined cause when not provided', () => {
        const err = new KMSError({
            code: 'KMS_UNKNOWN',
            message: 'unknown',
            retryable: false,
        });
        expect(err.cause).toBeUndefined();
    });
});

// ── AwsKmsAdapter.generateKey ─────────────────────────────────────────────────

describe('AwsKmsAdapter.generateKey', () => {
    it('should return GenerateKeyResult on successful CreateKey response', async () => {
        const creationDate = new Date('2026-05-10T00:00:00Z');
        const mock = makeMockClient(() => ({
            KeyMetadata: {
                KeyId: 'test-key-id-001',
                KeyState: 'Enabled',
                CreationDate: creationDate,
                KeySpec: 'ECC_NIST_P256',
                Description: 'test key',
            },
        }));
        const adapter = new AwsKmsAdapter({
            awsKmsClient: mock,
            commandFactory: makeTestCommandFactory(),
        });

        const result = await adapter.generateKey({
            algorithm: 'ECDSA_P256',
            description: 'test key',
        });

        expect(result.keyId).toBe('test-key-id-001');
        expect(result.createdAt).toBe('2026-05-10T00:00:00.000Z');
        expect(result.metadata.keyId).toBe('test-key-id-001');
        expect(result.metadata.state).toBe('ENABLED');
        expect(result.metadata.algorithm).toBe('ECDSA_P256');
        expect(result.metadata.providerMetadata?.['provider']).toBe('aws-kms');
    });

    it('should throw KMSError(KMS_PROTOCOL_ERROR) when KeyId is missing', async () => {
        const mock = makeMockClient(() => ({
            KeyMetadata: {
                KeyState: 'Enabled',
            },
        }));
        const adapter = new AwsKmsAdapter({
            awsKmsClient: mock,
            commandFactory: makeTestCommandFactory(),
        });

        await expect(
            adapter.generateKey({ algorithm: 'ECDSA_P256' }),
        ).rejects.toMatchObject({
            code: 'KMS_PROTOCOL_ERROR',
            retryable: false,
        });
    });

    it('should throw KMSError(KMS_AUTH_FAILED retryable=false) on AccessDeniedException', async () => {
        const mock = makeMockClient(() => {
            const err = Object.assign(new Error('Access denied'), {
                name: 'AccessDeniedException',
            });
            throw err;
        });
        const adapter = new AwsKmsAdapter({
            awsKmsClient: mock,
            commandFactory: makeTestCommandFactory(),
        });

        await expect(
            adapter.generateKey({ algorithm: 'ECDSA_P256' }),
        ).rejects.toMatchObject({ code: 'KMS_AUTH_FAILED', retryable: false });
    });

    it('should throw KMSError(KMS_THROTTLED retryable=true) on ThrottlingException', async () => {
        const mock = makeMockClient(() => {
            throw Object.assign(new Error('Throttled'), {
                name: 'ThrottlingException',
            });
        });
        const adapter = new AwsKmsAdapter({
            awsKmsClient: mock,
            commandFactory: makeTestCommandFactory(),
        });

        await expect(
            adapter.generateKey({ algorithm: 'SYMMETRIC_256' }),
        ).rejects.toMatchObject({ code: 'KMS_THROTTLED', retryable: true });
    });

    it('should map SYMMETRIC_256 to SYMMETRIC_DEFAULT KeySpec', async () => {
        const sendMock = vi.fn().mockResolvedValue({
            KeyMetadata: {
                KeyId: 'sym-key-001',
                KeyState: 'Enabled',
                CreationDate: new Date(),
                KeySpec: 'SYMMETRIC_DEFAULT',
            },
        });
        const adapter = new AwsKmsAdapter({
            awsKmsClient: { send: sendMock },
            commandFactory: makeTestCommandFactory(),
        });

        await adapter.generateKey({ algorithm: 'SYMMETRIC_256' });

        // send is called as (command, { abortSignal }); the second argument is the AbortSignal container
        /* eslint-disable @typescript-eslint/no-unsafe-assignment*/
        expect(sendMock).toHaveBeenCalledWith(
            expect.objectContaining({ KeySpec: 'SYMMETRIC_DEFAULT' }),
            expect.objectContaining({ abortSignal: expect.anything() }),
        );
        /* eslint-enable @typescript-eslint/no-unsafe-assignment*/
    });
});

// ── AwsKmsAdapter.sign ────────────────────────────────────────────────────────

describe('AwsKmsAdapter.sign', () => {
    it('should return base64-encoded signature on success', async () => {
        const mockSigBytes = new Uint8Array([1, 2, 3, 4, 5]);
        const mock = makeMockClient(() => ({
            Signature: mockSigBytes,
            SigningAlgorithm: 'ECDSA_SHA_256',
        }));
        const adapter = new AwsKmsAdapter({
            awsKmsClient: mock,
            commandFactory: makeTestCommandFactory(),
        });

        const result = await adapter.sign({
            keyId: 'test-key-id',
            payload: new Uint8Array([10, 20, 30]),
            algorithm: 'ECDSA_SHA_256',
        });

        expect(result.signature).toBe(
            Buffer.from(mockSigBytes).toString('base64'),
        );
        expect(result.algorithm).toBe('ECDSA_SHA_256');
        expect(result.signedAt).toMatch(/^\d{4}-/); // ISO timestamp
    });

    it('should throw KMSError(KMS_PROTOCOL_ERROR) when signature is empty', async () => {
        const mock = makeMockClient(() => ({
            Signature: new Uint8Array(0),
            SigningAlgorithm: 'ECDSA_SHA_256',
        }));
        const adapter = new AwsKmsAdapter({
            awsKmsClient: mock,
            commandFactory: makeTestCommandFactory(),
        });

        await expect(
            adapter.sign({
                keyId: 'test-key-id',
                payload: new Uint8Array([1]),
                algorithm: 'ECDSA_SHA_256',
            }),
        ).rejects.toMatchObject({
            code: 'KMS_PROTOCOL_ERROR',
            retryable: false,
        });
    });

    it('should throw KMSError(KMS_KEY_NOT_FOUND) on NotFoundException', async () => {
        const mock = makeMockClient(() => {
            throw Object.assign(new Error('Key not found'), {
                name: 'NotFoundException',
            });
        });
        const adapter = new AwsKmsAdapter({
            awsKmsClient: mock,
            commandFactory: makeTestCommandFactory(),
        });

        await expect(
            adapter.sign({
                keyId: 'missing-key',
                payload: new Uint8Array([1]),
                algorithm: 'ECDSA_SHA_256',
            }),
        ).rejects.toMatchObject({
            code: 'KMS_KEY_NOT_FOUND',
            retryable: false,
        });
    });

    it('should use MessageType=RAW so KMS performs hashing', async () => {
        const sendMock = vi.fn().mockResolvedValue({
            Signature: new Uint8Array([9, 8, 7]),
            SigningAlgorithm: 'ECDSA_SHA_256',
        });
        const adapter = new AwsKmsAdapter({
            awsKmsClient: { send: sendMock },
            commandFactory: makeTestCommandFactory(),
        });

        await adapter.sign({
            keyId: 'k1',
            payload: new Uint8Array([0xff]),
            algorithm: 'ECDSA_SHA_256',
        });

        // send is called as (command, { abortSignal }); the second argument is the AbortSignal container
        /* eslint-disable @typescript-eslint/no-unsafe-assignment*/
        expect(sendMock).toHaveBeenCalledWith(
            expect.objectContaining({ MessageType: 'RAW' }),
            expect.objectContaining({ abortSignal: expect.anything() }),
        );
        /* eslint-enable @typescript-eslint/no-unsafe-assignment*/
    });

    it('should throw KMSError(KMS_INVALID_PARAMETER) on ValidationException', async () => {
        const mock = makeMockClient(() => {
            throw Object.assign(new Error('Invalid algorithm'), {
                name: 'ValidationException',
            });
        });
        const adapter = new AwsKmsAdapter({
            awsKmsClient: mock,
            commandFactory: makeTestCommandFactory(),
        });

        await expect(
            adapter.sign({
                keyId: 'k1',
                payload: new Uint8Array([1]),
                algorithm: 'ECDSA_SHA_256',
            }),
        ).rejects.toMatchObject({
            code: 'KMS_INVALID_PARAMETER',
            retryable: false,
        });
    });
});

// ── AwsKmsAdapter.decrypt ─────────────────────────────────────────────────────

describe('AwsKmsAdapter.decrypt', () => {
    it('should return decrypted plaintext Uint8Array on success', async () => {
        const plaintextBytes = new Uint8Array([65, 66, 67]); // 'ABC'
        const mock = makeMockClient(() => ({
            Plaintext: plaintextBytes,
            KeyId: 'arn:aws:kms:us-east-1:123456789:key/test-key-id',
        }));
        const adapter = new AwsKmsAdapter({
            awsKmsClient: mock,
            commandFactory: makeTestCommandFactory(),
        });

        const result = await adapter.decrypt({
            keyId: 'test-key-id',
            ciphertextBlob: Buffer.from([1, 2, 3]).toString('base64'),
            algorithm: 'RSAES_OAEP_SHA_256',
        });

        expect(result.plaintext).toEqual(plaintextBytes);
        expect(result.keyId).toBe(
            'arn:aws:kms:us-east-1:123456789:key/test-key-id',
        );
    });

    it('should throw KMSError(KMS_PROTOCOL_ERROR) when plaintext is empty', async () => {
        const mock = makeMockClient(() => ({
            Plaintext: new Uint8Array(0),
        }));
        const adapter = new AwsKmsAdapter({
            awsKmsClient: mock,
            commandFactory: makeTestCommandFactory(),
        });

        await expect(
            adapter.decrypt({
                keyId: 'test-key-id',
                ciphertextBlob: Buffer.from([1]).toString('base64'),
                algorithm: 'SYMMETRIC_DEFAULT',
            }),
        ).rejects.toMatchObject({
            code: 'KMS_PROTOCOL_ERROR',
            retryable: false,
        });
    });

    it('should decode base64 ciphertextBlob before sending to AWS', async () => {
        const sendMock = vi.fn().mockResolvedValue({
            Plaintext: new Uint8Array([1, 2, 3]),
            KeyId: 'k1',
        });
        const adapter = new AwsKmsAdapter({
            awsKmsClient: { send: sendMock },
            commandFactory: makeTestCommandFactory(),
        });
        const ciphertextBytes = Buffer.from([10, 20, 30]);
        const ciphertextBlob = ciphertextBytes.toString('base64');

        await adapter.decrypt({
            keyId: 'k1',
            ciphertextBlob,
            algorithm: 'RSAES_OAEP_SHA_256',
        });

        const callArg = sendMock.mock.calls[0]?.[0] as Record<string, unknown>;
        // CiphertextBlob must be a Buffer/Uint8Array, not raw base64 string
        expect(callArg['CiphertextBlob']).toBeInstanceOf(Buffer);
        expect(Buffer.from(callArg['CiphertextBlob'] as Buffer)).toEqual(
            ciphertextBytes,
        );
    });
});

// ── AwsKmsAdapter.getKeyMetadata ──────────────────────────────────────────────

describe('AwsKmsAdapter.getKeyMetadata', () => {
    it('should return KMSKeyMetadata on successful DescribeKey', async () => {
        const creationDate = new Date('2026-01-01T00:00:00Z');
        const mock = makeMockClient(() => ({
            KeyMetadata: {
                KeyId: 'meta-key-001',
                KeyState: 'Enabled',
                CreationDate: creationDate,
                KeySpec: 'ECC_NIST_P256',
                Description: 'signing key',
            },
        }));
        const adapter = new AwsKmsAdapter({
            awsKmsClient: mock,
            commandFactory: makeTestCommandFactory(),
        });

        const result = await adapter.getKeyMetadata('meta-key-001');

        expect(result.keyId).toBe('meta-key-001');
        expect(result.state).toBe('ENABLED');
        expect(result.algorithm).toBe('ECDSA_P256');
        expect(result.createdAt).toBe('2026-01-01T00:00:00.000Z');
        expect(result.expiresAt).toBeNull();
        expect(result.description).toBe('signing key');
        expect(result.providerMetadata?.['provider']).toBe('aws-kms');
    });

    it('should throw KMSError(KMS_INVALID_PARAMETER) when keyId is empty string', async () => {
        const mock = makeMockClient(() => ({}));
        const adapter = new AwsKmsAdapter({
            awsKmsClient: mock,
            commandFactory: makeTestCommandFactory(),
        });

        await expect(adapter.getKeyMetadata('')).rejects.toMatchObject({
            code: 'KMS_INVALID_PARAMETER',
            retryable: false,
        });
    });

    it('should throw KMSError(KMS_INVALID_PARAMETER) when keyId is whitespace only', async () => {
        const mock = makeMockClient(() => ({}));
        const adapter = new AwsKmsAdapter({
            awsKmsClient: mock,
            commandFactory: makeTestCommandFactory(),
        });

        await expect(adapter.getKeyMetadata('   ')).rejects.toMatchObject({
            code: 'KMS_INVALID_PARAMETER',
        });
    });

    it('should throw KMSError(KMS_PROTOCOL_ERROR) when KeyMetadata.KeyId is missing', async () => {
        const mock = makeMockClient(() => ({
            KeyMetadata: { KeyState: 'Enabled' },
        }));
        const adapter = new AwsKmsAdapter({
            awsKmsClient: mock,
            commandFactory: makeTestCommandFactory(),
        });

        await expect(adapter.getKeyMetadata('some-key')).rejects.toMatchObject({
            code: 'KMS_PROTOCOL_ERROR',
            retryable: false,
        });
    });

    it('should map PendingDeletion state correctly', async () => {
        const mock = makeMockClient(() => ({
            KeyMetadata: {
                KeyId: 'del-key',
                KeyState: 'PendingDeletion',
                CreationDate: new Date(),
                KeySpec: 'SYMMETRIC_DEFAULT',
            },
        }));
        const adapter = new AwsKmsAdapter({
            awsKmsClient: mock,
            commandFactory: makeTestCommandFactory(),
        });

        const result = await adapter.getKeyMetadata('del-key');
        expect(result.state).toBe('PENDING_DELETION');
    });

    it('should map ValidTo to expiresAt when present', async () => {
        const expiryDate = new Date('2027-01-01T00:00:00Z');
        const mock = makeMockClient(() => ({
            KeyMetadata: {
                KeyId: 'expiring-key',
                KeyState: 'Enabled',
                CreationDate: new Date('2026-01-01T00:00:00Z'),
                KeySpec: 'RSA_4096',
                ValidTo: expiryDate,
            },
        }));
        const adapter = new AwsKmsAdapter({
            awsKmsClient: mock,
            commandFactory: makeTestCommandFactory(),
        });

        const result = await adapter.getKeyMetadata('expiring-key');
        expect(result.expiresAt).toBe('2027-01-01T00:00:00.000Z');
    });
});

// ── mapAwsError coverage ──────────────────────────────────────────────────────

describe('mapAwsError (via AwsKmsAdapter)', () => {
    const makeErrorAdapter = (errorProps: Record<string, unknown>) =>
        new AwsKmsAdapter({
            awsKmsClient: makeMockClient(() => {
                throw Object.assign(new Error('test'), errorProps);
            }),
            commandFactory: makeTestCommandFactory(),
        });

    it('should map ETIMEDOUT code to KMS_TIMEOUT retryable=true', async () => {
        const a = makeErrorAdapter({ code: 'ETIMEDOUT', name: 'Error' });
        await expect(a.getKeyMetadata('k1')).rejects.toMatchObject({
            code: 'KMS_TIMEOUT',
            retryable: true,
        });
    });

    it('should map ECONNRESET to KMS_TIMEOUT', async () => {
        const a = makeErrorAdapter({ code: 'ECONNRESET', name: 'Error' });
        await expect(a.getKeyMetadata('k1')).rejects.toMatchObject({
            code: 'KMS_TIMEOUT',
            retryable: true,
        });
    });

    it('should map HTTP 429 to KMS_THROTTLED', async () => {
        const a = makeErrorAdapter({
            name: 'RequestLimitExceeded',
            $metadata: { httpStatusCode: 429 },
        });
        await expect(a.getKeyMetadata('k1')).rejects.toMatchObject({
            code: 'KMS_THROTTLED',
            retryable: true,
        });
    });

    it('should map HTTP 404 to KMS_KEY_NOT_FOUND', async () => {
        const a = makeErrorAdapter({
            name: 'NotFoundException',
            $metadata: { httpStatusCode: 404 },
        });
        await expect(a.getKeyMetadata('k1')).rejects.toMatchObject({
            code: 'KMS_KEY_NOT_FOUND',
            retryable: false,
        });
    });

    it('should map HTTP 401 to KMS_AUTH_FAILED', async () => {
        const a = makeErrorAdapter({
            name: 'UnauthorizedException',
            $metadata: { httpStatusCode: 401 },
        });
        await expect(a.getKeyMetadata('k1')).rejects.toMatchObject({
            code: 'KMS_AUTH_FAILED',
            retryable: false,
        });
    });

    it('should map InvalidKeyUsageException to KMS_INVALID_PARAMETER', async () => {
        const a = makeErrorAdapter({ name: 'InvalidKeyUsageException' });
        await expect(a.getKeyMetadata('k1')).rejects.toMatchObject({
            code: 'KMS_INVALID_PARAMETER',
            retryable: false,
        });
    });

    it('should map SerializationException to KMS_PROTOCOL_ERROR', async () => {
        const a = makeErrorAdapter({ name: 'SerializationException' });
        await expect(a.getKeyMetadata('k1')).rejects.toMatchObject({
            code: 'KMS_PROTOCOL_ERROR',
            retryable: false,
        });
    });

    it('should map unknown error to KMS_UNKNOWN retryable=false', async () => {
        const a = makeErrorAdapter({ name: 'SomeRandomException' });
        await expect(a.getKeyMetadata('k1')).rejects.toMatchObject({
            code: 'KMS_UNKNOWN',
            retryable: false,
        });
    });

    it('should re-throw KMSError unchanged when already a KMSError', async () => {
        const existingError = new KMSError({
            code: 'KMS_TIMEOUT',
            message: 'pre-mapped timeout',
            retryable: true,
        });
        // Note: getKeyMetadata first does an empty-string keyId check, so we test via the sign path
        const signA = new AwsKmsAdapter({
            awsKmsClient: makeMockClient(() => {
                throw existingError;
            }),
            commandFactory: makeTestCommandFactory(),
        });
        await expect(
            signA.sign({
                keyId: 'k1',
                payload: new Uint8Array([1]),
                algorithm: 'ECDSA_SHA_256',
            }),
        ).rejects.toBe(existingError);
    });
});

// ── withTimeout ───────────────────────────────────────────────────────────────

describe('withTimeout (via AwsKmsAdapter)', () => {
    it('should throw KMSError(KMS_TIMEOUT) when operation exceeds timeoutMs', async () => {
        // Use an extremely short timeout (1ms) to trigger a timeout
        const adapter = new AwsKmsAdapter({
            awsKmsClient: makeMockClient(
                () =>
                    new Promise((resolve) => {
                        setTimeout(resolve, 500);
                    }),
            ),
            timeoutMs: 1,
            commandFactory: makeTestCommandFactory(),
        });

        await expect(adapter.getKeyMetadata('slow-key')).rejects.toMatchObject({
            code: 'KMS_TIMEOUT',
            retryable: true,
        });
    }, 2000);
});
