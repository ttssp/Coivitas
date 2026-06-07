/**
 * AWS KMS adapter implementation
 *
 * Responsibility:
 *   Maps the 4 operations of the KMSClient interface (generateKey / sign / decrypt / getKeyMetadata)
 *   to the corresponding API calls of @aws-sdk/client-kms.
 *
 * Design decision (monorepo placement + KMS provider):
 *   - Placement: packages/sdk/src/key-custody/ (L5 SDK; enterprise features do not enter the L2 identity core)
 *   - provider: AWS KMS (used in the GA env; aligned with the AWS infrastructure of the managed-service-runtime)
 *   - dependency: @aws-sdk/client-kms (optional peer dep; raises a runtime error rather than a compile error when not installed)
 *   - managed-service-runtime reuse: it uses PostgreSQL / Express 5 / noble;
 *     there is no prior KMS provider -> this file is the first introduction of AWS KMS
 *
 * Error handling strategy (fail-closed):
 *   - All AWS SDK errors -> converted to KMSError (precise code mapping; no silent degradation)
 *   - Network timeout / ECONNRESET -> KMS_TIMEOUT (retryable: true)
 *   - InvalidKeyUsage / ValidationException -> KMS_INVALID_PARAMETER (retryable: false)
 *   - AccessDeniedException / InvalidClientTokenId -> KMS_AUTH_FAILED (retryable: false)
 *   - ThrottlingException / KMSInvalidStateException (to be removed) -> KMS_THROTTLED (retryable: true)
 *   - All other errors -> KMS_UNKNOWN (retryable: false)
 *
 * Retry policy (implemented by the caller; the adapter itself does not retry):
 *   - retryable=true -> exponential backoff (recommended 100ms base, up to 3 attempts)
 *   - retryable=false -> no retry; raise an alert immediately
 */

import type {
    KMSClient,
    GenerateKeyParams,
    GenerateKeyResult,
    SignParams,
    SignResult,
    DecryptParams,
    DecryptResult,
    KMSKeyMetadata,
    KMSKeyAlgorithm,
    KMSKeyState,
} from './types.js';
import { KMSError } from './types.js';
import type { Timestamp } from '@coivitas/types';

// ── AWS KMS SDK types (dynamic import; @aws-sdk/client-kms optional peer dep) ───────

/**
 * AWS KMS SDK client interface (declares only the methods this adapter uses)
 *
 * Rationale: using an interface rather than directly importing the concrete class eases unit-test mocking (avoiding AWS SDK initialization).
 * The caller injects a real or mock instance via AwsKmsAdapterConfig.awsKmsClient.
 *
 * Production injection example:
 *   ```ts
 *   import { KMSClient as AwsSdkKmsClient } from '@aws-sdk/client-kms';
 *   const adapter = new AwsKmsAdapter({
 *     awsKmsClient: new AwsSdkKmsClient({ region: 'us-east-1' }),
 *   });
 *   ```
 *
 * Internal calls build a Command instance via commandFactory before passing it to send(),
 * ensuring that in production send() receives a Command instance (with resolveMiddleware),
 * while a test-injected mock client accepts any command shape.
 */
export interface AwsKmsClientPort {
    send(
        command: unknown,
        options?: { abortSignal?: AbortSignal },
    ): Promise<unknown>;
}

/**
 * AWS KMS Command constructor factory (optional; used for test injection / production default)
 *
 * Rationale: production must pass real Command instances (with resolveMiddleware);
 * the factory-injection pattern allows tests to override it, avoiding a dependency on the real @aws-sdk/client-kms SDK.
 *
 * The production default dynamically imports @aws-sdk/client-kms via createDefaultCommandFactory().
 * Tests inject an AwsKmsCommandFactoryPort mock (returns a plain object; accepted by the mock client).
 */
export interface AwsKmsCommandFactoryPort {
    /** Build a CreateKeyCommand instance*/
    createKey(input: Record<string, unknown>): unknown;
    /** Build a SignCommand instance*/
    sign(input: Record<string, unknown>): unknown;
    /** Build a DecryptCommand instance*/
    decrypt(input: Record<string, unknown>): unknown;
    /** Build a DescribeKeyCommand instance*/
    describeKey(input: Record<string, unknown>): unknown;
}

/**
 * Default Command factory (production; dynamically imports @aws-sdk/client-kms)
 *
 * Rationale: the dynamic import is deferred to the first operation call, avoiding a startup error when the optional peer dep
 * is not installed; when not installed it throws an explicit KMSError(KMS_INVALID_PARAMETER).
 */
async function createDefaultCommandFactory(): Promise<AwsKmsCommandFactoryPort> {
    let sdk: {
        CreateKeyCommand: new (input: Record<string, unknown>) => unknown;
        SignCommand: new (input: Record<string, unknown>) => unknown;
        DecryptCommand: new (input: Record<string, unknown>) => unknown;
        DescribeKeyCommand: new (input: Record<string, unknown>) => unknown;
    };

    try {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore — optional peer dep; not in TS project references
        sdk = await import('@aws-sdk/client-kms');
    } catch {
        throw new KMSError({
            code: 'KMS_INVALID_PARAMETER',
            message:
                '@aws-sdk/client-kms is not installed; ' +
                'install it as a dependency or inject a custom commandFactory.',
            retryable: false,
        });
    }

    return {
        createKey: (input) => new sdk.CreateKeyCommand(input),
        sign: (input) => new sdk.SignCommand(input),
        decrypt: (input) => new sdk.DecryptCommand(input),
        describeKey: (input) => new sdk.DescribeKeyCommand(input),
    };
}

/**
 * Test Command factory (injected for use by a test mock client)
 *
 * Test scenario: the mock client.send() accepts a plain object (AwsKmsClientPort.send: unknown);
 * this factory returns a plain object carrying the input fields, so that vi.fn() argument assertions can still inspect properties.
 *
 * Usage:
 *   ```ts
 *   import { makeTestCommandFactory } from '../aws-kms-adapter.js';
 *   const adapter = new AwsKmsAdapter({
 *     awsKmsClient: mockClient,
 *     commandFactory: makeTestCommandFactory(),
 *   });
 *   ```
 */
export function makeTestCommandFactory(): AwsKmsCommandFactoryPort {
    const wrap =
        (commandName: string) =>
        (input: Record<string, unknown>): Record<string, unknown> => ({
            _commandName: commandName,
            ...input,
        });
    return {
        createKey: wrap('CreateKeyCommand'),
        sign: wrap('SignCommand'),
        decrypt: wrap('DecryptCommand'),
        describeKey: wrap('DescribeKeyCommand'),
    };
}

// ── Constants ─────────────────────────────────────────────────────────────────

/**
 * Default KMS API timeout (milliseconds)
 * AWS KMS P99 latency is usually < 100ms; a 10s timeout leaves ample headroom for ops response.
 */
const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * AWS KMS KeySpec -> KMSKeyAlgorithm mapping
 *
 * For the KeySpecs supported by AWS KMS, see:
 * https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html#KMS-CreateKey-request-KeySpec
 */
const AWS_KEY_SPEC_MAP: Record<string, KMSKeyAlgorithm> = {
    ECC_NIST_P256: 'ECDSA_P256',
    RSA_4096: 'RSA_4096_OAEP_SHA256',
    SYMMETRIC_DEFAULT: 'SYMMETRIC_256',
};

/**
 * KMSKeyAlgorithm -> AWS KMS KeySpec mapping (used by generateKey)
 */
const ALGORITHM_TO_KEY_SPEC: Record<
    Exclude<KMSKeyAlgorithm, 'UNKNOWN'>,
    string
> = {
    ECDSA_P256: 'ECC_NIST_P256',
    RSA_4096_OAEP_SHA256: 'RSA_4096',
    SYMMETRIC_256: 'SYMMETRIC_DEFAULT',
};

/**
 * KMSKeyAlgorithm -> AWS KMS KeyUsage mapping (used by generateKey)
 */
const ALGORITHM_TO_KEY_USAGE: Record<
    Exclude<KMSKeyAlgorithm, 'UNKNOWN'>,
    string
> = {
    ECDSA_P256: 'SIGN_VERIFY',
    RSA_4096_OAEP_SHA256: 'ENCRYPT_DECRYPT',
    SYMMETRIC_256: 'ENCRYPT_DECRYPT',
};

/**
 * AWS KMS KeyState -> KMSKeyState mapping
 */
const AWS_KEY_STATE_MAP: Record<string, KMSKeyState> = {
    Enabled: 'ENABLED',
    Disabled: 'DISABLED',
    PendingDeletion: 'PENDING_DELETION',
    Unavailable: 'UNAVAILABLE',
};

// ── AwsKmsAdapterConfig ───────────────────────────────────────────────────────

/** AWS KMS adapter configuration*/
export interface AwsKmsAdapterConfig {
    /**
     * AWS KMS SDK client instance (injected to enable test mocking)
     *
     * Production:
     *   ```ts
     *   import { KMSClient } from '@aws-sdk/client-kms';
     *   const awsKmsClient = new KMSClient({ region: process.env.AWS_REGION });
     *   ```
     * Test: inject an AwsKmsClientPort mock
     */
    awsKmsClient: AwsKmsClientPort;

    /**
     * KMS Command instance factory (optional; defaults to dynamically importing @aws-sdk/client-kms)
     *
     * Rationale: in production the default factory dynamically imports @aws-sdk/client-kms
     * to build real Command instances (with resolveMiddleware).
     * In tests, inject makeTestCommandFactory(), which returns a plain object;
     * the mock client.send() accepts unknown, and property assertions work as usual.
     */
    commandFactory?: AwsKmsCommandFactoryPort;

    /**
     * KMS operation timeout (milliseconds; defaults to DEFAULT_TIMEOUT_MS)
     * On timeout, rejects with KMSError(KMS_TIMEOUT)
     */
    timeoutMs?: number;
}

// ── Internal utility functions ────────────────────────────────────────────────

/**
 * ISO 8601 UTC timestamp (ensures consistency with the project's Timestamp format)
 */
function nowTimestamp(): Timestamp {
    return new Date().toISOString() as Timestamp;
}

/**
 * Convert a Date to a Timestamp (null-safe)
 */
function dateToTimestamp(date: Date | undefined | null): Timestamp | null {
    if (!date) return null;
    return date.toISOString() as Timestamp;
}

/**
 * Map an AWS KMS KeyState to a KMSKeyState
 */
function mapKeyState(awsState: string | undefined): KMSKeyState {
    if (!awsState) return 'UNKNOWN';
    return AWS_KEY_STATE_MAP[awsState] ?? 'UNKNOWN';
}

/**
 * Map an AWS KMS KeySpec to a KMSKeyAlgorithm
 */
function mapKeyAlgorithm(awsKeySpec: string | undefined): KMSKeyAlgorithm {
    if (!awsKeySpec) return 'UNKNOWN';
    return AWS_KEY_SPEC_MAP[awsKeySpec] ?? 'UNKNOWN';
}

/**
 * Convert an AWS SDK error to a KMSError (precise mapping; no silent degradation)
 *
 * Rationale: AWS SDK v3 errors carry a name field (e.g. 'InvalidKeyUsageException');
 * match on name first, then fall back to checking $metadata.httpStatusCode.
 */
function mapAwsError(error: unknown, operation: string): KMSError {
    // AWS SDK v3 error structure
    const awsErr = error as {
        name?: string;
        message?: string;
        $metadata?: { httpStatusCode?: number };
        code?: string; // Node.js network errors such as ETIMEDOUT
    };

    const name = awsErr.name ?? '';
    const httpStatus = awsErr.$metadata?.httpStatusCode;
    const nodeCode = awsErr.code ?? '';
    const message = awsErr.message ?? 'Unknown KMS error';

    // Network timeout (including AbortError: AWS SDK send() rejects with AbortError after receiving the AbortSignal;
    // if AbortError wins the race ahead of the local timeout Promise, it must be mapped to KMS_TIMEOUT
    // rather than the fallback KMS_UNKNOWN retryable:false)
    if (
        nodeCode === 'ETIMEDOUT' ||
        nodeCode === 'ECONNRESET' ||
        name === 'AbortError' ||
        name === 'TimeoutError' ||
        name.includes('Timeout')
    ) {
        return new KMSError({
            code: 'KMS_TIMEOUT',
            message: `KMS ${operation} timed out: ${message}`,
            retryable: true,
            cause: error,
        });
    }

    // Throttling
    if (
        name === 'ThrottlingException' ||
        name === 'RequestLimitExceeded' ||
        httpStatus === 429
    ) {
        return new KMSError({
            code: 'KMS_THROTTLED',
            message: `KMS ${operation} throttled: ${message}`,
            retryable: true,
            cause: error,
        });
    }

    // Key not found
    if (name === 'NotFoundException' || httpStatus === 404) {
        return new KMSError({
            code: 'KMS_KEY_NOT_FOUND',
            message: `KMS key not found during ${operation}: ${message}`,
            retryable: false,
            cause: error,
        });
    }

    // Authentication / permission failure
    if (
        name === 'AccessDeniedException' ||
        name === 'InvalidClientTokenIdException' ||
        name === 'UnauthorizedException' ||
        httpStatus === 401 ||
        httpStatus === 403
    ) {
        return new KMSError({
            code: 'KMS_AUTH_FAILED',
            message: `KMS ${operation} auth failed: ${message}`,
            retryable: false,
            cause: error,
        });
    }

    // Parameter error (caller's fault; no retry)
    if (
        name === 'InvalidKeyUsageException' ||
        name === 'ValidationException' ||
        name === 'InvalidArnException' ||
        name === 'UnsupportedOperationException' ||
        httpStatus === 400
    ) {
        return new KMSError({
            code: 'KMS_INVALID_PARAMETER',
            message: `KMS ${operation} invalid parameter: ${message}`,
            retryable: false,
            cause: error,
        });
    }

    // Protocol error (the KMS response cannot be parsed)
    if (
        name === 'SerializationException' ||
        name === 'ParseError' ||
        name === 'SyntaxError'
    ) {
        return new KMSError({
            code: 'KMS_PROTOCOL_ERROR',
            message: `KMS ${operation} protocol error: ${message}`,
            retryable: false,
            cause: error,
        });
    }

    // Fallback: KMS_UNKNOWN (retryable: false; the caller raises an alert)
    return new KMSError({
        code: 'KMS_UNKNOWN',
        message: `KMS ${operation} unknown error (${name || 'no-name'}): ${message}`,
        retryable: false,
        cause: error,
    });
}

/**
 * Promise timeout race (prevent hung KMS calls)
 *
 * Rationale: uses AbortController + Promise.race and passes the signal to the operation,
 * ensuring the AWS SDK can release the connection early after receiving the abort signal (preventing background request leaks).
 *
 * The operation now receives an AbortSignal argument; the caller passes the signal to the AWS SDK via
 * `awsClient.send(command, { abortSignal: signal })`, so the real KMS request is aborted on timeout
 * (rather than merely racing a local Promise).
 */
async function withTimeout<T>(
    operation: (signal: AbortSignal) => Promise<T>,
    timeoutMs: number,
    operationName: string,
): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
        const result = await Promise.race([
            operation(controller.signal),
            new Promise<never>((_, reject) => {
                controller.signal.addEventListener('abort', () => {
                    reject(
                        new KMSError({
                            code: 'KMS_TIMEOUT',
                            message: `KMS ${operationName} timed out after ${timeoutMs}ms`,
                            retryable: true,
                        }),
                    );
                });
            }),
        ]);
        return result;
    } finally {
        clearTimeout(timer);
    }
}

// ── AwsKmsAdapter ─────────────────────────────────────────────────────────────

/**
 * AWS KMS adapter (the AWS KMS implementation of the KMSClient interface)
 *
 * Usage example (production):
 * ```ts
 * import { KMSClient as AwsSdkKmsClient } from '@aws-sdk/client-kms';
 * import { AwsKmsAdapter } from '@coivitas/sdk/key-custody';
 *
 * const adapter = new AwsKmsAdapter({
 *   awsKmsClient: new AwsSdkKmsClient({ region: 'us-east-1' }),
 *   timeoutMs: 5000,
 * });
 * ```
 *
 * Note: the AWS KMS v3 SDK uses the Command pattern;
 * client.send() must receive a Command instance (with resolveMiddleware),
 * otherwise production throws "command.resolveMiddleware is not a function".
 * commandFactory defaults to dynamically importing @aws-sdk/client-kms to build a real Command.
 * Tests inject makeTestCommandFactory() which returns a plain object; the mock client accepts unknown.
 */
export class AwsKmsAdapter implements KMSClient {
    private readonly awsClient: AwsKmsClientPort;
    private readonly timeoutMs: number;
    private readonly injectedFactory: AwsKmsCommandFactoryPort | undefined;
    /** Lazy-initialization cache: reused after the first getFactory()*/
    private resolvedFactory: AwsKmsCommandFactoryPort | undefined;

    constructor(config: AwsKmsAdapterConfig) {
        this.awsClient = config.awsKmsClient;
        this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
        this.injectedFactory = config.commandFactory;
    }

    /**
     * Get the Command factory (lazy initialization; injection takes priority, otherwise dynamic import)
     *
     * Rationale: cache after a single import to avoid triggering a dynamic import on every operation.
     */
    private async getFactory(): Promise<AwsKmsCommandFactoryPort> {
        if (this.injectedFactory) return this.injectedFactory;
        if (this.resolvedFactory) return this.resolvedFactory;
        this.resolvedFactory = await createDefaultCommandFactory();
        return this.resolvedFactory;
    }

    /**
     * Generate a new key within AWS KMS (using CreateKeyCommand)
     *
     * Immediately after generation, calls DescribeKey to fetch and return the full metadata.
     * The private key material never leaves the AWS KMS HSM (guaranteed by AWS).
     *
     * Builds a CreateKeyCommand instance via commandFactory.createKey(),
     * ensuring client.send() receives a real Command with resolveMiddleware.
     */
    async generateKey(params: GenerateKeyParams): Promise<GenerateKeyResult> {
        const keySpec = ALGORITHM_TO_KEY_SPEC[params.algorithm];
        const keyUsage = ALGORITHM_TO_KEY_USAGE[params.algorithm];

        const factory = await this.getFactory();

        // Build a CreateKeyCommand instance (with resolveMiddleware; required by KMSClient.send() in production)
        const createKeyCommand = factory.createKey({
            KeySpec: keySpec,
            KeyUsage: keyUsage,
            Description: params.description,
            // AWS KMS does not support specifying an expiry at creation time; expiry is managed externally by the key rotation policy
            // (handled when the rotation policy is implemented later)
        });

        let createResult: {
            KeyMetadata?: {
                KeyId?: string;
                KeyState?: string;
                CreationDate?: Date;
                KeySpec?: string;
                Description?: string;
            };
        };

        try {
            createResult = await withTimeout(
                (signal) =>
                    this.awsClient.send(createKeyCommand, {
                        abortSignal: signal,
                    }) as Promise<typeof createResult>,
                this.timeoutMs,
                'generateKey',
            );
        } catch (error) {
            if (error instanceof KMSError) throw error;
            throw mapAwsError(error, 'generateKey');
        }

        const keyId = createResult.KeyMetadata?.KeyId;
        if (!keyId) {
            throw new KMSError({
                code: 'KMS_PROTOCOL_ERROR',
                message: 'AWS KMS CreateKey returned no KeyId',
                retryable: false,
            });
        }

        const createdAt =
            dateToTimestamp(createResult.KeyMetadata?.CreationDate) ??
            nowTimestamp();

        const metadata: KMSKeyMetadata = {
            keyId,
            state: mapKeyState(createResult.KeyMetadata?.KeyState),
            algorithm: mapKeyAlgorithm(createResult.KeyMetadata?.KeySpec),
            createdAt,
            expiresAt: params.expiresAt ?? null,
            description: createResult.KeyMetadata?.Description,
            providerMetadata: { provider: 'aws-kms' },
        };

        return { keyId, createdAt, metadata };
    }

    /**
     * Sign using an AWS KMS key (using SignCommand)
     *
     * AWS KMS signing flow:
     *   1. Call the Sign API, passing MessageType='RAW' and the raw payload
     *   2. AWS KMS internally takes a SHA-256/SHA-384 digest of the payload and then signs
     *   3. Returns a DER-encoded ECDSA signature (base64 encoded)
     *
     * Note: the AWS KMS Sign API's MessageType has two values, 'RAW' and 'DIGEST';
     * this adapter uniformly uses 'RAW' (letting the KMS side hash), avoiding a double-hash by the caller.
     *
     * Builds a SignCommand instance via commandFactory.sign().
     */
    async sign(params: SignParams): Promise<SignResult> {
        const factory = await this.getFactory();

        // Build a SignCommand instance (with resolveMiddleware; required in production)
        const signCommand = factory.sign({
            KeyId: params.keyId,
            Message: params.payload,
            MessageType: 'RAW',
            SigningAlgorithm: params.algorithm,
        });

        let signResult: {
            Signature?: Uint8Array;
            SigningAlgorithm?: string;
        };

        try {
            signResult = await withTimeout(
                (signal) =>
                    this.awsClient.send(signCommand, {
                        abortSignal: signal,
                    }) as Promise<typeof signResult>,
                this.timeoutMs,
                'sign',
            );
        } catch (error) {
            if (error instanceof KMSError) throw error;
            throw mapAwsError(error, 'sign');
        }

        const rawSignature = signResult.Signature;
        if (!rawSignature || rawSignature.length === 0) {
            throw new KMSError({
                code: 'KMS_PROTOCOL_ERROR',
                message: 'AWS KMS Sign returned empty signature',
                retryable: false,
            });
        }

        // Convert the Uint8Array to a base64 encoded string (the caller can store / transmit it directly)
        const signature = Buffer.from(rawSignature).toString('base64');

        return {
            signature,
            algorithm: signResult.SigningAlgorithm ?? params.algorithm,
            signedAt: nowTimestamp(),
        };
    }

    /**
     * Decrypt using an AWS KMS key (using DecryptCommand; envelope decryption)
     *
     * Scenario: decrypt a data encryption key (DEK); the DEK is stored wrapped by the CMK;
     * after decrypting the DEK it is used to decrypt the actual data (the data does not pass through the KMS API).
     *
     * Builds a DecryptCommand instance via commandFactory.decrypt().
     */
    async decrypt(params: DecryptParams): Promise<DecryptResult> {
        // Convert the base64 encoded ciphertext back to a Uint8Array
        const ciphertextBytes = Buffer.from(params.ciphertextBlob, 'base64');

        const factory = await this.getFactory();

        // Build a DecryptCommand instance (with resolveMiddleware; required in production)
        const decryptCommand = factory.decrypt({
            KeyId: params.keyId,
            CiphertextBlob: ciphertextBytes,
            EncryptionAlgorithm: params.algorithm,
        });

        let decryptResult: {
            Plaintext?: Uint8Array;
            KeyId?: string;
        };

        try {
            decryptResult = await withTimeout(
                (signal) =>
                    this.awsClient.send(decryptCommand, {
                        abortSignal: signal,
                    }) as Promise<typeof decryptResult>,
                this.timeoutMs,
                'decrypt',
            );
        } catch (error) {
            if (error instanceof KMSError) throw error;
            throw mapAwsError(error, 'decrypt');
        }

        const plaintext = decryptResult.Plaintext;
        if (!plaintext || plaintext.length === 0) {
            throw new KMSError({
                code: 'KMS_PROTOCOL_ERROR',
                message: 'AWS KMS Decrypt returned empty plaintext',
                retryable: false,
            });
        }

        return {
            plaintext,
            keyId: decryptResult.KeyId ?? params.keyId,
        };
    }

    /**
     * Query AWS KMS key metadata (using DescribeKeyCommand)
     *
     * Commonly used for:
     *   - key rotation policy checks (verifying the key's current state + expiry time)
     *   - alerting: the key is about to expire or is in the PENDING_DELETION state
     *
     * Builds a DescribeKeyCommand instance via commandFactory.describeKey().
     */
    async getKeyMetadata(keyId: string): Promise<KMSKeyMetadata> {
        if (!keyId || keyId.trim().length === 0) {
            throw new KMSError({
                code: 'KMS_INVALID_PARAMETER',
                message: 'keyId must be a non-empty string',
                retryable: false,
            });
        }

        const factory = await this.getFactory();

        // Build a DescribeKeyCommand instance (with resolveMiddleware; required in production)
        const describeKeyCommand = factory.describeKey({ KeyId: keyId });

        let describeResult: {
            KeyMetadata?: {
                KeyId?: string;
                KeyState?: string;
                CreationDate?: Date;
                DeletionDate?: Date;
                KeySpec?: string;
                Description?: string;
                ValidTo?: Date;
            };
        };

        try {
            describeResult = await withTimeout(
                (signal) =>
                    this.awsClient.send(describeKeyCommand, {
                        abortSignal: signal,
                    }) as Promise<typeof describeResult>,
                this.timeoutMs,
                'getKeyMetadata',
            );
        } catch (error) {
            if (error instanceof KMSError) throw error;
            throw mapAwsError(error, 'getKeyMetadata');
        }

        const meta = describeResult.KeyMetadata;
        if (!meta?.KeyId) {
            throw new KMSError({
                code: 'KMS_PROTOCOL_ERROR',
                message: `AWS KMS DescribeKey returned no metadata for keyId=${keyId}`,
                retryable: false,
            });
        }

        // Expiry time: the AWS KMS ValidTo field (only valid for imported key material)
        // For KMS-generated keys, expiry is managed by the external rotation policy (it does not rely on AWS ValidTo)
        const expiresAt = dateToTimestamp(meta.ValidTo);

        return {
            keyId: meta.KeyId,
            state: mapKeyState(meta.KeyState),
            algorithm: mapKeyAlgorithm(meta.KeySpec),
            createdAt: dateToTimestamp(meta.CreationDate) ?? nowTimestamp(),
            expiresAt,
            description: meta.Description,
            providerMetadata: {
                provider: 'aws-kms',
                awsKeyId: meta.KeyId,
            },
        };
    }
}
