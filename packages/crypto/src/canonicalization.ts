import canonicalizePackage from 'canonicalize';

import { CryptoError } from './types.js';

function assertSerializable(
    value: unknown,
    seen: WeakSet<object>,
    path: string,
): void {
    if (
        value === undefined ||
        typeof value === 'function' ||
        typeof value === 'symbol' ||
        typeof value === 'bigint'
    ) {
        throw new CryptoError(
            'SERIALIZATION_FAILED',
            `Unsupported value at ${path || '$'}.`,
        );
    }

    if (typeof value === 'number' && !Number.isFinite(value)) {
        throw new CryptoError(
            'SERIALIZATION_FAILED',
            `Non-finite number at ${path || '$'}.`,
        );
    }

    if (value === null || typeof value !== 'object') {
        return;
    }

    if (seen.has(value)) {
        throw new CryptoError(
            'SERIALIZATION_FAILED',
            `Circular reference detected at ${path || '$'}.`,
        );
    }

    seen.add(value);

    if (Array.isArray(value)) {
        value.forEach((entry, index) => {
            assertSerializable(entry, seen, `${path}[${index}]`);
        });
        seen.delete(value);
        return;
    }

    for (const [key, entry] of Object.entries(value)) {
        assertSerializable(entry, seen, path ? `${path}.${key}` : key);
    }

    seen.delete(value);
}

export function canonicalize(obj: Record<string, unknown>): string {
    assertSerializable(obj, new WeakSet<object>(), '$');

    try {
        const serialized = (
            canonicalizePackage as unknown as (
                input: unknown,
            ) => string | undefined
        )(obj);

        if (typeof serialized !== 'string') {
            throw new CryptoError(
                'SERIALIZATION_FAILED',
                'Unable to canonicalize the provided value.',
            );
        }

        return serialized;
    } catch (error) {
        if (error instanceof CryptoError) {
            throw error;
        }

        throw new CryptoError(
            'SERIALIZATION_FAILED',
            'Unable to canonicalize the provided value.',
            error instanceof Error ? error : undefined,
        );
    }
}
