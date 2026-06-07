const BASE58_ALPHABET =
    '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE58_INDEX = new Map(
    Array.from(BASE58_ALPHABET, (char, index) => [char, index]),
);
const ED25519_MULTICODEC_PREFIX = new Uint8Array([0xed, 0x01]);

export function encodeBase58(bytes: Uint8Array): string {
    if (bytes.length === 0) {
        return '';
    }

    const digits = [0];

    for (const byte of bytes) {
        let carry = byte;

        for (let index = 0; index < digits.length; index += 1) {
            const value = digits[index]! * 256 + carry;
            digits[index] = value % 58;
            carry = Math.floor(value / 58);
        }

        while (carry > 0) {
            digits.push(carry % 58);
            carry = Math.floor(carry / 58);
        }
    }

    let output = '';

    for (const byte of bytes) {
        if (byte !== 0) {
            break;
        }
        output += BASE58_ALPHABET[0];
    }

    for (let index = digits.length - 1; index >= 0; index -= 1) {
        output += BASE58_ALPHABET[digits[index]!]!;
    }

    return output;
}

export function decodeBase58(value: string): Uint8Array {
    if (value.length === 0) {
        return new Uint8Array();
    }

    const bytes = [0];

    for (const char of value) {
        const digit = BASE58_INDEX.get(char);
        if (digit === undefined) {
            throw new Error(`Invalid base58 character: ${char}`);
        }

        let carry = digit;

        for (let index = 0; index < bytes.length; index += 1) {
            const current = bytes[index]! * 58 + carry;
            bytes[index] = current & 0xff;
            carry = current >> 8;
        }

        while (carry > 0) {
            bytes.push(carry & 0xff);
            carry >>= 8;
        }
    }

    for (const char of value) {
        if (char !== BASE58_ALPHABET[0]) {
            break;
        }
        bytes.push(0);
    }

    return Uint8Array.from(bytes.reverse());
}

export function publicKeyToDidKey(publicKeyBytes: Uint8Array): string {
    const payload = new Uint8Array(
        ED25519_MULTICODEC_PREFIX.length + publicKeyBytes.length,
    );
    payload.set(ED25519_MULTICODEC_PREFIX, 0);
    payload.set(publicKeyBytes, ED25519_MULTICODEC_PREFIX.length);

    return `did:key:z${encodeBase58(payload)}`;
}

export function decodeDidKeyPayload(methodSpecificId: string): Uint8Array {
    if (!methodSpecificId.startsWith('z')) {
        throw new Error(
            'did:key payload must use base58btc multibase encoding.',
        );
    }

    const bytes = decodeBase58(methodSpecificId.slice(1));

    if (bytes.length !== 34) {
        throw new Error('did:key payload must decode to 34 bytes for Ed25519.');
    }

    if (
        bytes[0] !== ED25519_MULTICODEC_PREFIX[0] ||
        bytes[1] !== ED25519_MULTICODEC_PREFIX[1]
    ) {
        throw new Error('did:key payload is not an Ed25519 public key.');
    }

    return bytes.subarray(2);
}
