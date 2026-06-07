import { describe, expect, it } from 'vitest';

import {
    ACTION_VOCABULARY,
    HANDSHAKE_CAPABILITY_VOCABULARY,
    ProtocolError,
    SPEC_VERSION,
} from '../index.js';

describe('@coivitas/types base exports', () => {
    it('exports the protocol spec version constant', () => {
        expect(SPEC_VERSION).toBe('0.1.0');
    });

    it('formats ProtocolError consistently', () => {
        const error = new ProtocolError(
            'TOKEN_EXPIRED',
            'capability token expired',
        );

        expect(error.name).toBe('ProtocolError');
        expect(error.code).toBe('TOKEN_EXPIRED');
        expect(error.detail).toBe('capability token expired');
        expect(error.message).toBe('[TOKEN_EXPIRED] capability token expired');
    });

    /**
     * HANDSHAKE_CAPABILITY_VOCABULARY is the business-facing subset of
     * ACTION_VOCABULARY, excluding only SESSION_SUPERSEDED (a control-plane action).
     * Drift guard: when ACTION_VOCABULARY grows or shrinks in the future, this case ensures the handshake subset
     * is updated accordingly; otherwise the communication.schema.json initiatorCapabilities enum and the runtime check
     * would diverge again.
     */
    it('HANDSHAKE_CAPABILITY_VOCABULARY equals ACTION_VOCABULARY minus SESSION_SUPERSEDED', () => {
        const expected = ACTION_VOCABULARY.filter(
            (action) => action !== 'SESSION_SUPERSEDED',
        );
        expect([...HANDSHAKE_CAPABILITY_VOCABULARY]).toEqual(expected);
    });

    it('HANDSHAKE_CAPABILITY_VOCABULARY excludes SESSION_SUPERSEDED', () => {
        expect(
            (HANDSHAKE_CAPABILITY_VOCABULARY as readonly string[]).includes(
                'SESSION_SUPERSEDED',
            ),
        ).toBe(false);
    });
});
