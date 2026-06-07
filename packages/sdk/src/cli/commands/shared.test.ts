import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { createPlaceholderHandler } from './shared.js';

describe('createPlaceholderHandler', () => {
    let logSpy: ReturnType<typeof vi.spyOn>;

    beforeEach(() => {
        logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('should log command path and summary when handler is called', () => {
        const handler = createPlaceholderHandler(
            'discover peer',
            'Discover a peer agent',
        );
        handler({});
        expect(logSpy).toHaveBeenCalledWith(
            '[placeholder] discover peer: Discover a peer agent',
        );
    });

    it('should not log args JSON when args is empty', () => {
        const handler = createPlaceholderHandler('foo bar', 'Foo bar');
        handler({});
        expect(logSpy).toHaveBeenCalledTimes(1);
    });

    it('should log args JSON when args has entries', () => {
        const handler = createPlaceholderHandler('discover peer', 'Discover');
        const args = { did: 'did:agent:abc', verbose: true };
        handler(args);
        expect(logSpy).toHaveBeenCalledTimes(2);
        const secondCall = logSpy.mock.calls[1]![0] as string;
        const parsed = JSON.parse(secondCall) as Record<string, unknown>;
        expect(parsed.did).toBe('did:agent:abc');
        expect(parsed.verbose).toBe(true);
    });

    it('should include commandPath and summary in PlaceholderCommandContext', () => {
        const handler = createPlaceholderHandler(
            'audit log',
            'View audit logs',
        );
        handler({ since: '2024-01-01' });
        const firstCall = logSpy.mock.calls[0]![0] as string;
        expect(firstCall).toContain('audit log');
        expect(firstCall).toContain('View audit logs');
    });
});
