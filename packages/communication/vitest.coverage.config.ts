import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        environment: 'node',
        include: ['src/**/*.test.ts'],
        coverage: {
            provider: 'v8',
            include: [
                'src/handshake/initiator.ts',
                'src/handshake/responder.ts',
                // types.ts contains only interface declarations, no JS runtime code; V8 correctly reports 0 executable statements
                // This file is excluded from the coverage gate (no executable statements)
            ],
            reporter: ['text', 'json-summary'],
        },
    },
});
