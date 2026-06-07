import { PassThrough } from 'node:stream';

import { describe, expect, it } from 'vitest';

import { HumanCheckpoint } from '../human-checkpoint.js';

describe('HumanCheckpoint', () => {
    it('approves yes, denies no, retries invalid input, and defaults to deny on timeout', async () => {
        const output = new PassThrough();
        const approveInput = new PassThrough();
        const approve = new HumanCheckpoint({
            input: approveInput,
            output,
            timeoutMs: 100,
        });
        approveInput.write('y\n');
        await expect(
            approve.requestConfirmation({
                action: 'CONFIRM',
                agentDid: 'did:agent:00112233445566778899aabbccddeeff00112233',
                params: { amount: 100 },
            }),
        ).resolves.toBe(true);

        const retryInput = new PassThrough();
        const retryCheckpoint = new HumanCheckpoint({
            input: retryInput,
            output: new PassThrough(),
            timeoutMs: 100,
        });
        retryInput.write('maybe\nn\n');
        await expect(
            retryCheckpoint.requestConfirmation({
                action: 'CONFIRM',
                agentDid: 'did:agent:00112233445566778899aabbccddeeff00112233',
                params: { amount: 100 },
            }),
        ).resolves.toBe(false);

        const timeoutCheckpoint = new HumanCheckpoint({
            input: new PassThrough(),
            output: new PassThrough(),
            timeoutMs: 20,
        });
        await expect(
            timeoutCheckpoint.requestConfirmation({
                action: 'CONFIRM',
                agentDid: 'did:agent:00112233445566778899aabbccddeeff00112233',
                params: { amount: 100 },
            }),
        ).resolves.toBe(false);
    });
});
