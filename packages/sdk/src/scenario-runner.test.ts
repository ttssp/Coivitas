import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { ScenarioRunner } from './scenario-runner.js';

describe('ScenarioRunner', () => {
    it('executes derived steps and reports actual vs expected output', async () => {
        const directory = await mkdtemp(
            path.join(os.tmpdir(), 'scenario-runner-'),
        );
        const scenarioPath = path.join(directory, 'scenario.json');

        try {
            await writeFile(
                scenarioPath,
                JSON.stringify({
                    scenarioId: 'scenario-test',
                    description: 'Synthetic scenario',
                    steps: [
                        {
                            name: 'publish',
                            action: 'PUBLISH',
                            params: { channel_id: 'official-blog' },
                            expectedResult: {
                                handled: true,
                                messageType: 'NEGOTIATION_RESPONSE',
                            },
                        },
                    ],
                }),
            );

            const runner = new ScenarioRunner({
                orchestrator: {
                    handleEnvelope: (envelope) =>
                        Promise.resolve({
                            handled: true,
                            responseEnvelope: {
                                ...envelope,
                                messageType: 'NEGOTIATION_RESPONSE',
                                body: {
                                    status: 'SUCCESS',
                                },
                            },
                        }),
                },
            });

            const result = await runner.run(scenarioPath);

            expect(result).toMatchObject({
                scenarioId: 'scenario-test',
                passed: true,
                stepResults: [
                    {
                        name: 'publish',
                        passed: true,
                    },
                ],
            });
        } finally {
            await rm(directory, { recursive: true, force: true });
        }
    });
});
