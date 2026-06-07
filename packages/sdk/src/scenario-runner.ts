import { readFile } from 'node:fs/promises';
import path from 'node:path';

import type { DID } from '@coivitas/types';
import type { Orchestrator } from './orchestrator.js';

export interface ScenarioStep {
    name: string;
    action: string;
    params: Record<string, unknown>;
    expectedResult: Record<string, unknown>;
}

export interface ScenarioFile {
    scenarioId: string;
    description: string;
    steps?: ScenarioStep[];
    envelopes?: Array<{
        messageType: string;
        body: Record<string, unknown>;
        header: {
            senderDid: DID;
            recipientDid: DID;
            sessionId: string | null;
        };
    }>;
    expectedOutcomes?: Record<string, unknown>;
}

export interface ScenarioRunResult {
    scenarioId: string;
    passed: boolean;
    stepResults: Array<{
        name: string;
        passed: boolean;
        actualResult?: unknown;
        expectedResult?: unknown;
        error?: string;
    }>;
    totalDurationMs: number;
}

export class ScenarioRunner {
    private readonly orchestrator: Pick<Orchestrator, 'handleEnvelope'>;
    private readonly verbose: boolean;

    public constructor(options: {
        orchestrator: Pick<Orchestrator, 'handleEnvelope'>;
        verbose?: boolean;
    }) {
        this.orchestrator = options.orchestrator;
        this.verbose = options.verbose ?? false;
    }

    public async run(scenarioFilePath: string): Promise<ScenarioRunResult> {
        const startedAt = Date.now();
        const raw = await readFile(scenarioFilePath, 'utf8');
        const scenario = JSON.parse(raw) as ScenarioFile;
        const derivedSteps = this.deriveSteps(scenario, scenarioFilePath);
        const stepResults: ScenarioRunResult['stepResults'] = [];

        for (const step of derivedSteps) {
            try {
                const result = await this.orchestrator.handleEnvelope(
                    step.envelope,
                );
                const actualResult = {
                    handled: result.handled,
                    messageType: result.responseEnvelope.messageType,
                    body: result.responseEnvelope.body,
                };
                const passed = matchesExpected(
                    actualResult,
                    step.expectedResult,
                );

                stepResults.push({
                    name: step.name,
                    passed,
                    actualResult,
                    expectedResult: step.expectedResult,
                    error: passed
                        ? undefined
                        : buildDiffMessage(actualResult, step.expectedResult),
                });
            } catch (error) {
                stepResults.push({
                    name: step.name,
                    passed: false,
                    expectedResult: step.expectedResult,
                    error:
                        error instanceof Error ? error.message : String(error),
                });
            }
        }

        if (this.verbose) {
            console.log(
                `Scenario ${scenario.scenarioId} completed in ${
                    Date.now() - startedAt
                }ms`,
            );
        }

        return {
            scenarioId: scenario.scenarioId,
            passed: stepResults.every((result) => result.passed),
            stepResults,
            totalDurationMs: Date.now() - startedAt,
        };
    }

    public async runAll(
        scenarioFilePaths: string[],
    ): Promise<ScenarioRunResult[]> {
        const results: ScenarioRunResult[] = [];
        for (const scenarioFilePath of scenarioFilePaths) {
            results.push(await this.run(scenarioFilePath));
        }
        return results;
    }

    private deriveSteps(
        scenario: ScenarioFile,
        scenarioFilePath: string,
    ): Array<{
        name: string;
        envelope: Parameters<Orchestrator['handleEnvelope']>[0];
        expectedResult: Record<string, unknown>;
    }> {
        if (scenario.steps && scenario.steps.length > 0) {
            return scenario.steps.map((step, index) => ({
                name: step.name,
                envelope: {
                    id: `scenario-step-${index}`,
                    specVersion: '0.1.0',
                    header: {
                        senderDid:
                            'did:agent:00112233445566778899aabbccddeeff00112233' as DID,
                        recipientDid:
                            'did:agent:1111222233334444555566667777888899990000' as DID,
                        sessionId: null,
                    },
                    messageType: 'NEGOTIATION_REQUEST',
                    body: {
                        action: step.action,
                        params: step.params,
                    },
                    signature: '0'.repeat(128) as never,
                    timestamp: new Date().toISOString() as never,
                },
                expectedResult: step.expectedResult,
            }));
        }

        const envelopes = (scenario.envelopes ?? []).filter(
            (envelope) =>
                envelope.messageType === 'NEGOTIATION_REQUEST' ||
                envelope.messageType === 'NEGOTIATION_CONFIRM',
        );

        return envelopes.map((envelope, index) => {
            const action = normalizeAction(envelope.body['action']);
            const expectedResult =
                action === 'PUBLISH'
                    ? {
                          handled: true,
                          messageType: 'NEGOTIATION_RESPONSE',
                          body: {
                              status: 'SUCCESS',
                          },
                      }
                    : action === 'CONFIRM'
                      ? {
                            handled: true,
                            messageType: 'NEGOTIATION_RESPONSE',
                            body: {
                                status: 'SUCCESS',
                            },
                        }
                      : {
                            handled: true,
                            messageType: 'NEGOTIATION_RESPONSE',
                            body: {
                                status: 'SUCCESS',
                            },
                        };

            return {
                name: `${path.basename(scenarioFilePath)}#${index + 1}:${action}`,
                envelope: {
                    id: `scenario-envelope-${index}`,
                    specVersion: '0.1.0',
                    header: envelope.header,
                    messageType: envelope.messageType as never,
                    body: envelope.body,
                    signature: '0'.repeat(128) as never,
                    timestamp: new Date().toISOString() as never,
                },
                expectedResult,
            };
        });
    }
}

function matchesExpected(
    actual: Record<string, unknown>,
    expected: Record<string, unknown>,
): boolean {
    return Object.entries(expected).every(([key, value]) => {
        const actualValue = actual[key];
        if (
            value &&
            typeof value === 'object' &&
            !Array.isArray(value) &&
            actualValue &&
            typeof actualValue === 'object' &&
            !Array.isArray(actualValue)
        ) {
            return matchesExpected(
                actualValue as Record<string, unknown>,
                value as Record<string, unknown>,
            );
        }

        return actualValue === value;
    });
}

function buildDiffMessage(actual: unknown, expected: unknown): string {
    return `expected ${JSON.stringify(expected)} but received ${JSON.stringify(actual)}`;
}

function normalizeAction(value: unknown): string {
    return typeof value === 'string' ? value : 'UNKNOWN';
}
