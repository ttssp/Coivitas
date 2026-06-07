export interface StepExecutionRecord {
    number: number;
    name: string;
    durationMs: number;
    passed: boolean;
    /** Explicit skip flag.*/
    skipped?: boolean;
    skipReason?: string;
}

/**
 * Construct an "explicitly skipped" step record.
 *
 * Used for DEFER-class steps (such as Step 31 DHT routing) so that GoldenPathResult.steps
 * keeps step numbers monotonically contiguous, letting a caller doing full trace validation or step-count
 * assertions distinguish "intentionally deferred" from "execution stopped before step N".
 */
export function makeSkippedStepRecord(
    stepNumber: number,
    stepName: string,
    reason: string,
): StepExecutionRecord {
    return {
        number: stepNumber,
        name: stepName,
        durationMs: 0,
        passed: true, // not treated as a failure (a skip does not block subsequent steps)
        skipped: true,
        skipReason: reason,
    };
}

export async function runStep<T>(
    stepNumber: number,
    stepName: string,
    fn: () => Promise<T>,
    verbose: boolean,
): Promise<{ value?: T; record: StepExecutionRecord; error?: Error }> {
    const startedAt = Date.now();

    try {
        const value = await fn();
        const durationMs = Date.now() - startedAt;
        logStep(stepNumber, stepName, durationMs, true, verbose);

        return {
            value,
            record: {
                number: stepNumber,
                name: stepName,
                durationMs,
                passed: true,
            },
        };
    } catch (error) {
        const durationMs = Date.now() - startedAt;
        const normalized =
            error instanceof Error ? error : new Error(String(error));
        logStep(stepNumber, stepName, durationMs, false, verbose, normalized);

        return {
            error: normalized,
            record: {
                number: stepNumber,
                name: stepName,
                durationMs,
                passed: false,
            },
        };
    }
}

function logStep(
    stepNumber: number,
    stepName: string,
    durationMs: number,
    passed: boolean,
    verbose: boolean,
    error?: Error,
): void {
    if (!verbose && passed) {
        console.log(`Step ${stepNumber} ${stepName} ✅ (${durationMs}ms)`);
        return;
    }

    if (passed) {
        console.log(`Step ${stepNumber} ${stepName} ✅ (${durationMs}ms)`);
        return;
    }

    console.log(
        `Step ${stepNumber} ${stepName} ❌ (${durationMs}ms)${
            error ? ` ${error.message}` : ''
        }`,
    );
}
