import type { Readable, Writable } from 'node:stream';
import {
    clearTimeout as clearTimer,
    setTimeout as setTimer,
} from 'node:timers';
import readline from 'node:readline';

export interface HumanCheckpointContext {
    action: string;
    agentDid: string;
    params: Record<string, unknown>;
}

export interface HumanCheckpointOptions {
    input?: Readable;
    output?: Writable;
    timeoutMs?: number;
}

export class HumanCheckpoint {
    private readonly input: Readable;
    private readonly output: Writable;
    private readonly timeoutMs: number;

    public constructor(options: HumanCheckpointOptions = {}) {
        this.input = options.input ?? process.stdin;
        this.output = options.output ?? process.stdout;
        this.timeoutMs = options.timeoutMs ?? 30_000;
    }

    public async requestConfirmation(
        context: HumanCheckpointContext,
    ): Promise<boolean> {
        this.output.write(
            `Policy approval required for ${context.action} by ${context.agentDid}\n${JSON.stringify(context.params)}\nApprove? [y/n]: `,
        );

        const rl = readline.createInterface({
            input: this.input,
            output: this.output,
            terminal: false,
        });

        try {
            let approved: boolean | null = null;
            while (approved === null) {
                const answer = await questionWithTimeout(
                    rl,
                    this.input,
                    this.timeoutMs,
                );
                if (answer === null) {
                    this.output.write('\nTimed out, denying by default.\n');
                    return false;
                }

                const normalized = answer.trim().toLowerCase();
                if (normalized === 'y') {
                    approved = true;
                } else if (normalized === 'n') {
                    approved = false;
                } else {
                    this.output.write('Please respond with y or n: ');
                }
            }

            return approved;
        } finally {
            rl.close();
        }
    }
}

async function questionWithTimeout(
    rl: readline.Interface,
    input: Readable,
    timeoutMs: number,
): Promise<string | null> {
    return await new Promise<string | null>((resolve) => {
        const onLine = (line: string) => {
            cleanup();
            resolve(line);
        };

        const timer = setTimer(() => {
            cleanup();
            resolve(null);
        }, timeoutMs);

        const cleanup = () => {
            clearTimer(timer);
            rl.off('line', onLine);
        };

        rl.on('line', onLine);
        input.resume();
    });
}
