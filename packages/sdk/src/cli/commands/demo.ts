import { Command } from 'commander';

import { runGoldenPath } from '../../golden-path/index.js';
import { createCliPool, printOutput } from '../runtime.js';

export const createDemoCommand = (): Command => {
    const command = new Command('demo').description(
        'Run packaged demos and integration walkthroughs.',
    );

    command
        .command('golden-path')
        .description('Run the 26-step golden path demo flow.')
        .option(
            '--registry-url <url>',
            'Identity registry URL. If omitted, a local temporary registry is started.',
        )
        .option('--verbose', 'Print detailed execution diagnostics.', false)
        .action(
            async (options: { registryUrl?: string; verbose?: boolean }) => {
                const pool = createCliPool();

                try {
                    const result = await runGoldenPath({
                        pool,
                        identityRegistryUrl: options.registryUrl,
                        verbose: options.verbose,
                    });

                    printOutput(result, false);

                    if (!result.success) {
                        process.exitCode = 1;
                    }
                } finally {
                    await pool.end();
                }
            },
        );

    return command;
};
