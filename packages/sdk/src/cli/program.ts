import { Command } from 'commander';

import { createAuditCommand } from './commands/audit-query.js';
import { createDemoCommand } from './commands/demo.js';
import { createDiscoverCommand } from './commands/discover.js';
import { createIdentityCommand } from './commands/identity.js';
import { createLedgerCommand } from './commands/ledger.js';
import { createSessionEncryptCommand } from './commands/session-encrypt.js';
import { createTokenCommand } from './commands/token.js';

export const buildCliProgram = (): Command => {
    const program = new Command();

    program
        .name('coivitas')
        .description('Dev CLI for the Coivitas SDK and demo workflows.')
        .showHelpAfterError()
        .configureHelp({
            sortSubcommands: true,
        });

    program.addCommand(createIdentityCommand());
    program.addCommand(createTokenCommand());
    program.addCommand(createLedgerCommand());
    program.addCommand(createDiscoverCommand());
    program.addCommand(createDemoCommand());
    program.addCommand(createSessionEncryptCommand());
    program.addCommand(createAuditCommand());

    return program;
};
