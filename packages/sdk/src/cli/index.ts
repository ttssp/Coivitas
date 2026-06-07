#!/usr/bin/env node

import { buildCliProgram } from './program.js';

const program = buildCliProgram();

await program.parseAsync(process.argv);
