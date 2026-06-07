#!/usr/bin/env node
/**
 * coivitas-conformance CLI shim.
 *
 * Summary:
 * - This file is the npm bin entry, pointed at by package.json#bin.
 * - It dynamically imports dist/index.js (the compiled output) and calls runCli().
 * - When not compiled, it falls back to loading src/index.ts directly via tsx/ts-node (development mode).
 */

import { createRequire } from 'module';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const distEntry = path.resolve(__dirname, '../dist/index.js');

// Prefer the compiled dist/index.js.
let runCli;
try {
    const mod = await import(distEntry);
    runCli = mod.runCli;
} catch {
    // Development environment: try to run src directly (requires ts-node or tsx).
    process.stderr.write(
        'Warning: dist/index.js not found. Run `pnpm build` first, or use `tsx src/index.ts`.\n',
    );
    process.exit(2);
}

await runCli(process.argv);
