import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// interop harness: makes scanning the `tests/fixtures/conformance/<version>/` subdirectories the unified
// entry point for all version switches from v0.3.0 onward, so each new fixture no longer has to be imported
// manually inside a `*.test.ts`.

// Guarding against silent skips:
// - Explicit version whitelist (VERSION_WHITELIST): undeclared versions are not read; prevents a rename from quietly leaving a version unrun.
// - Fail-closed on load failure: if a whitelisted version's directory is missing or yields 0 samples, loadFixtureDir throws;
// the caller's `expect(scanned.totalSamples).toBeGreaterThan(0)` promotes a silent skip into an assertion failure.

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// fixture root directory: a fixed layout relative to this file, independent of the vitest cwd.
const FIXTURE_ROOT = path.resolve(__dirname, '../fixtures/conformance');

// First round: v0.3.0 only; v0.2-encoding is a reserved nominal placeholder for the encoding-switch batch
// (the subdirectory has not landed yet, so loadFixtureDir skips it under dir-must-exist mode; see SCAN_OPTIONS).
export const VERSION_WHITELIST = ['v0.3.0', 'v0.2-encoding'] as const;

export type VersionDir = (typeof VERSION_WHITELIST)[number];

export type SchemaIdHint =
    | 'agentIdentityDocument'
    | 'capabilityToken'
    | 'capability'
    | 'actionRecord'
    | 'agentCard'
    | 'negotiationEnvelope'
    | 'handshakeChallenge'
    | 'handshakeResponse'
    | 'resolvedPublicKeys'
    | 'sessionSupersededParams'
    | 'keyRotationState';

// Three container shapes for fixture files (compatible with already-landed shapes + the newly introduced
// cross-version centralized-encoding shape):
// 1. ValidInvalid: valid[] / invalid[] / optional cross_version[] / boundary[] — the body of A2/A4/A8.
// 2. CrossVersionCases: top-level schemaId + cases[], each pair carrying its own schemaId override — cross-version.v0.3.json.
export interface FixtureCase {
    id?: string;
    description?: string;
    data: unknown;
    valid?: boolean;
    expectedError?: string;
    schemaId?: SchemaIdHint;
}

export interface ValidInvalidFixture {
    description?: string;
    valid?: FixtureCase[];
    invalid?: FixtureCase[];
    cross_version?: FixtureCase[];
    boundary?: FixtureCase[];
    schemaId?: SchemaIdHint;
}

export interface CrossVersionFixture {
    description?: string;
    schemaId?: SchemaIdHint;
    /** v0.2 encoding-switch shape */
    cases?: FixtureCase[];
    /** Cross-version interop matrix shape (each case carries its own schemaId/expectedResult) */
    matrix?: FixtureCase[];
}

export type LoadedFixture = {
    file: string;
    fixture: ValidInvalidFixture | CrossVersionFixture;
};

export interface ScanResult {
    version: VersionDir;
    files: LoadedFixture[];
    totalSamples: number;
}

export interface ScanOptions {
    // Default strict: a whitelisted version's directory must exist and contain at least one fixture (guards against silent skips).
    // strict=false is only for placeholder versions that have not landed yet (v0.2-encoding currently has no directory).
    strict?: boolean;
}

const isFixtureFile = (name: string): boolean =>
    name.endsWith('.json') && !name.startsWith('.');

const countCases = (
    fixture: ValidInvalidFixture | CrossVersionFixture,
): number => {
    if ('cases' in fixture && Array.isArray(fixture.cases)) {
        return fixture.cases.length;
    }
    const f = fixture as ValidInvalidFixture;
    return (
        (f.valid?.length ?? 0) +
        (f.invalid?.length ?? 0) +
        (f.cross_version?.length ?? 0) +
        (f.boundary?.length ?? 0)
    );
};

export const loadFixtureDir = (
    version: VersionDir,
    options: ScanOptions = {},
): ScanResult => {
    const { strict = true } = options;
    if (!VERSION_WHITELIST.includes(version)) {
        // Whitelist defense: throw immediately when the caller passes an undeclared version, to keep a new version from quietly slipping into the scan.
        throw new Error(
            `loadFixtureDir: version '${version}' not in VERSION_WHITELIST [${VERSION_WHITELIST.join(', ')}]`,
        );
    }

    const dir = path.join(FIXTURE_ROOT, version);
    if (!fs.existsSync(dir)) {
        if (strict) {
            throw new Error(
                `loadFixtureDir: directory not found: ${dir} (version ${version} declared in whitelist but missing on disk; either land fixtures or move version out of whitelist)`,
            );
        }
        return { version, files: [], totalSamples: 0 };
    }

    const entries = fs
        .readdirSync(dir, { withFileTypes: true })
        .filter((entry) => entry.isFile() && isFixtureFile(entry.name))
        .map((entry) => entry.name)
        .sort();

    const files: LoadedFixture[] = entries.map((name) => {
        const filePath = path.join(dir, name);
        const raw = fs.readFileSync(filePath, 'utf8');
        const fixture = JSON.parse(raw) as
            | ValidInvalidFixture
            | CrossVersionFixture;
        return { file: name, fixture };
    });

    const totalSamples = files.reduce(
        (acc, loaded) => acc + countCases(loaded.fixture),
        0,
    );

    if (strict && totalSamples === 0) {
        // Before upgrade, fixtures do not count toward the acceptance pass criteria.
        throw new Error(
            `loadFixtureDir: version '${version}' produced 0 samples (silent skip guard tripped)`,
        );
    }

    return { version, files, totalSamples };
};

export const isCrossVersionFixture = (
    fixture: ValidInvalidFixture | CrossVersionFixture,
): fixture is CrossVersionFixture => {
    // Supports two fixture shapes:
    // - v0.2 encoding switch: `cases: FixtureCase[]`
    // - cross-version interop matrix: `matrix: FixtureCase[]` (each case carries its own
    // schemaId/expectedResult). The two are semantically equivalent and conformance-suite
    // processes them via the same cross-version path.
    if (
        'cases' in fixture &&
        Array.isArray((fixture).cases)
    ) {
        return true;
    }
    if (
        'matrix' in fixture &&
        Array.isArray((fixture as { matrix?: unknown }).matrix)
    ) {
        return true;
    }
    return false;
};

/**
 * encoding_pairs fixture shape detection.
 *
 * encoding-switch-dual-format.v0.3.json is a pure encoding lookup table and does not enter the schema
 * validation path (`encoding_pairs[].hex/base64url` are value pairs with no envelope context).
 * conformance-suite uses this helper to skip schema validation.
 */
export const isEncodingPairsFixture = (
    fixture: ValidInvalidFixture | CrossVersionFixture,
): boolean => {
    return (
        'encoding_pairs' in fixture &&
        Array.isArray((fixture as { encoding_pairs?: unknown }).encoding_pairs)
    );
};

/**
 * Nested-group fixture shape detection (v030-base64url-field-extensions.v0.3.json).
 *
 * Shape: the root level has group keys such as `a2_dual_key_base64url` / `a4_delegation_depth_base64url` /
 * `a8_session_supersede_base64url`, each group carrying its own valid/invalid lists and its own schemaId
 * (not the standard top-level schemaId). The current conformance-suite model does not support nesting,
 * so this is a placeholder skip for now, to be handled later.
 */
export const isNestedGroupFixture = (
    fixture: ValidInvalidFixture | CrossVersionFixture,
): boolean => {
    const f = fixture as Record<string, unknown>;
    // Detection: the root level has an object key ending in _base64url whose object contains valid/invalid lists
    for (const key of Object.keys(f)) {
        if (key === 'description' || key === '$schema') continue;
        const value = f[key];
        if (
            typeof value === 'object' &&
            value !== null &&
            !Array.isArray(value) &&
            ('valid' in (value as Record<string, unknown>) ||
                'invalid' in (value as Record<string, unknown>))
        ) {
            return true;
        }
    }
    return false;
};
