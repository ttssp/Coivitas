/**
 * Internal type definitions for conformance-test-suite.
 *
 * Summary first:
 * - ConformanceResult: the result of a single fixture run
 * - ConformanceReport: the full report for this run
 * - ReportFormat: the output format (json | markdown)
 * - RunnerOptions: the ConformanceRunner constructor parameters
 * - FixtureCase: a single test case loaded from a JSON fixture
 * - FixtureFile: the top-level structure of a fixture file
 */

/** The result of a single fixture run. */
export interface ConformanceResult {
    /** Fixture case ID (from the id or description field in the fixture file) */
    fixtureId: string;
    /** PASS means the result matches the fixture's expectation; FAIL means it does not; SKIP means actively skipped */
    status: 'PASS' | 'FAIL' | 'SKIP';
    /** Actual run duration (milliseconds); 0 for SKIP */
    latencyMs: number;
    /** Summary of the error or skip reason on FAIL / SKIP */
    error?: string;
    /** Source fixture file name */
    fixtureFile: string;
    /** Expected result (true=should pass validation, false=should be rejected) */
    expected: boolean;
    /** Actual schema validation result (uses local schema validation while the target endpoint is not implemented) */
    actual?: boolean;
}

/** The full report for this conformance run. */
export interface ConformanceReport {
    /** Target endpoint URL under test */
    target: string;
    /** Run time (ISO 8601) */
    runAt: string;
    /** Overall result: all PASS=true, any FAIL=false */
    passed: boolean;
    /** Statistics */
    summary: {
        total: number;
        pass: number;
        fail: number;
        skip: number;
    };
    /** Detailed result of each fixture */
    results: ConformanceResult[];
}

/** Report output format. */
export type ReportFormat = 'json' | 'markdown';

/** ConformanceRunner constructor parameters. */
export interface RunnerOptions {
    /** Target endpoint URL (current stage: used for metadata recording; schema validation runs locally) */
    target: string;
    /** List of fixture file or directory paths; when empty, the built-in v0.3.0 full fixture suite is used */
    fixturePaths?: string[];
    /**
     * Whether SKIP is allowed not to affect the overall passed determination.
     * Default false: when there is a SKIP, passed=false (exit 1), forcing the caller to be explicitly aware of the skip.
     * Set to true: SKIP is not counted toward the fail determination (equivalent to the --allow-skip CLI flag).
     */
    allowSkip?: boolean;
}

/** Minimal interface for a single case in a fixture JSON file (compatible with all valid/invalid/boundary/cases/matrix shapes). */
export interface FixtureCase {
    id?: string;
    description?: string;
    data?: unknown;
    valid?: boolean;
    expectedResult?: 'PASS' | 'FAIL' | 'REJECT' | 'RUNTIME_DEPENDENT';
    expectedError?: string;
    schemaId?: string;
    validatorVersion?: string;
    inputSpecVersion?: string;
}

/** Top-level structure of a fixture file (ValidInvalid shape). */
export interface ValidInvalidFixtureFile {
    description?: string;
    schemaId?: string;
    valid?: FixtureCase[];
    invalid?: FixtureCase[];
    cross_version?: FixtureCase[];
    boundary?: FixtureCase[];
}

/** Top-level structure of a fixture file (CrossVersion cases/matrix shape). */
export interface CrossVersionFixtureFile {
    description?: string;
    schemaId?: string;
    cases?: FixtureCase[];
    matrix?: FixtureCase[];
}

/** encoding_pairs fixture shape (lookup table only, no schema-validation semantics). */
export interface EncodingPairsFixtureFile {
    description?: string;
    encoding_pairs: Array<{
        hex: string;
        base64url: string;
        description?: string;
    }>;
}

/** Nested-group fixture (v030-base64url-field-extensions shape; currently DEFER). */
export interface NestedGroupFixtureFile {
    description?: string;
    [key: string]: unknown;
}

/** Union type of loaded fixture files. */
export type AnyFixtureFile =
    | ValidInvalidFixtureFile
    | CrossVersionFixtureFile
    | EncodingPairsFixtureFile
    | NestedGroupFixtureFile;
