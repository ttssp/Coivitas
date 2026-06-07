import { readFile } from 'node:fs/promises';

const requiredScenarioFiles = [
    'examples/scenarios/scenario-1-data.json',
    'examples/scenarios/scenario-2-data.json',
    'examples/scenarios/scenario-3-data.json',
];

// Documentation / governance artifacts that must exist and be non-empty in the public repo.
const requiredDocArtifacts = [
    'docs/architecture.md',
    'README.md',
    'CONTRIBUTING.md',
    'SECURITY.md',
    'CHANGELOG.md',
    'LICENSE',
];

const loadText = async (path) =>
    readFile(new URL(`../${path}`, import.meta.url), 'utf8');

const assert = (condition, message) => {
    if (!condition) {
        throw new Error(message);
    }
};

const verifyTypedocConfig = async () => {
    const raw = await loadText('typedoc.json');
    const config = JSON.parse(raw);

    assert(
        Array.isArray(config.entryPoints),
        'typedoc.json must define entryPoints',
    );
    assert(
        config.entryPoints.length >= 6,
        'typedoc.json should cover all six protocol packages',
    );
    assert(
        config.out === 'docs/api/generated',
        'typedoc.json output directory drifted',
    );
};

const verifyScenarios = async () => {
    const scenarios = await Promise.all(
        requiredScenarioFiles.map(async (path) => [
            path,
            JSON.parse(await loadText(path)),
        ]),
    );

    const byPath = Object.fromEntries(scenarios);

    assert(
        byPath['examples/scenarios/scenario-1-data.json'].scenarioId ===
            'scenario-1',
        'scenario-1 id mismatch',
    );
    assert(
        byPath['examples/scenarios/scenario-2-data.json'].scenarioId ===
            'scenario-2',
        'scenario-2 id mismatch',
    );
    assert(
        byPath['examples/scenarios/scenario-3-data.json'].scenarioId ===
            'scenario-3',
        'scenario-3 id mismatch',
    );

    assert(
        byPath['examples/scenarios/scenario-1-data.json'].expectedOutcomes
            .finalOrderStatus === 'confirmed',
        'scenario-1 expected outcome drifted',
    );
    assert(
        byPath['examples/scenarios/scenario-2-data.json'].expectedOutcomes
            .publishStatus === 'published',
        'scenario-2 expected outcome drifted',
    );
    assert(
        byPath['examples/scenarios/scenario-3-data.json'].expectedOutcomes
            .supportedToday === false,
        'scenario-3 should remain a forward-looking boundary case',
    );
};

const verifyDocArtifacts = async () => {
    await Promise.all(
        requiredDocArtifacts.map(async (path) => {
            const content = await loadText(path);
            assert(content.trim().length > 0, `${path} must not be empty`);
        }),
    );
};

await verifyTypedocConfig();
await verifyScenarios();
await verifyDocArtifacts();

console.log('Docs/scenario artifacts look healthy.');
