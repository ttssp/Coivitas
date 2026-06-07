# Contributing to Coivitas

Thanks for your interest in contributing. This document covers everything you
need to file a change that we can accept: prerequisites, the local build and
test loop, commit conventions, and the pull-request workflow.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
By participating you agree to uphold it.

## Reporting security issues

**Do not open a public issue for security vulnerabilities.** Follow the
private disclosure process in [SECURITY.md](SECURITY.md).

---

## Prerequisites

- **Node.js** >= 20
- **pnpm** >= 9 (the repo pins `pnpm@9.15.0` via `packageManager`)
- **Python** >= 3.11 (only required if you touch `packages/sdk-python/`)
- **Docker** (only required for the database-backed examples and integration
  tests)

## Local setup

```bash
git clone https://github.com/ttssp/Coivitas.git
cd coivitas
pnpm install
pnpm build
```

Run the golden-path demo to confirm the toolchain works end-to-end:

```bash
pnpm run golden-path
```

## Tests & linting

Run these before opening a PR:

```bash
pnpm test                  # unit + package tests
pnpm run lint              # eslint + prettier
pnpm run test:integration  # cross-package integration (Docker required)
pnpm run test:interop      # conformance + interop
```

Coverage report:

```bash
pnpm run test:coverage
```

Python SDK tests (only if you touched `packages/sdk-python/`):

```bash
pytest
```

## Style

- **TypeScript / JavaScript**: ESLint + Prettier configs in the repo root.
  Run `pnpm run lint` and fix all errors before pushing.
- **Python**: Match the existing style in `packages/sdk-python/` (PEP 8,
  type hints required on public APIs).
- **No untyped escape hatches** (`any`, `// @ts-ignore`, `# type: ignore`)
  unless you justify them in a code comment.

---

## Commit conventions

### Conventional Commits

Every commit message must follow
[Conventional Commits 1.0](https://www.conventionalcommits.org/):

```
<type>(<optional scope>): <short summary>

<optional body>

<optional footers>
```

Accepted types: `feat`, `fix`, `chore`, `docs`, `test`, `refactor`, `perf`,
`build`, `ci`, `style`, `revert`.

Examples:

```
feat(policy): add scope-narrowing guard for delegated tokens
fix(crypto): reject malformed Ed25519 signatures earlier
docs(readme): clarify pnpm version requirement
```

### DCO sign-off (required)

All commits must be signed off under the
[Developer Certificate of Origin](https://developercertificate.org/). This is
a lightweight assertion that you have the right to submit the contribution.
There is **no CLA**.

Use `git commit -s` to append the sign-off automatically:

```
Signed-off-by: Your Name <you@example.com>
```

The email in the sign-off must match a verified email on your GitHub account.
You can configure git to always sign off:

```bash
git config --local format.signoff true
```

If you forget, amend with `git commit --amend --signoff`; for older commits
in a branch, `git rebase --signoff <base>` rewrites the range.

---

## Pull-request workflow

1. **Fork** the repo and create a feature branch off `main`:
   `git checkout -b feat/short-description`.
2. **Make focused commits.** One logical change per commit. Don't mix
   refactors with behavior changes.
3. **Add tests.** New behavior needs new tests; bug fixes need a regression
   test that fails before the fix.
4. **Run the full check locally**: `pnpm run lint && pnpm test` (and
   `pnpm run build && pnpm run lint:docs` for changes that touch builds or docs).
5. **Open a PR** against `main`. Describe the change and link any related
   issues.
6. **Address review feedback** by pushing new commits to the branch; don't
   force-push during review unless asked.
7. A maintainer will squash-merge once the local checks pass and at least one
   approving review is in.

### What makes a PR easy to accept

- Small, single-purpose, with a clear "why" in the description.
- The local checks (`pnpm run lint && pnpm test`) pass before you push.
- Tests demonstrate the new behavior (or the bug, for fixes).
- No unrelated formatting changes.
- DCO sign-off present on every commit.

### What slows a PR down

- Mixing refactors with feature changes.
- Disabling tests or lint rules without justification.
- Introducing new top-level dependencies without discussion.
- Breaking public API surface in `packages/sdk/` or `packages/sdk-python/`
  without a migration note.

---

## Filing issues

Before opening an issue, search existing issues to avoid duplicates. When
filing:

- **Bugs**: include reproduction steps, expected vs. actual behavior, the
  Node/pnpm versions, and the relevant log output.
- **Feature requests**: describe the use case first, then the proposed API.
  Sketches and prior art are welcome.

---

Questions that don't fit an issue can be opened as a GitHub Discussion
(once enabled). Thanks for contributing.
