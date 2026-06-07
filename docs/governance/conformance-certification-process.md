# Conformance Certification Process

Coivitas supports three certification tiers for implementations claiming
protocol conformance. Each tier raises the bar on independence and evidence;
the tooling (`@coivitas/conformance-test-suite`) is identical across tiers.

## Tiers

### Self-Assessed

The implementer runs `coivitas-conformance run` against their own deployment
and publishes the report alongside their release. No third party is involved.
This is the entry tier; it does not produce a certificate.

### Verified

A foundation-designated verifier runs `coivitas-conformance run` against the
implementation and signs a verification statement attesting to the report.
The verifier's signature is the artifact; no foundation certificate is
issued.

### Certified

The foundation conducts an audit run and issues a signed certificate. This
tier is available once the foundation is formally established and has
published its audit-run methodology.

## Process

1. Run `coivitas-conformance run --target <endpoint> --report markdown`
   against the implementation under test. The exit code distinguishes pass
   (0), fail (1), and configuration error (2).
2. **Self-Assessed** — publish the generated report next to your release
   notes.
3. **Verified** — open a verification request (process TBD once the verifier
   roster is published) and provide the verifier with reproducible access.
4. **Certified** — contact the foundation. The audit run uses the same CLI
   plus additional methodology defined in the foundation's audit handbook
   (TBD).

## Reporting issues

If a fixture appears to misrepresent the protocol, file an issue against
`@coivitas/conformance-test-suite`. See [`CONTRIBUTING.md`](../../CONTRIBUTING.md)
for the workflow.
