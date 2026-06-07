# Communication Conformance Fixtures

These samples add semantic-level conformance coverage for the L4 communication layer.

## Files

- `negotiation-envelope.json`: general L4 envelope samples covering valid / invalid / boundary cases
- `handshake-messages.json`: handshake-specific message samples covering `HANDSHAKE_INIT` / `HANDSHAKE_ACK`
- `error-envelope.json`: standard error-envelope samples covering standard error codes and malformed error bodies

## Relationship to [`tests/fixtures/conformance/negotiation-envelope.json`](../negotiation-envelope.json)

- The top-level file remains the frozen wire-format baseline.
- The samples in this directory supplement it with semantic regression coverage for handshake and error envelopes.
