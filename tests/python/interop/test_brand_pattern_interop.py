"""TS <-> Python Brand pattern literal-value byte-level interop verification.

TS source of truth
------------------
- ``packages/types/src/schemas.ts:125-145``: literal definitions of the 9 Brand patterns
- ``packages/sdk-python/src/coivitas/_brands.py``: the manually synced Python copy

Cross-language alignment contract (anchor for CI gate ``pnpm sdk-python:check-brands``)
---------------------------------------------------------------------------------------
1. The accept/reject string set of the 9 Python ``_check_*`` validators matches the
   TS schema patterns (not a single character of drift allowed)
2. Boundary vectors (pattern length bounds / charset / prefix) all pass verification
3. Cross-language fail-closed behavior reconciliation: TS schema rejects -> Python validator rejects
"""

from __future__ import annotations

import re

import pytest

from coivitas._brands import (
    _check_cap_token_id,
    _check_did,
    _check_did_agent,
    _check_did_key,
    _check_hash,
    _check_public_key,
    _check_record_id,
    _check_signature,
    _check_timestamp,
)


# --- Reconciled against schemas.ts:125-145 (equivalent to CI gate sdk-python:check-brands) ---


SCHEMA_PATTERNS = {
    "did": r"^did:[a-z][a-z0-9-]*:[a-zA-Z0-9._%-]+(?::[a-zA-Z0-9._%-]+)*$",
    "didKey": r"^did:key:[a-zA-Z0-9._%-]+(?::[a-zA-Z0-9._%-]+)*$",
    "didAgent": r"^did:agent:[a-f0-9]{40}$",
    "hex64": r"^[0-9a-f]{64}$",
    "hex128": r"^[0-9a-f]{128}$",
    "base64url43": r"^[A-Za-z0-9_-]{43}$",
    "base64url86": r"^[A-Za-z0-9_-]{86}$",
    "timestamp": r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$",
    "uuidV4": r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    "capabilityTokenId": (
        r"^urn:cap:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
        r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    ),
    "recordId": (
        r"^rec-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
        r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    ),
}


class TestBrandPatternRoundtrip:
    """Python validators accept the same string set as the TS schemas.ts patterns."""

    def test_did_pattern_accepts_common_dids(self) -> None:
        for valid in [
            "did:agent:" + "a" * 40,
            "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
            "did:web:example.com",
            "did:example:foo:bar",
        ]:
            # Python validator
            assert _check_did(valid) == valid
            # Literal pattern check is equivalent (anchors the CI gate sync contract)
            assert re.match(SCHEMA_PATTERNS["did"], valid), valid

    def test_did_pattern_rejects_invalid(self) -> None:
        for invalid in [
            "",
            "not-a-did",
            "did:",
            "did:1agent:abc",  # method must start with a letter
            "did:agent",  # missing method-specific id
        ]:
            with pytest.raises((ValueError, TypeError)):
                _check_did(invalid)

    def test_did_agent_pattern_accepts_40_hex(self) -> None:
        valid = "did:agent:" + "0123456789abcdef" * 2 + "01234567"  # 40 hex
        assert _check_did_agent(valid) == valid
        # 39 hex (one character short) is rejected
        with pytest.raises(ValueError):
            _check_did_agent("did:agent:" + "a" * 39)

    def test_timestamp_pattern_iso8601_milliseconds_utc(self) -> None:
        valid = "2026-05-07T12:00:00.000Z"
        assert _check_timestamp(valid) == valid
        # Microseconds (6 digits) rejected (schema requires 3-digit milliseconds)
        with pytest.raises(ValueError):
            _check_timestamp("2026-05-07T12:00:00.000123Z")
        # Missing Z suffix rejected
        with pytest.raises(ValueError):
            _check_timestamp("2026-05-07T12:00:00.000")

    def test_signature_pattern_accepts_hex128_or_base64url86(self) -> None:
        # hex128
        sig_hex = "0" * 128
        assert _check_signature(sig_hex) == sig_hex
        # base64url86
        sig_b64 = "A" * 86
        assert _check_signature(sig_b64) == sig_b64
        # Length boundary - 127 hex rejected
        with pytest.raises(ValueError):
            _check_signature("0" * 127)
        # base64url containing '+' rejected (must be URL-safe)
        with pytest.raises(ValueError):
            _check_signature("+" * 86)

    def test_public_key_pattern_accepts_hex64_or_base64url43(self) -> None:
        # hex64
        pk_hex = "d" * 64
        assert _check_public_key(pk_hex) == pk_hex
        # base64url43
        pk_b64 = "A" * 43
        assert _check_public_key(pk_b64) == pk_b64
        # Length boundary - 65 hex rejected
        with pytest.raises(ValueError):
            _check_public_key("0" * 65)

    def test_hash_pattern_accepts_hex64_or_base64url43(self) -> None:
        # Shares the pattern with _check_public_key
        assert _check_hash("0" * 64) == "0" * 64
        assert _check_hash("A" * 43) == "A" * 43
        with pytest.raises(ValueError):
            _check_hash("0" * 63)

    def test_capability_token_id_urn_format(self) -> None:
        valid = "urn:cap:01234567-89ab-1cde-89ab-0123456789ab"
        assert _check_cap_token_id(valid) == valid
        # Missing urn:cap: prefix rejected
        with pytest.raises(ValueError):
            _check_cap_token_id("01234567-89ab-1cde-89ab-0123456789ab")
        # version digit must be 1-5 (values other than 4 also accepted, but 6 rejected)
        with pytest.raises(ValueError):
            _check_cap_token_id("urn:cap:01234567-89ab-6cde-89ab-0123456789ab")

    def test_record_id_accepts_rec_prefix_or_uuidv4(self) -> None:
        # rec-* prefix
        valid_rec = "rec-01234567-89ab-1cde-89ab-0123456789ab"
        assert _check_record_id(valid_rec) == valid_rec
        # Plain uuidv4
        valid_uuid = "01234567-89ab-4cde-89ab-0123456789ab"
        assert _check_record_id(valid_uuid) == valid_uuid
        # uuid v3 (3xxx) is accepted under the rec- prefix ([1-5] range), but the plain uuidV4 path requires 4
        with pytest.raises(ValueError):
            _check_record_id("01234567-89ab-3cde-89ab-0123456789ab")


class TestBrandPatternMatchesSchemaLiteral:
    """The Python-side pattern strings are identical to the TS schemas.ts literal strings (CI gate equivalence contract)."""

    def test_python_pattern_strings_match_schema_ts_literals(self) -> None:
        """Compare the compiled pattern.pattern in _brands.py directly against the schemas.ts literals.

        The CI gate ``pnpm sdk-python:check-brands`` runs in the production
        environment; this test acts as a Python-side fail-fast sentinel: if the
        Python pattern literals drift, this test goes red immediately, instead
        of having to wait for CI to surface the problem.
        """
        from coivitas import _brands

        # Reconcile (the internal _XXX_PATTERN in _brands.py are re.compile()'d objects)
        assert _brands._DID_PATTERN.pattern == SCHEMA_PATTERNS["did"]
        assert _brands._DID_KEY_PATTERN.pattern == SCHEMA_PATTERNS["didKey"]
        assert _brands._DID_AGENT_PATTERN.pattern == SCHEMA_PATTERNS["didAgent"]
        assert _brands._HEX64_PATTERN.pattern == SCHEMA_PATTERNS["hex64"]
        assert _brands._HEX128_PATTERN.pattern == SCHEMA_PATTERNS["hex128"]
        assert _brands._BASE64URL_43_PATTERN.pattern == SCHEMA_PATTERNS["base64url43"]
        assert _brands._BASE64URL_86_PATTERN.pattern == SCHEMA_PATTERNS["base64url86"]
        assert _brands._TIMESTAMP_PATTERN.pattern == SCHEMA_PATTERNS["timestamp"]
        assert _brands._UUID_V4_PATTERN.pattern == SCHEMA_PATTERNS["uuidV4"]
        # cap_token_id / record_id are multi-line concatenations; reconcile the concatenated string
        assert _brands._CAP_TOKEN_ID_PATTERN.pattern == SCHEMA_PATTERNS["capabilityTokenId"]
        assert _brands._RECORD_ID_PATTERN.pattern == SCHEMA_PATTERNS["recordId"]
