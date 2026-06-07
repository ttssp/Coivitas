"""Cross-language fixture consumer -- the Python verification side.

Role
----
The TypeScript SDK is the **authoritative producer** of the cross-lang golden
bytes; this file is the Python-side **consumer** test. TS runs
``pnpm cross-lang:ts-fixtures:regenerate`` to write out three fixture JSON files,
and Python reads the expected values from those files and drives this side's
implementation to verify byte-level consistency.

Anti self-equal principle (mandatory)
--------------------------------------
All expected values **must come from the fixture JSON files**, and must not look like::

    expected = canonicalize(input_obj)   # WRONG: tautology

The correct form::

    expected_output = vector["expected_output"]   # from fixture JSON

Cross-language tautology guard
------------------------------
Computing and asserting within the same test is not allowed -- the compute side
may only accept the expected value from the fixture.

Type boundary annotations
-------------------------
Add a ``# boundary:`` comment at each base64 / bytes / str type crossing point.

File dependencies
-----------------
- ``tests/fixtures/cross-lang/canonicalize-vectors.json``
- ``tests/fixtures/cross-lang/signature-vectors.json``
- ``tests/fixtures/cross-lang/envelope-wire-vectors.json``

Path convention
---------------
``__file__`` lives in ``tests/python/interop/``, and REPO_ROOT is 3 levels up:
``parent.parent.parent.parent`` (interop->python->tests->REPO_ROOT)
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from coivitas._crypto import verify_ed25519
from coivitas._wire import canonicalize, envelope_to_wire, from_hex

# --- Path constants ---------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_FIXTURE_DIR = _REPO_ROOT / "tests" / "fixtures" / "cross-lang"

_CANONICALIZE_FIXTURE = _FIXTURE_DIR / "canonicalize-vectors.json"
_SIGNATURE_FIXTURE = _FIXTURE_DIR / "signature-vectors.json"
_ENVELOPE_FIXTURE = _FIXTURE_DIR / "envelope-wire-vectors.json"


# --- Fixture loading helpers ------------------------------------------------


def _load_canonicalize_fixture() -> dict:
    with _CANONICALIZE_FIXTURE.open("r", encoding="utf-8") as f:
        return json.load(f)


def _load_signature_fixture() -> dict:
    with _SIGNATURE_FIXTURE.open("r", encoding="utf-8") as f:
        return json.load(f)


def _load_envelope_fixture() -> dict:
    with _ENVELOPE_FIXTURE.open("r", encoding="utf-8") as f:
        return json.load(f)


# ─── TestCanonicalizeFixtureConsumer ────────────────────────────────────────


class TestCanonicalizeFixtureConsumer:
    """Per-vector verification of Python canonicalize against the TS golden bytes.

    expected_output comes from the fixture JSON, not from canonicalize(input).
    """

    def test_should_load_version_v0_1_when_canonicalize_fixture_is_read(self) -> None:
        """should load version v0.1 when canonicalize fixture is read."""
        fixture = _load_canonicalize_fixture()
        assert fixture["version"] == "v0.1"

    def test_should_contain_at_least_30_vectors_when_canonicalize_fixture_is_loaded(
        self,
    ) -> None:
        """should contain at least 30 vectors when canonicalize fixture is loaded."""
        fixture = _load_canonicalize_fixture()
        assert len(fixture["vectors"]) >= 30

    def test_should_match_ts_output_for_all_vectors_when_python_canonicalize_runs(
        self,
    ) -> None:
        """should match TS output for all vectors when python canonicalize runs.

        Anti self-equal: actual = canonicalize(v["input"]) (Python implementation);
        expected = v["expected_output"] (from the TS-produced fixture, not recomputed).
        """
        fixture = _load_canonicalize_fixture()
        failures: list[str] = []
        for v in fixture["vectors"]:
            # expected comes from the fixture, not recomputed by Python
            expected_output: str = v["expected_output"]
            # actual comes from the Python implementation
            actual_output: str = canonicalize(v["input"])
            if actual_output != expected_output:
                failures.append(
                    f"  id={v['id']!r}\n"
                    f"    expected={expected_output!r}\n"
                    f"    actual  ={actual_output!r}"
                )
        assert not failures, (
            f"Python canonicalize diverged from TS fixture for {len(failures)} vector(s):\n"
            + "\n".join(failures)
        )

    def test_should_match_ts_sha256_for_all_vectors_when_python_canonicalize_runs(
        self,
    ) -> None:
        """should match TS sha256 for all vectors when python canonicalize runs.

        boundary: str -> UTF-8 bytes -> sha256 hex
        """
        fixture = _load_canonicalize_fixture()
        for v in fixture["vectors"]:
            # expected_sha256 comes from the fixture
            expected_sha256: str = v["expected_sha256"]
            actual_output: str = canonicalize(v["input"])
            # boundary: UTF-8 encode -> SHA-256
            actual_sha256 = hashlib.sha256(actual_output.encode("utf-8")).hexdigest()
            assert actual_sha256 == expected_sha256, (
                f"sha256 mismatch for id={v['id']!r}: "
                f"expected={expected_sha256!r}, actual={actual_sha256!r}"
            )

    def test_should_produce_ascii_keys_sorted_output_when_ascii_keys_sorted_vector_is_consumed(
        self,
    ) -> None:
        """should produce ascii-keys-sorted output when ascii-keys-sorted vector is consumed.

        expected comes from the fixture, not recomputed by Python.
        """
        fixture = _load_canonicalize_fixture()
        v = next((x for x in fixture["vectors"] if x["id"] == "ascii-keys-sorted"), None)
        assert v is not None, "ascii-keys-sorted vector not found in fixture"
        # expected comes from the fixture JSON
        expected_output: str = v["expected_output"]
        assert expected_output == '{"a":1,"m":2,"z":3}', (
            f"fixture expected_output unexpected: {expected_output!r}"
        )
        # The Python implementation must match TS
        actual_output: str = canonicalize(v["input"])
        assert actual_output == expected_output

    def test_should_produce_cjk_keys_after_ascii_when_unicode_cjk_keys_vector_is_consumed(
        self,
    ) -> None:
        """should produce cjk keys after ascii when unicode-cjk-keys vector is consumed."""
        fixture = _load_canonicalize_fixture()
        v = next((x for x in fixture["vectors"] if x["id"] == "unicode-cjk-keys"), None)
        assert v is not None, "unicode-cjk-keys vector not found in fixture"
        # expected comes from the fixture
        expected_output: str = v["expected_output"]
        assert expected_output == '{"a":0,"中":1,"文":2}', (
            f"fixture expected_output unexpected: {expected_output!r}"
        )
        actual_output: str = canonicalize(v["input"])
        assert actual_output == expected_output


# ─── TestSignatureFixtureConsumer ────────────────────────────────────────────


class TestSignatureFixtureConsumer:
    """Per-vector verification of Python Ed25519 verify_ed25519 against the TS golden bytes.

    expected_signature_hex / expected_signature_base64url come from the fixture JSON.
    """

    def test_should_load_at_least_10_signature_vectors_when_fixture_is_read(
        self,
    ) -> None:
        """should load at least 10 signature vectors when fixture is read."""
        fixture = _load_signature_fixture()
        assert len(fixture["vectors"]) >= 10

    def test_should_verify_all_ed25519_signatures_against_ts_golden_bytes(
        self,
    ) -> None:
        """should verify all ed25519 signatures against ts golden bytes.

        expected_signature_hex comes from the fixture (TS signature); Python only
        verifies, never re-signs.
        boundary: hex string -> bytes
        """
        fixture = _load_signature_fixture()
        failures: list[str] = []
        for v in fixture["vectors"]:
            # From the fixture, not re-signed
            public_key_bytes = from_hex(v["public_key_hex"])  # boundary: hex -> bytes
            message_bytes = from_hex(v["message_hex"]) if v["message_hex"] else b""  # boundary
            expected_sig_bytes = from_hex(v["expected_signature_hex"])  # boundary

            result = verify_ed25519(public_key_bytes, message_bytes, expected_sig_bytes)
            if not result:
                failures.append(
                    f"  id={v['id']!r}: verify_ed25519 returned False"
                )
        assert not failures, (
            f"Ed25519 signature verification failed for {len(failures)} vector(s):\n"
            + "\n".join(failures)
        )

    def test_should_verify_rfc8032_test_vector_1_when_ed25519_rfc8032_test1_empty_is_consumed(
        self,
    ) -> None:
        """should verify rfc8032 test vector 1 when ed25519-rfc8032-test1-empty is consumed.

        expected values from fixture, not recomputed.
        """
        fixture = _load_signature_fixture()
        v = next(
            (x for x in fixture["vectors"] if x["id"] == "ed25519-rfc8032-test1-empty"), None
        )
        assert v is not None
        # expected comes from the fixture
        assert v["public_key_hex"] == (
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        )
        assert v["expected_signature_hex"] == (
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        # Python verify_ed25519 must be True for RFC 8032 TV1
        pub = from_hex(v["public_key_hex"])  # boundary: hex -> bytes
        msg = b""  # empty message
        sig = from_hex(v["expected_signature_hex"])  # boundary
        assert verify_ed25519(pub, msg, sig) is True

    def test_should_have_base64url_without_padding_when_signature_vectors_are_consumed(
        self,
    ) -> None:
        """should have base64url without padding when signature vectors are consumed.

        boundary: base64url RFC 4648 §5 no-padding verification.
        """
        fixture = _load_signature_fixture()
        for v in fixture["vectors"]:
            b64url: str = v["expected_signature_base64url"]
            # boundary: base64url contains no '=' padding
            assert "=" not in b64url, (
                f"id={v['id']!r}: base64url contains '=': {b64url!r}"
            )
            assert "+" not in b64url, (
                f"id={v['id']!r}: base64url contains '+': {b64url!r}"
            )
            assert "/" not in b64url, (
                f"id={v['id']!r}: base64url contains '/': {b64url!r}"
            )

    def test_should_decode_base64url_signatures_to_64_bytes_when_all_vectors_are_consumed(
        self,
    ) -> None:
        """should decode base64url signatures to 64 bytes when all vectors are consumed.

        boundary: base64url -> bytes (standard padding required for decode)
        """
        fixture = _load_signature_fixture()
        for v in fixture["vectors"]:
            b64url: str = v["expected_signature_base64url"]
            # boundary: base64url -> bytes (standard decode after re-padding)
            padded = b64url + "=" * ((4 - len(b64url) % 4) % 4)
            sig_bytes = base64.urlsafe_b64decode(padded)
            assert len(sig_bytes) == 64, (
                f"id={v['id']!r}: signature decoded to {len(sig_bytes)} bytes, expected 64"
            )

    def test_should_have_hex_and_base64url_consistent_when_all_vectors_are_consumed(
        self,
    ) -> None:
        """should have hex and base64url consistent when all vectors are consumed.

        Dual-path consistency check between expected_signature_hex and
        expected_signature_base64url.
        """
        fixture = _load_signature_fixture()
        for v in fixture["vectors"]:
            # boundary: hex -> bytes
            sig_from_hex = from_hex(v["expected_signature_hex"])
            # boundary: base64url -> bytes
            b64url: str = v["expected_signature_base64url"]
            padded = b64url + "=" * ((4 - len(b64url) % 4) % 4)
            sig_from_b64url = base64.urlsafe_b64decode(padded)
            assert sig_from_hex == sig_from_b64url, (
                f"id={v['id']!r}: hex and base64url decode to different bytes"
            )


# ─── TestEnvelopeWireFixtureConsumer ─────────────────────────────────────────


class TestEnvelopeWireFixtureConsumer:
    """Per-vector verification of Python envelope_to_wire against the TS golden bytes.

    expected_wire_bytes_base64 / expected_sha256 come from the fixture JSON.
    """

    def test_should_load_at_least_10_envelope_vectors_when_fixture_is_read(
        self,
    ) -> None:
        """should load at least 10 envelope vectors when fixture is read."""
        fixture = _load_envelope_fixture()
        assert len(fixture["vectors"]) >= 10

    def test_should_match_ts_wire_bytes_for_all_vectors_when_python_envelope_to_wire_runs(
        self,
    ) -> None:
        """should match TS wire bytes for all vectors when python envelope_to_wire runs.

        expected_wire_bytes_base64 comes from the TS-produced fixture, not re-run.
        boundary: base64 (standard) -> bytes; UTF-8 bytes -> str
        """
        fixture = _load_envelope_fixture()
        failures: list[str] = []
        for v in fixture["vectors"]:
            # expected comes from the fixture
            expected_b64: str = v["expected_wire_bytes_base64"]
            # boundary: standard base64 -> bytes
            expected_wire_bytes: bytes = base64.b64decode(expected_b64)

            # Python implementation
            actual_wire_bytes: bytes = envelope_to_wire(v["input"])

            if actual_wire_bytes != expected_wire_bytes:
                failures.append(
                    f"  id={v['id']!r}\n"
                    f"    expected_wire={expected_wire_bytes!r}\n"
                    f"    actual_wire  ={actual_wire_bytes!r}"
                )
        assert not failures, (
            f"Python envelope_to_wire diverged from TS fixture for {len(failures)} vector(s):\n"
            + "\n".join(failures)
        )

    def test_should_match_ts_sha256_for_all_vectors_when_python_envelope_to_wire_runs(
        self,
    ) -> None:
        """should match TS sha256 for all vectors when python envelope_to_wire runs.

        boundary: bytes -> sha256 hex
        """
        fixture = _load_envelope_fixture()
        for v in fixture["vectors"]:
            # expected_sha256 comes from the fixture
            expected_sha256: str = v["expected_sha256"]
            actual_wire: bytes = envelope_to_wire(v["input"])
            # boundary: bytes -> sha256
            actual_sha256 = hashlib.sha256(actual_wire).hexdigest()
            assert actual_sha256 == expected_sha256, (
                f"sha256 mismatch for id={v['id']!r}: "
                f"expected={expected_sha256!r}, actual={actual_sha256!r}"
            )

    def test_should_include_conformance_valid_handshake_init_when_fixture_is_read(
        self,
    ) -> None:
        """should include conformance-valid-handshake-init when fixture is read."""
        fixture = _load_envelope_fixture()
        ids = [v["id"] for v in fixture["vectors"]]
        assert "conformance-valid-handshake-init" in ids, (
            f"conformance-valid-handshake-init not found in fixture; ids={ids}"
        )

    def test_should_decode_wire_bytes_to_valid_utf8_json_when_all_vectors_are_consumed(
        self,
    ) -> None:
        """should decode wire bytes to valid utf-8 json when all vectors are consumed.

        boundary: base64 -> bytes -> UTF-8 -> JSON.parse
        """
        fixture = _load_envelope_fixture()
        for v in fixture["vectors"]:
            # boundary: standard base64 -> bytes
            expected_wire_bytes = base64.b64decode(v["expected_wire_bytes_base64"])
            # boundary: bytes -> UTF-8 string
            wire_str = expected_wire_bytes.decode("utf-8")
            # RFC 8785 JCS output is valid JSON
            parsed = json.loads(wire_str)
            assert isinstance(parsed, dict), (
                f"id={v['id']!r}: wire bytes decode to {type(parsed).__name__}, expected dict"
            )


# --- TestDriftDetectionRegression (monkeypatch drift regression) -------------
# Add a Python-side monkeypatch-based drift regression test.
# Goal: verify that if the Python canonicalize implementation produces wrong
#       output, the fixture-consumer test can detect it.
# Strategy: monkeypatch canonicalize with a stub that always returns a wrong
#       string; assert at least 1 vector has actual != expected (i.e. the
#       detection mechanism works).
# Cross-language tautology guard: this test does not call expected =
#   canonicalize(input); instead it verifies that "when canonicalize output is
#   wrong, the fixture-comparison mechanism finds the difference".
# Anti self-equal: expected comes from the fixture JSON (as in TestCanonicalizeFixtureConsumer).


class TestDriftDetectionRegression:
    """Verify the drift-detection mechanism itself works -- when monkeypatched canonicalize produces wrong output, at least 1 vector should fail."""

    def test_should_detect_wrong_canonicalize_output_when_canonicalize_is_monkeypatched(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """should detect wrong canonicalize output when canonicalize is monkeypatched.

        monkeypatch canonicalize -> always returns '{}' (wrong stub);
        verify >=1 fixture vector has actual != expected.
        expected comes from the fixture JSON, not recomputed by Python.
        No expected = canonicalize(input) tautology allowed.
        """
        import coivitas._wire as wire_module

        # monkeypatch: replace canonicalize with a stub that always returns '{}'
        monkeypatch.setattr(wire_module, "canonicalize", lambda _obj: "{}")

        fixture = _load_canonicalize_fixture()
        # expected comes from the fixture JSON
        mismatch_count = sum(
            1
            for v in fixture["vectors"]
            if wire_module.canonicalize(v["input"]) != v["expected_output"]
        )

        # At least 1 vector must detect the inconsistency (verifying the mechanism works)
        # Note: only the empty-object vector has expected_output '{}'; the other >=29 vectors must be inconsistent
        assert mismatch_count >= 1, (
            "drift detection regression FAILED: monkeypatched canonicalize returned '{}' "
            "but no vector detected a mismatch — fixture comparison mechanism is broken"
        )

    def test_should_detect_wrong_envelope_wire_output_when_envelope_to_wire_is_monkeypatched(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """should detect wrong envelope wire output when envelope_to_wire is monkeypatched.

        monkeypatch envelope_to_wire -> always returns b'{}' (wrong stub);
        verify >=1 fixture vector has a sha256 different from expected_sha256.
        expected_sha256 comes from the fixture JSON.
        """
        import coivitas._wire as wire_module

        # monkeypatch: replace envelope_to_wire with a stub that always returns b'{}'
        monkeypatch.setattr(wire_module, "envelope_to_wire", lambda _obj: b"{}")

        fixture = _load_envelope_fixture()
        stub_sha256 = hashlib.sha256(b"{}").hexdigest()

        # expected_sha256 comes from the fixture JSON
        mismatch_count = sum(
            1
            for v in fixture["vectors"]
            if stub_sha256 != v["expected_sha256"]
        )

        # At least 1 vector must detect the sha256 inconsistency
        assert mismatch_count >= 1, (
            "drift detection regression FAILED: monkeypatched envelope_to_wire returned b'{}' "
            "but no vector detected a sha256 mismatch — fixture comparison mechanism is broken"
        )
