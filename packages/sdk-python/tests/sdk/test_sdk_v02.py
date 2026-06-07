"""sdk v0.2 unit tests (pytest)

Coverage: six cases for the transport verifier's mTLS / JWT / OAuth2 paths

Test naming convention: should_<expected behavior>_when_<condition>

Note: the mTLS/JWT/OAuth2 verifier tests use dynamically generated key material (to avoid hardcoded secrets).
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from coivitas.sdk import (
    SDK_VERSION,
    SdkError,
    SdkErrorCode,
    TrustedSettlerDid,
    VerifiedTransportContext,
    verify_jwt_and_derive_did,
    verify_mtls_and_derive_did,
    verify_oauth2_and_derive_did,
)


# ─── TrustedSettlerDid brand guard ────────────────────────────────
class TestTrustedSettlerDidBrandGuard:
    """brand guard: TrustedSettlerDid cannot be constructed directly."""

    def should_raise_when_direct_construction_attempted(self) -> None:
        """brand guard: calling TrustedSettlerDid(value) directly should raise TypeError."""
        with pytest.raises(TypeError, match="verify_mtls_and_derive_did"):
            TrustedSettlerDid("did:key:abc123")


# ─── VerifiedTransportContext ─────────────────────────────────────
class TestVerifiedTransportContext:
    """VerifiedTransportContext basic-property validation."""

    def _make_vtx(self, kind: str = "mtls") -> VerifiedTransportContext:
        """Build a VerifiedTransportContext for testing (internal construction, bypassing the brand guard)."""
        return VerifiedTransportContext(
            trustedDid="did:key:test-did-001",
            verifierKind=kind,
            verifiedSubject="did:key:test-did-001",
            verifiedAt=datetime.now(tz=timezone.utc),
            sdkVersion=SDK_VERSION,
        )

    def should_have_sdk_version_200_when_constructed(self) -> None:
        """The sdkVersion default value must be '2.0.0'."""
        vtx = self._make_vtx()
        assert vtx.sdkVersion == SDK_VERSION

    def should_be_fresh_when_just_created(self) -> None:
        """A just-created VerifiedTransportContext should pass the is_fresh() check."""
        vtx = self._make_vtx()
        assert vtx.is_fresh(max_age_seconds=300.0)

    def should_be_stale_when_verified_at_too_old(self) -> None:
        """When verifiedAt exceeds max_age_seconds, is_fresh() should return False."""
        vtx = VerifiedTransportContext(
            trustedDid="did:key:old",
            verifierKind="mtls",
            verifiedSubject="did:key:old",
            verifiedAt=datetime.now(tz=timezone.utc) - timedelta(seconds=400),
            sdkVersion=SDK_VERSION,
        )
        assert not vtx.is_fresh(max_age_seconds=300.0)


# ─── Case 1: mTLS verify success ──────────────────────────────────
class TestMtlsVerifier:
    """Case 1-2: mTLS verifier (uses cryptography to generate certificates dynamically)."""

    def _generate_test_cert_and_ca(
        self, cn: str
    ) -> tuple[str, str]:
        """Dynamically generate a self-signed CA + client certificate (for testing only).

        Returns:
            (cert_pem, ca_pem)
        """
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        # Generate the CA key
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(tz=timezone.utc) - timedelta(hours=1))
            .not_valid_after(datetime.now(tz=timezone.utc) + timedelta(hours=24))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()

        # Generate the client key + certificate (CN = DID)
        client_key = ec.generate_private_key(ec.SECP256R1())
        client_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        client_cert = (
            x509.CertificateBuilder()
            .subject_name(client_name)
            .issuer_name(ca_name)
            .public_key(client_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(tz=timezone.utc) - timedelta(hours=1))
            .not_valid_after(datetime.now(tz=timezone.utc) + timedelta(hours=24))
            .sign(ca_key, hashes.SHA256())
        )
        cert_pem = client_cert.public_bytes(serialization.Encoding.PEM).decode()

        return cert_pem, ca_pem

    def should_return_vtx_when_cert_valid_and_did_matches(self) -> None:
        """Case 1 mTLS success: valid certificate + matching DID -> returns VerifiedTransportContext."""
        expected_did = "did:key:zQ3shmtest001"
        cert_pem, ca_pem = self._generate_test_cert_and_ca(expected_did)

        vtx = verify_mtls_and_derive_did(cert_pem, ca_pem, expected_did)

        assert vtx.verifierKind == "mtls"
        assert vtx.trustedDid == expected_did
        assert vtx.sdkVersion == SDK_VERSION
        assert vtx.verifiedSubject == expected_did

    def should_raise_sdk_mapping_mismatch_when_did_differs(self) -> None:
        """Case 2 mTLS fail: cert CN != expected_did -> SDK_MAPPING_MISMATCH."""
        actual_did = "did:key:zQ3shmActual"
        expected_did = "did:key:zQ3shmExpected"
        cert_pem, ca_pem = self._generate_test_cert_and_ca(actual_did)

        with pytest.raises(SdkError) as exc_info:
            verify_mtls_and_derive_did(cert_pem, ca_pem, expected_did)
        assert exc_info.value.code == SdkErrorCode.SDK_MAPPING_MISMATCH

    def should_raise_when_invalid_pem_provided(self) -> None:
        """An invalid PEM should raise SdkError(SDK_MTLS_VERIFY_FAILED)."""
        with pytest.raises(SdkError) as exc_info:
            verify_mtls_and_derive_did("not-valid-pem", "not-valid-ca-pem", "did:key:test")
        assert exc_info.value.code == SdkErrorCode.SDK_MTLS_VERIFY_FAILED


# ─── Case 3-4: JWT verify ──────────────────────────────────────────
def _authlib_available() -> bool:
    """Check whether authlib is available (skip gracefully when sandbox pip is restricted)."""
    try:
        import authlib  # noqa: F401
        return True
    except ModuleNotFoundError:
        return False


@pytest.mark.skipif(not _authlib_available(), reason="authlib not installed; skip JWT tests")
class TestJwtVerifier:
    """Case 3-4: JWT verifier (uses authlib + dynamically generated RSA keys)."""

    def _make_test_jwt(
        self,
        subject: str,
        issuer: str,
        audience: str,
        exp_offset: int = 3600,
        private_key_pem: str | None = None,
    ) -> tuple[str, str, str]:
        """Generate a JWT for testing + the corresponding RSA public key JSON.

        Returns:
            (jwt_token_str, private_key_pem, public_key_jwk_json)
        """
        from authlib.jose import JsonWebKey, jwt
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        # Generate the RSA key pair
        if private_key_pem is None:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            private_key_pem_bytes = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
            private_key_pem = private_key_pem_bytes.decode()
            public_key_pem = private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()
        else:
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            pk = load_pem_private_key(private_key_pem.encode(), password=None)
            public_key_pem = pk.public_key().public_bytes(  # type: ignore[attr-defined]
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()

        # Generate the JWT
        header = {"alg": "RS256"}
        payload = {
            "iss": issuer,
            "sub": subject,
            "aud": audience,
            "exp": int(time.time()) + exp_offset,
            "iat": int(time.time()),
        }

        # Import the private key into authlib (signature: import_key(raw, options))
        jwk = JsonWebKey.import_key(private_key_pem, {"kty": "RSA"})
        token = jwt.encode(header, payload, jwk).decode()

        # Export the public key as JWK JSON
        pub_jwk = JsonWebKey.import_key(public_key_pem, {"kty": "RSA"})
        import json
        pub_jwk_json = json.dumps(pub_jwk.as_dict())

        return token, private_key_pem, pub_jwk_json

    def should_return_vtx_when_jwt_valid(self) -> None:
        """Case 3 JWT success: a valid JWT -> VerifiedTransportContext(verifierKind='jwt')."""
        expected_did = "did:key:zQ3shmJwtTest001"
        issuer = "https://auth.example.com"
        audience = "coivitas"

        token, _, pub_jwk_json = self._make_test_jwt(expected_did, issuer, audience)

        vtx = verify_jwt_and_derive_did(token, pub_jwk_json, issuer, audience, expected_did)

        assert vtx.verifierKind == "jwt"
        assert vtx.trustedDid == expected_did
        assert vtx.sdkVersion == SDK_VERSION

    def should_raise_sdk_jwt_failed_when_token_expired(self) -> None:
        """Case 4 JWT fail: exp is in the past -> SDK_JWT_VERIFY_FAILED."""
        expected_did = "did:key:zQ3shmJwtExpired"
        issuer = "https://auth.example.com"
        audience = "coivitas"

        # exp_offset=-3600 -> already expired by 1 hour
        token, _, pub_jwk_json = self._make_test_jwt(
            expected_did, issuer, audience, exp_offset=-3600
        )

        with pytest.raises(SdkError) as exc_info:
            verify_jwt_and_derive_did(token, pub_jwk_json, issuer, audience, expected_did)
        assert exc_info.value.code == SdkErrorCode.SDK_JWT_VERIFY_FAILED

    def should_raise_sdk_mapping_mismatch_when_sub_differs(self) -> None:
        """JWT sub != expected_did -> SDK_MAPPING_MISMATCH."""
        actual_did = "did:key:zQ3shmActual"
        wrong_expected = "did:key:zQ3shmWrongExpected"
        issuer = "https://auth.example.com"
        audience = "coivitas"

        token, _, pub_jwk_json = self._make_test_jwt(actual_did, issuer, audience)

        with pytest.raises(SdkError) as exc_info:
            verify_jwt_and_derive_did(token, pub_jwk_json, issuer, audience, wrong_expected)
        assert exc_info.value.code == SdkErrorCode.SDK_MAPPING_MISMATCH

    def should_raise_when_iss_mismatch(self) -> None:
        """JWT iss != expected_issuer -> SDK_JWT_VERIFY_FAILED."""
        expected_did = "did:key:zQ3shmJwtIss"
        token, _, pub_jwk_json = self._make_test_jwt(
            expected_did, "https://wrong-iss.com", "coivitas"
        )

        with pytest.raises(SdkError) as exc_info:
            verify_jwt_and_derive_did(
                token, pub_jwk_json, "https://expected-iss.com", "coivitas", expected_did
            )
        assert exc_info.value.code == SdkErrorCode.SDK_JWT_VERIFY_FAILED


# ─── Case 5-6: OAuth2 verify ──────────────────────────────────────
class TestOAuth2Verifier:
    """Case 5-6: OAuth2 introspection verifier (mocked HTTP)."""

    def should_return_vtx_when_introspection_active(self) -> None:
        """Case 5 OAuth2 success: introspection active=true -> VerifiedTransportContext."""
        expected_did = "did:key:zQ3shmOAuth2Test001"
        client_id = "client-001"

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "active": True,
            "client_id": client_id,
            "sub": expected_did,
            "aud": "https://api.example.com",
        }
        mock_response.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_response):
            vtx = verify_oauth2_and_derive_did(
                access_token="test-token",
                introspection_endpoint="https://auth.example.com/introspect",
                client_id=client_id,
                client_secret="secret",
                expected_did=expected_did,
                expected_audience="https://api.example.com",
            )

        assert vtx.verifierKind == "oauth2"
        assert vtx.trustedDid == expected_did
        assert vtx.sdkVersion == SDK_VERSION

    def should_raise_sdk_oauth2_failed_when_token_inactive(self) -> None:
        """Case 6 OAuth2 fail: active=false -> SDK_OAUTH2_VERIFY_FAILED (fail-closed)."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"active": False}
        mock_response.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_response):
            with pytest.raises(SdkError) as exc_info:
                verify_oauth2_and_derive_did(
                    access_token="inactive-token",
                    introspection_endpoint="https://auth.example.com/introspect",
                    client_id="client-001",
                    client_secret="secret",
                    expected_did="did:key:zQ3shmOAuth2Test",
                    expected_audience="https://api.example.com",
                )
        assert exc_info.value.code == SdkErrorCode.SDK_OAUTH2_VERIFY_FAILED

    def should_raise_sdk_oauth2_failed_when_request_fails(self) -> None:
        """A network error / HTTP error should raise SdkError(SDK_OAUTH2_VERIFY_FAILED)."""
        with patch("requests.post", side_effect=Exception("connection refused")):
            with pytest.raises(SdkError) as exc_info:
                verify_oauth2_and_derive_did(
                    access_token="token",
                    introspection_endpoint="https://unreachable.example.com/introspect",
                    client_id="client-001",
                    client_secret="secret",
                    expected_did="did:key:test",
                    expected_audience="https://api.example.com",
                )
        assert exc_info.value.code == SdkErrorCode.SDK_OAUTH2_VERIFY_FAILED

    def should_raise_sdk_mapping_mismatch_when_sub_differs(self) -> None:
        """OAuth2 sub != expected_did -> SDK_MAPPING_MISMATCH."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "active": True,
            "client_id": "client-001",
            "sub": "did:key:zQ3shmActualSub",
            "aud": "https://api.example.com",
        }
        mock_response.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_response):
            with pytest.raises(SdkError) as exc_info:
                verify_oauth2_and_derive_did(
                    access_token="token",
                    introspection_endpoint="https://auth.example.com/introspect",
                    client_id="client-001",
                    client_secret="secret",
                    expected_did="did:key:zQ3shmDifferentExpected",
                    expected_audience="https://api.example.com",
                )
        assert exc_info.value.code == SdkErrorCode.SDK_MAPPING_MISMATCH

    def should_raise_sdk_oauth2_failed_when_aud_mismatch(self) -> None:
        """aud does not contain expected_audience -> SDK_OAUTH2_VERIFY_FAILED (fail-closed)."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "active": True,
            "client_id": "client-001",
            "sub": "did:key:zQ3shmOAuth2Test001",
            "aud": "https://other-resource.example.com",
        }
        mock_response.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_response):
            with pytest.raises(SdkError) as exc_info:
                verify_oauth2_and_derive_did(
                    access_token="token-for-other-resource",
                    introspection_endpoint="https://auth.example.com/introspect",
                    client_id="client-001",
                    client_secret="secret",
                    expected_did="did:key:zQ3shmOAuth2Test001",
                    expected_audience="https://api.example.com",
                )
        assert exc_info.value.code == SdkErrorCode.SDK_OAUTH2_VERIFY_FAILED
