"""sdk v0.2 transport verifier factory functions.

      verify_mtls_and_derive_did   — X.509 mTLS certificate chain + DID extraction
      verify_jwt_and_derive_did    — JWT RS256/ES256 signature + claims verification
      verify_oauth2_and_derive_did — OAuth2 introspection + client_id mapping

Design principles (fail-closed)
----------------------------
- each verifier raises SdkError on any failure path (a stub default success is strictly forbidden)
- DID mapping cross-check: verifiedSubject <-> trustedDid consistency verification
- returns VerifiedTransportContext (contains the TrustedSettlerDid brand + verifierKind metadata)

Dependencies
------------
- authlib>=1.3,<2 (JWT verify + OAuth2 introspection)
- cryptography>=42.0 (X.509 cert parse)
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from .types import (
    SDK_VERSION,
    SdkError,
    SdkErrorCode,
    TrustedSettlerDid,
    VerifiedTransportContext,
)

# ─── DID format validation regex (aligned with _brands.py _DID_PATTERN) ──────────────
_DID_PATTERN = re.compile(r"^did:[a-z][a-z0-9-]*:[a-zA-Z0-9._%-]+(?::[a-zA-Z0-9._%-]+)*$")


def _validate_did(did: str, context: str) -> None:
    """Validate DID format; on failure -> SdkError(SDK_MAPPING_MISMATCH)."""
    if not _DID_PATTERN.match(did):
        raise SdkError(
            SdkErrorCode.SDK_MAPPING_MISMATCH,
            f"{context}: invalid DID format: {did!r}",
        )


def _make_trusted_did(did: str) -> TrustedSettlerDid:
    """Internal factory construction of the TrustedSettlerDid brand (cannot be bypassed externally)."""
    return TrustedSettlerDid(did, _sentinel=TrustedSettlerDid._FACTORY_SENTINEL)


# ─── verify_mtls_and_derive_did ────────────────────────────────
def verify_mtls_and_derive_did(
    cert_pem: str,
    trusted_ca_pem: str,
    expected_did: str,
) -> VerifiedTransportContext:
    """mTLS certificate chain verification + DID extraction (sdk v0.2).

    Algorithm
    ---------
    1. parse cert_pem (PEM-format X.509 client certificate)
    2. verify the certificate chain: cert issued by trusted_ca_pem (load the CA to verify the cert signature)
    3. verify the cert has not expired (notAfter > now)
    4. extract the DID from the cert Subject CN (CN=did:xxx:yyy format)
    5. cross-check: extracted DID == expected_did (literal DID equality)
    6. return VerifiedTransportContext

    Failure paths (fail-closed)
    ----------------------
    any step failing -> SdkError(SDK_MTLS_VERIFY_FAILED or SDK_MAPPING_MISMATCH)

    Args:
        cert_pem: the client certificate (PEM-encoded)
        trusted_ca_pem: the trusted CA certificate (PEM-encoded)
        expected_did: the DID declared by the caller (used for cross-check)

    Returns:
        VerifiedTransportContext (verifierKind="mtls")

    Raises:
        SdkError(SDK_MTLS_VERIFY_FAILED): certificate chain verification failed
        SdkError(SDK_MAPPING_MISMATCH): DID extraction or cross-check failed
    """
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.x509.oid import NameOID

    now = datetime.now(tz=timezone.utc)

    # Step 1: parse the client certificate
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
    except Exception as exc:
        raise SdkError(
            SdkErrorCode.SDK_MTLS_VERIFY_FAILED,
            f"failed to parse client certificate PEM: {exc}",
        ) from exc

    # Step 2: verify the certificate has not expired
    not_after = cert.not_valid_after_utc
    if now > not_after:
        raise SdkError(
            SdkErrorCode.SDK_MTLS_VERIFY_FAILED,
            f"client certificate expired at {not_after.isoformat()}",
        )

    # Step 3: parse the CA certificate and verify the cert signature
    try:
        ca_cert = x509.load_pem_x509_certificate(trusted_ca_pem.encode())
    except Exception as exc:
        raise SdkError(
            SdkErrorCode.SDK_MTLS_VERIFY_FAILED,
            f"failed to parse trusted CA PEM: {exc}",
        ) from exc

    try:
        ca_public_key = ca_cert.public_key()
        # choose the verification method based on the CA public key type
        if isinstance(ca_public_key, rsa.RSAPublicKey):
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                PKCS1v15(),
                SHA256(),
            )
        elif isinstance(ca_public_key, ec.EllipticCurvePublicKey):
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(SHA256()),
            )
        else:
            raise SdkError(
                SdkErrorCode.SDK_MTLS_VERIFY_FAILED,
                f"unsupported CA public key type: {type(ca_public_key).__name__}",
            )
    except SdkError:
        raise
    except Exception as exc:
        raise SdkError(
            SdkErrorCode.SDK_MTLS_VERIFY_FAILED,
            f"certificate chain verification failed: {exc}",
        ) from exc

    # Step 4: extract the DID from the cert Subject CN
    try:
        cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not cn_attr:
            raise SdkError(
                SdkErrorCode.SDK_MTLS_VERIFY_FAILED,
                "certificate Subject has no CommonName (CN) attribute",
            )
        # cryptography attr.value is str | bytes; CN is always str but the type annotation is str | bytes
        cn_value_raw = cn_attr[0].value
        cn_value: str = cn_value_raw if isinstance(cn_value_raw, str) else cn_value_raw.decode("utf-8")
    except SdkError:
        raise
    except Exception as exc:
        raise SdkError(
            SdkErrorCode.SDK_MTLS_VERIFY_FAILED,
            f"failed to extract Subject CN: {exc}",
        ) from exc

    # CN must be a valid DID format
    _validate_did(cn_value, "cert Subject CN")

    # Step 5: DID cross-check
    if cn_value != expected_did:
        raise SdkError(
            SdkErrorCode.SDK_MAPPING_MISMATCH,
            f"cert CN DID mismatch: cert_cn={cn_value!r} != expected_did={expected_did!r}",
        )

    trusted_did = _make_trusted_did(cn_value)

    return VerifiedTransportContext(
        trustedDid=str(trusted_did),
        verifierKind="mtls",
        verifiedSubject=cn_value,
        verifiedAt=now,
        sdkVersion=SDK_VERSION,
    )


# ─── verify_jwt_and_derive_did ─────────────────────────────────
def verify_jwt_and_derive_did(
    jwt_token: str,
    jwks_uri_or_pem: str,
    expected_issuer: str,
    expected_audience: str,
    expected_did: str,
) -> VerifiedTransportContext:
    """JWT RS256/ES256 signature verification + DID extraction (sdk v0.2).

    Algorithm
    ---------
    1. parse the JWT header (without verification) to obtain alg + kid
    2. load the JWK from jwks_uri_or_pem (PEM format loads directly; URI format is not fetched in this implementation)
    3. verify the JWT signature (authlib.jose.jwt.decode)
    4. verify claims: iss == expected_issuer, aud == expected_audience, exp > now
    5. extract the DID from claims.sub
    6. cross-check: sub DID == expected_did
    7. return VerifiedTransportContext

    Failure paths (fail-closed)
    ----------------------
    any step failing -> SdkError(SDK_JWT_VERIFY_FAILED or SDK_MAPPING_MISMATCH)

    Args:
        jwt_token: JWT string (compact serialization)
        jwks_uri_or_pem: JWK PEM string (the current implementation only supports PEM; URI mode is not yet implemented)
        expected_issuer: the expected iss claim value
        expected_audience: the expected aud claim value
        expected_did: the DID declared by the caller (used for cross-check)

    Returns:
        VerifiedTransportContext (verifierKind="jwt")

    Raises:
        SdkError(SDK_JWT_VERIFY_FAILED): JWT verification failed
        SdkError(SDK_MAPPING_MISMATCH): sub DID extraction or cross-check failed
    """
    from authlib.jose import JsonWebKey, jwt
    from authlib.jose.errors import JoseError

    now = datetime.now(tz=timezone.utc)

    # Step 1-3: verify the JWT signature (authlib.jose.jwt.decode includes signature verification)
    try:
        # jwks_uri_or_pem currently only supports PEM format (detected by the string starting with "-----BEGIN")
        if jwks_uri_or_pem.strip().startswith("-----BEGIN"):
            # PEM format: import directly. authlib's signature is
            # import_key(raw_key, options); the PEM string is the raw key and the
            # kty hint goes in options.
            key = JsonWebKey.import_key(jwks_uri_or_pem, {"kty": "RSA"})
        else:
            # JSON JWK string (dict format)
            import json

            jwk_dict = json.loads(jwks_uri_or_pem)
            key = JsonWebKey.import_key(jwk_dict)
    except Exception as exc:
        raise SdkError(
            SdkErrorCode.SDK_JWT_VERIFY_FAILED,
            f"failed to load JWK/PEM for JWT verification: {exc}",
        ) from exc

    try:
        claims = jwt.decode(jwt_token, key)  # type: ignore[arg-type]
    except JoseError as exc:
        raise SdkError(
            SdkErrorCode.SDK_JWT_VERIFY_FAILED,
            f"JWT signature verification failed: {exc}",
        ) from exc
    except Exception as exc:
        raise SdkError(
            SdkErrorCode.SDK_JWT_VERIFY_FAILED,
            f"JWT decode error: {exc}",
        ) from exc

    # Step 4: verify claims
    # iss verification
    if claims.get("iss") != expected_issuer:
        raise SdkError(
            SdkErrorCode.SDK_JWT_VERIFY_FAILED,
            f"JWT iss mismatch: got={claims.get('iss')!r}, expected={expected_issuer!r}",
        )
    # aud verification (aud may be a string or a list)
    aud = claims.get("aud")
    aud_list = [aud] if isinstance(aud, str) else (aud if isinstance(aud, list) else [])
    if expected_audience not in aud_list:
        raise SdkError(
            SdkErrorCode.SDK_JWT_VERIFY_FAILED,
            f"JWT aud mismatch: aud={aud!r}, expected={expected_audience!r}",
        )
    # exp verification
    exp = claims.get("exp")
    if exp is None:
        raise SdkError(
            SdkErrorCode.SDK_JWT_VERIFY_FAILED,
            "JWT missing 'exp' claim",
        )
    if now.timestamp() > exp:
        raise SdkError(
            SdkErrorCode.SDK_JWT_VERIFY_FAILED,
            f"JWT expired: exp={exp}, now={now.timestamp()}",
        )

    # Step 5: extract the DID from sub
    sub = claims.get("sub")
    if not sub or not isinstance(sub, str):
        raise SdkError(
            SdkErrorCode.SDK_JWT_VERIFY_FAILED,
            "JWT missing or invalid 'sub' claim",
        )
    _validate_did(sub, "JWT sub")

    # Step 6: DID cross-check
    if sub != expected_did:
        raise SdkError(
            SdkErrorCode.SDK_MAPPING_MISMATCH,
            f"JWT sub DID mismatch: sub={sub!r} != expected_did={expected_did!r}",
        )

    trusted_did = _make_trusted_did(sub)

    return VerifiedTransportContext(
        trustedDid=str(trusted_did),
        verifierKind="jwt",
        verifiedSubject=sub,
        verifiedAt=now,
        sdkVersion=SDK_VERSION,
    )


# ─── verify_oauth2_and_derive_did ──────────────────────────────
def verify_oauth2_and_derive_did(
    access_token: str,
    introspection_endpoint: str,
    client_id: str,
    client_secret: str,
    expected_did: str,
    expected_audience: str,
) -> VerifiedTransportContext:
    """OAuth2 token introspection + DID mapping (sdk v0.2).

    Algorithm
    ---------
    1. POST introspection_endpoint (RFC 7662) with access_token
    2. verify the introspection response: active == True
    3. verify client_id == introspection response.client_id
    3.5 verify aud contains expected_audience (fail-closed, aligned with the TS/JWT path)
    4. extract the DID from introspection response.sub
    5. cross-check: sub DID == expected_did
    6. return VerifiedTransportContext

    Failure paths (fail-closed)
    ----------------------
    any step failing -> SdkError(SDK_OAUTH2_VERIFY_FAILED or SDK_MAPPING_MISMATCH)

    Args:
        access_token: the OAuth2 access token to verify
        introspection_endpoint: RFC 7662 introspection endpoint URL
        client_id: OAuth2 client_id (used for verification + DID mapping)
        client_secret: OAuth2 client_secret (Basic Auth)
        expected_did: the DID declared by the caller (used for cross-check)
        expected_audience: the expected aud value (the token must be intended for this resource;
            otherwise a token for the same DID/client but issued for another resource would also pass)

    Returns:
        VerifiedTransportContext (verifierKind="oauth2")

    Raises:
        SdkError(SDK_OAUTH2_VERIFY_FAILED): introspection failed / token inactive / aud mismatch
        SdkError(SDK_MAPPING_MISMATCH): sub DID extraction or cross-check failed
    """
    import requests

    now = datetime.now(tz=timezone.utc)

    # Step 1: POST introspection endpoint
    try:
        resp = requests.post(
            introspection_endpoint,
            data={"token": access_token, "token_type_hint": "access_token"},
            auth=(client_id, client_secret),
            timeout=10,
        )
        resp.raise_for_status()
        introspection = resp.json()
    except SdkError:
        raise
    except Exception as exc:
        raise SdkError(
            SdkErrorCode.SDK_OAUTH2_VERIFY_FAILED,
            f"OAuth2 introspection request failed: {exc}",
        ) from exc

    # Step 2: verify active == True
    if not introspection.get("active"):
        raise SdkError(
            SdkErrorCode.SDK_OAUTH2_VERIFY_FAILED,
            f"OAuth2 token inactive: introspection response active={introspection.get('active')!r}",
        )

    # Step 3: verify client_id
    resp_client_id = introspection.get("client_id")
    if resp_client_id != client_id:
        raise SdkError(
            SdkErrorCode.SDK_OAUTH2_VERIFY_FAILED,
            f"OAuth2 client_id mismatch: response={resp_client_id!r}, expected={client_id!r}",
        )

    # Step 3.5: verify aud contains expected_audience (fail-closed)
    #   RFC 7662 aud may be a str or list[str]; missing / not str|list / not containing expected -> reject.
    #   Prevents a token for the same DID/client but intended for another resource from being accepted at this resource.
    resp_aud = introspection.get("aud")
    if isinstance(resp_aud, str):
        aud_list = [resp_aud]
    elif isinstance(resp_aud, list):
        aud_list = resp_aud
    else:
        aud_list = []
    if expected_audience not in aud_list:
        raise SdkError(
            SdkErrorCode.SDK_OAUTH2_VERIFY_FAILED,
            f"OAuth2 aud mismatch: aud={resp_aud!r}, expected={expected_audience!r}",
        )

    # Step 4: extract the DID from sub
    sub = introspection.get("sub")
    if not sub or not isinstance(sub, str):
        raise SdkError(
            SdkErrorCode.SDK_OAUTH2_VERIFY_FAILED,
            "OAuth2 introspection response missing or invalid 'sub'",
        )
    _validate_did(sub, "OAuth2 introspection sub")

    # Step 5: DID cross-check
    if sub != expected_did:
        raise SdkError(
            SdkErrorCode.SDK_MAPPING_MISMATCH,
            f"OAuth2 sub DID mismatch: sub={sub!r} != expected_did={expected_did!r}",
        )

    trusted_did = _make_trusted_did(sub)

    return VerifiedTransportContext(
        trustedDid=str(trusted_did),
        verifierKind="oauth2",
        verifiedSubject=sub,
        verifiedAt=now,
        sdkVersion=SDK_VERSION,
    )


__all__ = [
    "verify_mtls_and_derive_did",
    "verify_jwt_and_derive_did",
    "verify_oauth2_and_derive_did",
]
