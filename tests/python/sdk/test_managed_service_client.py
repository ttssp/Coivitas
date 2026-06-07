"""ManagedServiceClient + ManagedServiceError behavioral contract tests.

Anti self-equal
---------------
Every assert touches the ``ManagedServiceClient`` / ``ManagedServiceError``
production code; it is not a mock equaling itself.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from coivitas import (
    AgentIdentityDocument,
    ManagedServiceClient,
    ManagedServiceClientConfig,
    ManagedServiceError,
    ManagedServiceErrorCode,
    RevocationResult,
)


class _StubResolver:
    """Compatible with the ``FederatedResolver`` Protocol, implementing ``resolve(did)``.

    Literally aligned with the TS ``FederatedResolver`` interface:
    ``resolve(did: DID): Promise<AgentIdentityDocument | null>``.
    If the stub instead used ``resolve_did(did)`` -- not matching the interface --
    then wiring in any interface-conformant fallback resolver would raise
    AttributeError.
    """

    def __init__(self, response):
        self._response = response

    async def resolve(self, did):
        return self._response


class _LegacyStubResolverWithResolveDidOnly:
    """Legacy stub: has only ``.resolve_did(did)`` and not ``.resolve(did)``.

    Used to verify the legacy stub cannot be used -- confirming the binding layer
    uses ``.resolve()`` in literal alignment with the TS interface, no longer
    tolerating drifted names.
    """

    def __init__(self, response):
        self._response = response

    async def resolve_did(self, did):
        return self._response


# --- ManagedServiceError field contract ---


class TestManagedServiceErrorContract:
    def test_construct_with_str_enum_code(self) -> None:
        err = ManagedServiceError(
            ManagedServiceErrorCode.MANAGED_SERVICE_CLIENT_ERROR,
            "test failure",
        )
        assert err.code == "MANAGED_SERVICE_CLIENT_ERROR"
        assert err.message == "test failure"
        assert err.cause is None

    def test_construct_with_str_literal_code(self) -> None:
        err = ManagedServiceError(
            "MANAGED_SERVICE_RATE_LIMITED",
            "rate limited",
        )
        assert err.code == "MANAGED_SERVICE_RATE_LIMITED"

    def test_unknown_code_string_rejected(self) -> None:
        """The error code is a Literal type alias; fail-closed to guard against typos."""
        with pytest.raises(ValueError, match="unknown ManagedServiceErrorCode"):
            ManagedServiceError("ARBITRARY_TYPO", "x")

    def test_with_cause_chain(self) -> None:
        cause = RuntimeError("upstream")
        err = ManagedServiceError(
            "MANAGED_SERVICE_CLIENT_ERROR",
            "wrapped",
            cause=cause,
        )
        assert err.cause is cause


# --- ManagedServiceClientConfig BaseModel ---


class TestManagedServiceClientConfigShape:
    def test_minimal_config_with_fallback_only(self) -> None:
        config = ManagedServiceClientConfig(
            fallbackResolver=_StubResolver(None),
        )
        assert config.service_url is None
        assert config.api_key is None
        assert config.timeout_ms == 5000
        assert config.max_retries == 0

    def test_full_config(self) -> None:
        config = ManagedServiceClientConfig(
            serviceUrl="https://service.example",
            apiKey="key-001",
            timeoutMs=10000,
            maxRetries=3,
            fallbackResolver=_StubResolver(None),
        )
        assert config.service_url == "https://service.example"
        assert config.timeout_ms == 10000


# --- ManagedServiceClient.resolve_did behavior (fetch guard) ---


class TestManagedServiceClientResolveDid:
    def test_constructor_rejects_service_url_without_unsafe_opt_in(
        self,
    ) -> None:
        """service_url configured but unsafe not opted in -> constructor rejects.

        Before the fix: runtime raised NotImplementedError (triggered on the first
        resolve_did);
        after the fix: the constructor rejects directly, moving the failure point
        from runtime forward to construct-time, making the released API surface
        fail-closed.
        """
        config = ManagedServiceClientConfig(
            serviceUrl="https://service.example",
            apiKey="key",
            fallbackResolver=_StubResolver(None),
        )
        with pytest.raises(ValueError, match="service_url is configured"):
            ManagedServiceClient(config)

    def test_constructor_rejects_anonymous_service_url_without_unsafe_opt_in(
        self,
    ) -> None:
        """An anonymous service_url (api_key=None) must also opt in to unsafe."""
        config = ManagedServiceClientConfig(
            serviceUrl="https://service.example",
            fallbackResolver=_StubResolver(None),
        )
        with pytest.raises(ValueError, match="service_url is configured"):
            ManagedServiceClient(config)

    def test_constructor_rejects_base_class_with_opt_in_false_safety(
        self,
    ) -> None:
        """base class + opt-in still rejects (false-safety guard).

        opt-in alone is not enough -- a base-class instance + opt-in would fail on
        the first resolve_did, bypassing the release gate.
        Constraint: require a subclass to override resolve_did + check_revocation,
        binding transport evidence to construct-time (replacing the false-safety of
        opt-in alone).
        """
        config = ManagedServiceClientConfig(
            serviceUrl="https://service.example",
            apiKey="key",
            fallbackResolver=_StubResolver(None),
        )
        # base class + opt-in (no subclass-override evidence) -> false-safety guard rejects
        with pytest.raises(ValueError, match="false-safety guard"):
            ManagedServiceClient(config, allow_unsafe_service_url=True)

    def test_constructor_rejects_anonymous_base_class_with_opt_in(
        self,
    ) -> None:
        """anonymous service_url + base class + opt-in is likewise rejected."""
        config = ManagedServiceClientConfig(
            serviceUrl="https://service.example",
            fallbackResolver=_StubResolver(None),
        )
        assert config.api_key is None
        with pytest.raises(ValueError, match="false-safety guard"):
            ManagedServiceClient(config, allow_unsafe_service_url=True)

    @pytest.mark.asyncio
    async def test_subclass_override_both_methods_succeeds_with_opt_in(
        self,
    ) -> None:
        """Positive: subclass overrides resolve_did + check_revocation
        + opt-in -> constructor passes, real transport injection path.
        """

        class _SubclassedClient(ManagedServiceClient):
            async def resolve_did(self, did: str):
                # Real transport injection evidence (subclass overrides the base method)
                return None

            async def check_revocation(self, credential_id: str):
                return RevocationResult(
                    credentialId=credential_id,
                    revoked=False,
                    fallbackReason=None,
                )

        config = ManagedServiceClientConfig(
            serviceUrl="https://service.example",
            apiKey="key",
            fallbackResolver=_StubResolver(None),
        )
        # Subclass overrides both methods + opt-in -> valid
        client = _SubclassedClient(config, allow_unsafe_service_url=True)
        # The subclass's real resolve_did path does not raise NotImplementedError
        result = await client.resolve_did("did:agent:" + "a" * 40)
        assert result is None

    def test_constructor_rejects_subclass_overriding_only_resolve_did(
        self,
    ) -> None:
        """Overriding only resolve_did, not check_revocation
        -> reject (transport is considered complete only when both methods are overridden).
        """

        class _PartialSubclass(ManagedServiceClient):
            async def resolve_did(self, did: str):
                return None

            # check_revocation not overridden -> incomplete transport

        config = ManagedServiceClientConfig(
            serviceUrl="https://service.example",
            fallbackResolver=_StubResolver(None),
        )
        with pytest.raises(ValueError, match="false-safety guard"):
            _PartialSubclass(config, allow_unsafe_service_url=True)

    def test_constructor_rejects_subclass_overriding_only_check_revocation(
        self,
    ) -> None:
        """Overriding only check_revocation, not resolve_did
        -> reject (the reverse-direction partial override is likewise fail-closed).
        """

        class _PartialSubclass(ManagedServiceClient):
            async def check_revocation(self, credential_id: str):
                return RevocationResult(
                    credentialId=credential_id,
                    revoked=False,
                    fallbackReason=None,
                )

            # resolve_did not overridden -> incomplete transport

        config = ManagedServiceClientConfig(
            serviceUrl="https://service.example",
            fallbackResolver=_StubResolver(None),
        )
        with pytest.raises(ValueError, match="false-safety guard"):
            _PartialSubclass(config, allow_unsafe_service_url=True)

    @pytest.mark.asyncio
    async def test_resolve_did_no_service_url_uses_fallback_resolver(
        self,
    ) -> None:
        """When service_url=None, use the fallback_resolver; matches the TS implementation."""
        valid_doc = {
            "id": "did:agent:" + "c" * 40,
            "specVersion": "0.1.0",
            "principalDid": "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
            "publicKey": "e" * 64,
            "bindingProof": {
                "principalDid": "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
                "agentDid": "did:agent:" + "0" * 40,
                "issuedAt": "2026-05-07T12:00:00.000Z",
                "expiresAt": None,
                "signature": "0" * 128,
            },
            "createdAt": "2026-05-07T12:00:00.000Z",
            "updatedAt": "2026-05-07T12:00:00.000Z",
        }
        config = ManagedServiceClientConfig(
            # Deliberately leave serviceUrl unset
            fallbackResolver=_StubResolver(valid_doc),
        )
        client = ManagedServiceClient(config)
        result = await client.resolve_did("did:agent:" + "c" * 40)
        assert isinstance(result, AgentIdentityDocument)
        assert result.id == "did:agent:" + "c" * 40

    @pytest.mark.asyncio
    async def test_resolve_did_returns_none_when_fallback_returns_none(
        self,
    ) -> None:
        config = ManagedServiceClientConfig(
            fallbackResolver=_StubResolver(None),
        )
        client = ManagedServiceClient(config)
        result = await client.resolve_did("did:agent:" + "f" * 40)
        assert result is None

    @pytest.mark.asyncio
    async def test_resolve_did_validates_dict_via_base_model(self) -> None:
        """fallback returns a dict -> AgentIdentityDocument strict validation."""
        valid_doc = {
            "id": "did:agent:" + "a" * 40,
            "specVersion": "0.1.0",
            "principalDid": "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
            "publicKey": "d" * 64,
            "bindingProof": {
                "principalDid": "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
                "agentDid": "did:agent:" + "0" * 40,
                "issuedAt": "2026-05-07T12:00:00.000Z",
                "expiresAt": None,
                "signature": "0" * 128,
            },
            "createdAt": "2026-05-07T12:00:00.000Z",
            "updatedAt": "2026-05-07T12:00:00.000Z",
        }
        config = ManagedServiceClientConfig(
            fallbackResolver=_StubResolver(valid_doc),
        )
        client = ManagedServiceClient(config)
        result = await client.resolve_did("did:agent:" + "a" * 40)
        assert isinstance(result, AgentIdentityDocument)
        assert result.id == "did:agent:" + "a" * 40

    @pytest.mark.asyncio
    async def test_resolve_did_invalid_dict_raises_validation_error(self) -> None:
        """fail-closed: non-dict / wrong shape -> exception."""
        config = ManagedServiceClientConfig(
            fallbackResolver=_StubResolver({"missing": "fields"}),
        )
        client = ManagedServiceClient(config)
        with pytest.raises((ValidationError, Exception)):
            await client.resolve_did("did:agent:" + "a" * 40)

    @pytest.mark.asyncio
    async def test_resolve_did_non_dict_raises_managed_service_error(self) -> None:
        """fallback returns non-dict / non-None -> ManagedServiceError."""
        config = ManagedServiceClientConfig(
            fallbackResolver=_StubResolver("not-a-dict"),
        )
        client = ManagedServiceClient(config)
        with pytest.raises(ManagedServiceError, match="non-dict"):
            await client.resolve_did("did:agent:" + "a" * 40)


# --- extra="forbid" regression tests ---
# AgentIdentityDocument extra="forbid" + nested BindingProof/RotationProof strict
# typing block schema-invalid resolver fallback (extra="forbid" + nested BaseModel).


class TestAgentIdentityDocumentExtraForbid:
    """AgentIdentityDocument trust-boundary fail-closed."""

    @pytest.mark.asyncio
    async def test_resolver_fallback_rejects_extra_top_level_field(self) -> None:
        """A resolver fallback dict with an unknown top-level field -> AgentIdentityDocument rejects.

        Before the fix: extra="allow" let arbitrary fields like attackerInjected pass through;
        after the fix: extra="forbid" is fail-closed at the SDK boundary.
        """
        attacker_doc = {
            "id": "did:agent:" + "a" * 40,
            "specVersion": "0.1.0",
            "principalDid": "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
            "publicKey": "d" * 64,
            "bindingProof": {
                "principalDid": "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
                "agentDid": "did:agent:" + "0" * 40,
                "issuedAt": "2026-05-07T12:00:00.000Z",
                "expiresAt": None,
                "signature": "0" * 128,
            },
            "createdAt": "2026-05-07T12:00:00.000Z",
            "updatedAt": "2026-05-07T12:00:00.000Z",
            # Attacker-injected unknown fields
            "attackerInjected": 1,
            "totallyWrong": "evil",
        }
        config = ManagedServiceClientConfig(
            fallbackResolver=_StubResolver(attacker_doc),
        )
        client = ManagedServiceClient(config)
        # The pydantic ValidationError propagates upward (fail-closed; no silent downgrade)
        with pytest.raises(
            Exception
        ) as exc_info:  # noqa: B017 -- pydantic.ValidationError
            await client.resolve_did("did:agent:" + "a" * 40)
        # Verify the cause is a schema validation failure (pydantic ValidationError or ManagedServiceError)
        exc_str = str(exc_info.value)
        assert any(
            kw in exc_str.lower()
            for kw in ["validation", "extra_forbidden", "missing", "extra"]
        ), f"expected a schema validation error, got {exc_info.value!r}"

    @pytest.mark.asyncio
    async def test_resolver_fallback_rejects_malformed_binding_proof(self) -> None:
        """A resolver fallback bindingProof missing required fields -> rejected."""
        malformed_doc = {
            "id": "did:agent:" + "a" * 40,
            "specVersion": "0.1.0",
            "principalDid": "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
            "publicKey": "d" * 64,
            # bindingProof nesting is incomplete -- accepted before the fix (extra="allow" + dict[Any]);
            # rejected after the fix (BindingProof strict typing + extra="forbid")
            "bindingProof": {"totally": "wrong"},
            "createdAt": "2026-05-07T12:00:00.000Z",
            "updatedAt": "2026-05-07T12:00:00.000Z",
        }
        config = ManagedServiceClientConfig(
            fallbackResolver=_StubResolver(malformed_doc),
        )
        client = ManagedServiceClient(config)
        # The pydantic ValidationError propagates upward (fail-closed; no silent downgrade)
        with pytest.raises(
            Exception
        ) as exc_info:  # noqa: B017 -- pydantic.ValidationError
            await client.resolve_did("did:agent:" + "a" * 40)
        # Verify the cause is a schema validation failure (pydantic ValidationError or ManagedServiceError)
        exc_str = str(exc_info.value)
        assert any(
            kw in exc_str.lower()
            for kw in ["validation", "extra_forbidden", "missing", "extra"]
        ), f"expected a schema validation error, got {exc_info.value!r}"

    @pytest.mark.asyncio
    async def test_resolver_fallback_rejects_extra_field_in_nested_binding_proof(
        self,
    ) -> None:
        """A nested BindingProof with an unknown field -> rejected (nested forbid)."""
        nested_attack = {
            "id": "did:agent:" + "a" * 40,
            "specVersion": "0.1.0",
            "principalDid": "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
            "publicKey": "d" * 64,
            "bindingProof": {
                "principalDid": "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
                "agentDid": "did:agent:" + "0" * 40,
                "issuedAt": "2026-05-07T12:00:00.000Z",
                "expiresAt": None,
                "signature": "0" * 128,
                "evilNestedField": "haha",  # attacker field at the nested level
            },
            "createdAt": "2026-05-07T12:00:00.000Z",
            "updatedAt": "2026-05-07T12:00:00.000Z",
        }
        config = ManagedServiceClientConfig(
            fallbackResolver=_StubResolver(nested_attack),
        )
        client = ManagedServiceClient(config)
        # The pydantic ValidationError propagates upward (fail-closed; no silent downgrade)
        with pytest.raises(
            Exception
        ) as exc_info:  # noqa: B017 -- pydantic.ValidationError
            await client.resolve_did("did:agent:" + "a" * 40)
        # Verify the cause is a schema validation failure (pydantic ValidationError or ManagedServiceError)
        exc_str = str(exc_info.value)
        assert any(
            kw in exc_str.lower()
            for kw in ["validation", "extra_forbidden", "missing", "extra"]
        ), f"expected a schema validation error, got {exc_info.value!r}"


# --- ManagedServiceClient.check_revocation ---


class TestManagedServiceClientCheckRevocation:
    @pytest.mark.asyncio
    async def test_stub_only_returns_unknown_with_fallback_reason(self) -> None:
        """stub fail-closed: when service_url is not configured -> revoked='unknown' +
        fallback_reason literal 'serviceUrl_not_configured'; does not return a default 200 body.

        The reason string literal is aligned with the TS implementation --
        ``'serviceUrl_not_configured'``; the legacy string
        ``'managed_service_not_configured'`` was an early Python-invented drift.
        """
        config = ManagedServiceClientConfig(
            fallbackResolver=_StubResolver(None),
        )
        client = ManagedServiceClient(config)
        result = await client.check_revocation("urn:cap:test")
        assert isinstance(result, RevocationResult)
        assert result.revoked == "unknown"
        assert result.fallback_reason == "serviceUrl_not_configured"

    def test_base_class_with_opt_in_rejected_for_check_revocation_path(
        self,
    ) -> None:
        """base class + opt-in is likewise rejected on the check_revocation path
        (the false-safety guard covers both methods).
        """
        config = ManagedServiceClientConfig(
            serviceUrl="https://service.example",
            apiKey="k",
            fallbackResolver=_StubResolver(None),
        )
        with pytest.raises(ValueError, match="false-safety guard"):
            ManagedServiceClient(config, allow_unsafe_service_url=True)

    def test_anonymous_base_class_with_opt_in_rejected_for_check_revocation(
        self,
    ) -> None:
        """anonymous service_url + base class + opt-in is likewise rejected.

        Configuring service_url alone (api_key=None) is treated as managed (matches
        the TS implementation), but requires real transport injection evidence
        (subclass override) -- base class + opt-in is rejected in both the anonymous
        and paid sub-modes.
        """
        config = ManagedServiceClientConfig(
            serviceUrl="https://service.example",
            fallbackResolver=_StubResolver(None),
        )
        assert config.api_key is None
        with pytest.raises(ValueError, match="false-safety guard"):
            ManagedServiceClient(config, allow_unsafe_service_url=True)

    @pytest.mark.asyncio
    async def test_subclass_override_check_revocation_succeeds_with_opt_in(
        self,
    ) -> None:
        """Positive: subclass overrides both methods + opt-in ->
        check_revocation takes the real transport path (does not raise NotImplementedError).
        """

        class _SubclassedClient(ManagedServiceClient):
            async def resolve_did(self, did: str):
                return None

            async def check_revocation(self, credential_id: str):
                return RevocationResult(
                    credentialId=credential_id,
                    revoked=False,
                    fallbackReason=None,
                )

        config = ManagedServiceClientConfig(
            serviceUrl="https://service.example",
            apiKey="k",
            fallbackResolver=_StubResolver(None),
        )
        client = _SubclassedClient(config, allow_unsafe_service_url=True)
        result = await client.check_revocation("urn:cap:test")
        assert result.revoked is False
        assert result.fallback_reason is None

    @pytest.mark.asyncio
    async def test_stub_only_triggers_on_fallback_with_correct_signature(
        self,
    ) -> None:
        """``on_fallback(reason: str, identifier: str)`` order +
        reason string matching TS.

        TS-side literal:
        ``onFallback?: (reason: string, identifier: string) => void;`` ->
        on trigger it calls ``onFallback?.(reason, identifier)``. Python must use
        the same order + the same string literals.
        """
        captured: list[tuple[str, str]] = []

        def cb(reason: str, identifier: str) -> None:
            captured.append((reason, identifier))

        config = ManagedServiceClientConfig(
            fallbackResolver=_StubResolver(None),
            onFallback=cb,
        )
        client = ManagedServiceClient(config)
        result = await client.check_revocation("urn:cap:abc-123")
        assert result.revoked == "unknown"
        assert result.fallback_reason == "serviceUrl_not_configured"
        # reason string 'serviceUrl_not_configured' (literally matches the TS implementation)
        assert captured == [
            ("serviceUrl_not_configured", "urn:cap:abc-123")
        ], f"on_fallback parameter+reason drift: {captured!r}"


# --- on_fallback signature guard ---


class TestOnFallbackParameterOrder:
    """``on_fallback(reason, identifier)`` ordering contract."""

    @pytest.mark.asyncio
    async def test_resolve_did_none_fallback_calls_on_fallback_with_reason_first(
        self,
    ) -> None:
        """When fallback_resolver returns None, on_fallback receives (reason, did).

        TS-side ``triggerFallback`` and ``onFallback`` literal contract:
        ``(reason, identifier)`` -- reason first.

        The service_url=None path **first** triggers
        ``('serviceUrl_not_configured', did)`` (literally aligned with the TS
        implementation), **then** delegates to the fallback resolver; when the
        fallback returns None it **then** triggers
        ``('fallback_resolver_returned_none', did)``. So captured length should be 2,
        in a fixed order.
        """
        captured: list[tuple[str, str]] = []

        def cb(reason: str, identifier: str) -> None:
            captured.append((reason, identifier))

        target_did = "did:agent:" + "9" * 40
        config = ManagedServiceClientConfig(
            fallbackResolver=_StubResolver(None),  # returning None triggers fallback
            onFallback=cb,
        )
        client = ManagedServiceClient(config)
        result = await client.resolve_did(target_did)
        assert result is None
        # First 'serviceUrl_not_configured' (the service_url=None entry-point
        # notification, literally aligned with the TS implementation), then
        # 'fallback_resolver_returned_none' (notified after the resolver returns
        # None). The reason order is fixed.
        assert captured == [
            ("serviceUrl_not_configured", target_did),
            ("fallback_resolver_returned_none", target_did),
        ], f"on_fallback signal sequence drift in resolve_did: {captured!r}"

    @pytest.mark.asyncio
    async def test_on_fallback_callback_exception_does_not_break_main_path(
        self,
    ) -> None:
        """A callback exception is swallowed; the main path still fail-closed returns None."""

        def bad_cb(reason: str, identifier: str) -> None:
            raise RuntimeError("metric backend down")

        config = ManagedServiceClientConfig(
            fallbackResolver=_StubResolver(None),
            onFallback=bad_cb,
        )
        client = ManagedServiceClient(config)
        # Does not raise RuntimeError; the main path returns None normally
        result = await client.resolve_did("did:agent:" + "0" * 40)
        assert result is None


# --- FederatedResolver.resolve(did) interface contract ---


class TestFederatedResolverInterfaceR3F3:
    """The fallback resolver must implement ``resolve(did)`` (literally aligned with
    the TS ``FederatedResolver`` interface), no longer tolerating the drifted name
    ``resolve_did(did)``.
    """

    @pytest.mark.asyncio
    async def test_spec_compliant_resolve_method_works(self) -> None:
        """Interface contract: fallback_resolver implements ``.resolve(did)`` -> works normally.

        Literally aligned with the TS implementation:
        ``return this.fallbackResolver.resolve(did as never);``
        """
        valid_doc = {
            "id": "did:agent:" + "1" * 40,
            "specVersion": "0.1.0",
            "principalDid": "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
            "publicKey": "3" * 64,
            "bindingProof": {
                "principalDid": "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
                "agentDid": "did:agent:" + "0" * 40,
                "issuedAt": "2026-05-07T12:00:00.000Z",
                "expiresAt": None,
                "signature": "0" * 128,
            },
            "createdAt": "2026-05-07T12:00:00.000Z",
            "updatedAt": "2026-05-07T12:00:00.000Z",
        }
        config = ManagedServiceClientConfig(
            fallbackResolver=_StubResolver(valid_doc),
        )
        client = ManagedServiceClient(config)
        result = await client.resolve_did("did:agent:" + "1" * 40)
        assert isinstance(result, AgentIdentityDocument)
        assert result.id == "did:agent:" + "1" * 40

    @pytest.mark.asyncio
    async def test_legacy_resolve_did_only_resolver_rejected(self) -> None:
        """Reverse assertion: a legacy stub that has only ``.resolve_did(did)`` and
        not ``.resolve(did)`` -> ManagedServiceError(MANAGED_SERVICE_CLIENT_ERROR).

        The early Python side once hard-coded ``getattr(_, "resolve_did")``;
        after the fix the binding layer uses ``.resolve()``, and the legacy stub
        should be explicitly rejected (with a clear error message pointing to the
        FederatedResolver interface).
        """
        config = ManagedServiceClientConfig(
            fallbackResolver=_LegacyStubResolverWithResolveDidOnly(None),
        )
        client = ManagedServiceClient(config)
        with pytest.raises(ManagedServiceError) as exc_info:
            await client.resolve_did("did:agent:" + "5" * 40)
        # The error message should point to the FederatedResolver interface docs
        assert "resolve(did)" in str(exc_info.value)
        assert exc_info.value.code == "MANAGED_SERVICE_CLIENT_ERROR"

    @pytest.mark.asyncio
    async def test_resolver_with_both_methods_uses_resolve(self) -> None:
        """If a resolver implements both ``.resolve`` + ``.resolve_did`` -> call ``.resolve``
        (using the literal interface name, confirming there is no ambiguity)."""

        class _BothMethods:
            async def resolve(self, did):  # the literal interface name
                return None

            async def resolve_did(self, did):  # the legacy name (will be ignored)
                # If mistakenly called here -> raise explicitly to prove it was ignored
                raise AssertionError(
                    "binding layer must call .resolve(did), not .resolve_did(did)"
                )

        config = ManagedServiceClientConfig(
            fallbackResolver=_BothMethods(),
        )
        client = ManagedServiceClient(config)
        # Does not raise AssertionError -> proves the binding calls .resolve
        result = await client.resolve_did("did:agent:" + "7" * 40)
        assert result is None


# --- onFallback trigger order when service_url=None ---


class TestServiceUrlNotConfiguredFallbackR3F4:
    """When service_url=None, the ``resolve_did`` path **first** triggers
    ``onFallback('serviceUrl_not_configured', did)``, **then** delegates to fallback.
    Literally aligned with the TS implementation.
    """

    @pytest.mark.asyncio
    async def test_resolve_did_no_service_url_triggers_fallback_first(
        self,
    ) -> None:
        """When service_url=None, the entry point triggers ``serviceUrl_not_configured`` first.

        Key point: fallback must trigger **before** ``self.fallbackResolver.resolve(did)``
        -- this way, even if the fallback resolver raises, the monitoring side can
        still capture the request volume of the free-tier path (free-tier
        monitoring blind-spot fix).
        """
        valid_doc = {
            "id": "did:agent:" + "a" * 40,
            "specVersion": "0.1.0",
            "principalDid": "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
            "publicKey": "c" * 64,
            "bindingProof": {
                "principalDid": "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
                "agentDid": "did:agent:" + "0" * 40,
                "issuedAt": "2026-05-07T12:00:00.000Z",
                "expiresAt": None,
                "signature": "0" * 128,
            },
            "createdAt": "2026-05-07T12:00:00.000Z",
            "updatedAt": "2026-05-07T12:00:00.000Z",
        }
        captured: list[tuple[str, str]] = []

        def cb(reason: str, identifier: str) -> None:
            captured.append((reason, identifier))

        target_did = "did:agent:" + "a" * 40
        config = ManagedServiceClientConfig(
            fallbackResolver=_StubResolver(valid_doc),
            onFallback=cb,
        )
        client = ManagedServiceClient(config)
        result = await client.resolve_did(target_did)
        # The fallback resolver returns valid -> no fallback_resolver_returned_none
        assert isinstance(result, AgentIdentityDocument)
        # The entry point still triggers 'serviceUrl_not_configured' (free-tier monitoring signal)
        assert captured == [
            ("serviceUrl_not_configured", target_did)
        ], f"entry-point fallback signal missing or wrong: {captured!r}"

    @pytest.mark.asyncio
    async def test_resolve_did_fallback_signal_captured_before_resolver_throws(
        self,
    ) -> None:
        """When the fallback resolver raises, the ``serviceUrl_not_configured`` signal
        is still recorded (proving the trigger is before the resolver call --
        ensuring free-tier request-volume monitoring stays observable on the
        exception path)."""

        class _ErrorResolver:
            async def resolve(self, did):
                raise RuntimeError("upstream failure")

        captured: list[tuple[str, str]] = []

        def cb(reason: str, identifier: str) -> None:
            captured.append((reason, identifier))

        target_did = "did:agent:" + "a" * 40
        config = ManagedServiceClientConfig(
            fallbackResolver=_ErrorResolver(),
            onFallback=cb,
        )
        client = ManagedServiceClient(config)
        with pytest.raises(RuntimeError, match="upstream failure"):
            await client.resolve_did(target_did)
        # Even if the resolver raises, the entry-point 'serviceUrl_not_configured' signal is still recorded
        assert captured == [
            ("serviceUrl_not_configured", target_did)
        ], f"entry-point signal must precede resolver call: {captured!r}"
