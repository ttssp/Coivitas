"""ManagedServiceClient + ManagedServiceError.

Design principles
-----------------
1. Aligned with the TS ``packages/sdk/src/managed-service-client.ts`` public API surface
2. ``resolve_did`` returns ``AgentIdentityDocument | None``;
   shape + Brand validation happens at the SDK boundary (no longer degraded to ``dict[str, Any]``)
3. ``check_revocation`` returns ``RevocationResult``
4. **stub fail-closed guard**: when the managed path has not implemented a real fetch,
   fail-closed by raising ``NotImplementedError`` (5xx semantics; not returning 200 + empty body);
   in stub mode (``service_url`` not configured) ``check_revocation`` returns
   ``revoked='unknown'`` + an explicit ``fallback_reason`` (consistent with the three-state
   wire-protocol semantics of the TS RevocationResult; the caller fails closed per policy).
5. **fetch/mock guard**: the HTTP transport does not implement a real
   network fetch at this stage (httpx recommended, but left to the production implementer);
   when no transport is configured, fall back to the injected ``fallback_resolver`` Protocol.
   Production implementers must install httpx and inject it via ``transport``.
6. **anonymous managed-service mode aligned 1:1 with TS**: literally aligned with TS
   ``managed-service-client.ts:147-170`` — configuring ``service_url`` means
   "managed service enabled"; ``api_key`` is optional (free-tier mode). An early
   implementation set the enablement threshold to both ``service_url`` AND ``api_key`` being non-empty,
   incorrectly locking the anonymous free-tier path into the fallback path, causing behavior to diverge from TS.

fail-closed contract
----------------------------------
- The ``FederatedResolver`` interface is literally ``resolve(did)`` (see
  ``packages/types/src/federation.ts:147-152``); the TS call site is literally ``this
  .fallbackResolver.resolve(did as never)``. Early Python hardcoded
  ``getattr(fallback_resolver, "resolve_did")``
  -> any interface-conforming fallback resolver immediately raised AttributeError on integration. This implementation switches to
  ``.resolve(did)``; the type hint is likewise upgraded from ``Any`` to the ``FederatedResolver``
  Protocol (see the Protocol definition at the bottom of the module; literally aligned with the TS interface).
- When ``service_url is None``, the ``resolve_did`` path **first** triggers
  ``onFallback('serviceUrl_not_configured', did)``, **then** delegates to the fallback
  resolver — literally aligned with TS ``managed-service-client.ts:167-170``. Early
  Python skipped this hook entirely -> a free-tier monitoring blind spot.
- On the ``service_url is None`` path of ``check_revocation``, the
  ``fallbackReason`` string literal value is ``'serviceUrl_not_configured'`` (literally
  consistent with TS); early Python used a homegrown
  ``'managed_service_not_configured'`` -> a cross-language drift in the reason string.

Anchors
-------
- ``packages/sdk/src/managed-service-client.ts``
- ``packages/types/src/federation.ts:147-152`` ``FederatedResolver`` interface
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Protocol, runtime_checkable

from coivitas.types import (
    AgentIdentityDocument,
    ManagedServiceClientConfig,
    ManagedServiceErrorCode,
    RevocationResult,
)

# ─── FederatedResolver Protocol (literally aligned with TS federation.ts:147-152)
# TS interface (packages/types/src/federation.ts:147-152):
#     export interface FederatedResolver {
#         resolve(did: DID): Promise<AgentIdentityDocument | null>;
#         invalidateCache(did: DID): void;
#         getMetrics(): FederatedResolverMetrics;
#         close(): Promise<void>;
#     }
# The Python binding layer's minimal concern is ``resolve(did)`` (the other three methods are not
# called directly by the ``resolve_did`` path; users provide them as needed when implementing).
# ``runtime_checkable`` lets the isinstance guard do duck-typing checks at the binding boundary.
# ────────────────────────────────────────────────────────────────────


@runtime_checkable
class FederatedResolver(Protocol):
    """Literally aligned with the TS ``FederatedResolver`` interface (federation.ts:147-152).

    On the Python side ``ManagedServiceClient.resolve_did`` only calls ``resolve(did)``;
    the other three methods (``invalidateCache`` / ``getMetrics`` / ``close``) are provided as needed
    by production implementers and are not enforced by the binding layer.

    Background
    ----------
    Early Python hardcoded ``getattr(resolver, "resolve_did")`` -> inconsistent with the TS
    literal interface name ``resolve``; any **interface-conforming** fallback
    resolver raised AttributeError on integration.
    """

    def resolve(self, did: str) -> Awaitable[Any] | Any:
        """Resolve DID -> AgentIdentityDocument (dict) | None."""
        ...


class ManagedServiceError(Exception):
    """Managed service client exception.

    Field-aligned with the TS ``ManagedServiceError``: contains ``code`` + ``message`` + optional
    ``cause``; error code is restricted to ``ManagedServiceErrorCode``.
    """

    def __init__(
        self,
        code: ManagedServiceErrorCode | str,
        message: str,
        *,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message)
        # code is the ``ManagedServiceErrorCode`` Literal type alias;
        # the argument may be passed as a StrEnum or a literal string (equivalent to the TS Literal type alias)
        if isinstance(code, ManagedServiceErrorCode):
            self.code: str = code.value
        else:
            # string literal validation (fail-closed; prevents typo drift)
            allowed = {member.value for member in ManagedServiceErrorCode}
            if code not in allowed:
                raise ValueError(
                    f"unknown ManagedServiceErrorCode: {code!r}; "
                    f"expected one of {sorted(allowed)}"
                )
            self.code = code
        self.message: str = message
        self.cause: Exception | None = cause

    def __repr__(self) -> str:
        return f"ManagedServiceError(code={self.code!r}, message={self.message!r})"


class ManagedServiceClient:
    """Managed service client.

    Scope
    ----------------------
    - aligned 1:1 with the TS public API surface (``resolve_did`` / ``check_revocation``)
    - **does not implement a real HTTP fetch** (production users inject via a custom transport
      or fallback_resolver)
    - when the managed service path has no real fetch implemented -> ``NotImplementedError`` (an explicit
      boundary; diverging from the literal TS behavior is a declared scope subset at this stage)
    - **anonymous managed-service mode**: configuring ``service_url`` means "enabled";
      ``api_key`` is optional — literally aligned with TS ``managed-service-client.ts:147-170``.

    Usage conventions
    -----------------
    1. fallback_resolver-only path: ``service_url=None``. ``resolve_did`` goes through
       ``fallback_resolver``; ``check_revocation`` returns ``revoked='unknown'``
       + ``fallback_reason='serviceUrl_not_configured'``.
    2. managed service enabled (covering the two sub-modes: free-tier anonymous + paid api_key):
       ``service_url=<url>``, ``api_key=None`` or ``<key>``. At this stage the managed
       request path implements no real HTTP and uniformly raises ``NotImplementedError``; a production implementer
       just subclasses to override + installs httpx.
    """

    def __init__(
        self,
        config: ManagedServiceClientConfig,
        *,
        allow_unsafe_service_url: bool = False,
    ) -> None:
        """Construct a ManagedServiceClient.

        service_url safety gate
        ----------------------------------------------
        When ``service_url`` is configured but no real HTTP fetch / retry / fallback is implemented,
        a runtime ``NotImplementedError`` is unsafe
        (the config knob detonates in production, losing the three-state retry/fallback contract).

        When ``service_url is not None`` and ``allow_unsafe_service_url=True`` is not explicitly set,
        the constructor refuses construction, moving the detonation timing from
        runtime forward to construct-time, making the ship-time API surface fail-closed.

        Further: opt-in alone is not enough — an instance can still construct successfully but detonate
        on the first resolve_did/check_revocation call (false-safety). opt-in should be bound to
        **real transport injection evidence**; otherwise opt-in is itself false-safety, bypassing the
        ship-time gate.

        Fix: ``allow_unsafe_service_url=True`` must be **forced** through a subclassing path,
        i.e. the subclass must override both the ``resolve_did`` and ``check_revocation`` hooks;
        direct base-class construction + opt-in is still rejected (forced subclass override evidence).

        Subclassing example:
            class HttpxManagedServiceClient(ManagedServiceClient):
                def __init__(self, config):
                    super().__init__(config, allow_unsafe_service_url=True)
                    self._http = httpx.AsyncClient()
                async def resolve_did(self, did): ...     # must override
                async def check_revocation(self, cred): ... # must override

        ``allow_unsafe_service_url=True`` is permitted for:
        - test scenarios (test fixtures explicitly opt in while a subclass overrides both methods)
        - production implementers subclassing + injecting a real httpx transport

        Once the production HTTP transport implementation lands, this defaults to True and the flag is removed.
        """
        # ship-time fail-closed (replaces runtime detonation)
        if config.service_url is not None and not allow_unsafe_service_url:
            raise ValueError(
                "ManagedServiceClient: service_url is configured but the current "
                "release does not implement the HTTP fetch/retry/fallback transport. "
                "Public production export of this config knob is unsafe — it would "
                "runtime-detonate at first resolve_did/check_revocation call.\n"
                "\n"
                "Resolution paths:\n"
                "  1. (RECOMMENDED) Set service_url=None and use fallback_resolver only\n"
                "  2. Subclass ManagedServiceClient and pass "
                "allow_unsafe_service_url=True in your __init__ after "
                "implementing the HTTP transport"
            )

        # opt-in must be bound to real transport override evidence
        # opt-in=True + base class (not overridden) -> still rejected (false-safety guard)
        # opt-in is only legal after a subclass overrides resolve_did/check_revocation
        if allow_unsafe_service_url and config.service_url is not None:
            if (
                type(self).resolve_did is ManagedServiceClient.resolve_did
                or type(self).check_revocation is ManagedServiceClient.check_revocation
            ):
                raise ValueError(
                    "ManagedServiceClient: allow_unsafe_service_url=True requires "
                    "subclassing with both resolve_did() AND check_revocation() "
                    "overridden (false-safety guard).\n"
                    "\n"
                    "opt-in alone is not sufficient: a base-class instance with "
                    "service_url + opt-in would runtime-detonate at first method "
                    "call, defeating the ship-time gate. This is closed "
                    "by requiring subclass override evidence at construct time.\n"
                    "\n"
                    "Subclass example:\n"
                    "  class HttpxManagedServiceClient(ManagedServiceClient):\n"
                    "      def __init__(self, config):\n"
                    "          super().__init__(config, "
                    "allow_unsafe_service_url=True)\n"
                    "          self._http = httpx.AsyncClient()\n"
                    "      async def resolve_did(self, did): ...     # required\n"
                    "      async def check_revocation(self, cred): ... # required"
                )

        # pydantic instantiation has already fail-closed-validated the config shape
        self._config = config
        self._fallback_resolver: Any = config.fallback_resolver
        # ``on_fallback`` signature ``(reason: str, identifier: str) -> None``,
        # literally aligned with TS ``onFallback(reason, identifier)``
        self._on_fallback: Callable[[str, str], None] | None = config.on_fallback

    @property
    def config(self) -> ManagedServiceClientConfig:
        """Read-only access to the config (used for the orchestrator's internal consistency checks)."""
        return self._config

    async def resolve_did(self, did: str) -> AgentIdentityDocument | None:
        """Resolve DID -> AgentIdentityDocument.

        Paths
        -----
        1. If ``service_url`` is configured (**literally aligned with TS: ``api_key`` is optional**) ->
           take the managed service path. At this stage no real HTTP fetch is implemented;
           production users extend via transport injection -> raises ``NotImplementedError`` as an
           explicit boundary marker, to be overridden by user subclassing.
        2. Otherwise (``service_url is None``) -> first trigger
           ``onFallback('serviceUrl_not_configured', did)``, then delegate to
           ``fallback_resolver.resolve(did)`` (literally aligned with TS line 167-170).
        3. Any path returning ``None`` / an invalid shape -> fail-closed
           ``ManagedServiceError`` or pydantic ValidationError
        """
        # Path 1: managed service (configuring service_url enables it; api_key optional)
        if self._config.service_url is not None:
            # at this stage no real HTTP fetch is implemented
            # production implementers should inherit this class and override this method + inject an httpx transport
            # Note: literally aligned with TS behavior — if api_key is set, use the Authorization Bearer header;
            # if unset, use anonymous free-tier. Both sub-modes are handled in the production implementation layer
            # (subclass); this placeholder does not distinguish them when raising (a single boundary).
            raise NotImplementedError(
                "ManagedServiceClient.resolve_did with service_url requires "
                "a custom transport injection (httpx / requests / aiohttp). "
                "Subclass ManagedServiceClient and override resolve_did(), or use "
                "fallback_resolver-only mode by leaving service_url=None."
            )

        # When service_url=None, **first** notify the fallback trigger, **then** delegate to the
        # fallback resolver; literally aligned with TS managed-service-client.ts:167-170:
        #   if (!this.serviceUrl) {
        #       this.triggerFallback('serviceUrl_not_configured', did);
        #       return this.fallbackResolver.resolve(did as never);
        #   }
        # Path 2: fallback_resolver (the main production path)
        self._trigger_fallback("serviceUrl_not_configured", did)
        return await self._invoke_fallback_resolve(did)

    async def check_revocation(self, credential_id: str) -> RevocationResult:
        """Check credential revocation.

        At this stage a stub fail-closed: when no managed service is injected (``service_url is None``)
        it directly returns ``RevocationResult(revoked="unknown", fallback_reason=...)``,
        letting the caller decide fail-open / fail-closed (consistent with the three-state
        ``true`` / ``false`` / ``"unknown"`` of the TS RevocationResult.revoked).

        ``unknown`` is not a default-200-body drift — it is a state explicitly allowed by the wire protocol,
        meaning "the client cannot determine; choose fail-open/closed per policy"; once the caller receives
        ``unknown`` it must make an explicit decision (typically fail-closed).

        Literally aligned with TS ``checkRevocation`` — configuring ``service_url`` enters the
        managed path; ``api_key`` is optional (free-tier anonymous).

        The ``fallback_reason`` string literal value is
        ``'serviceUrl_not_configured'`` (literally aligned with TS managed-service-client.ts:227+230);
        early Python once used a homegrown string
        -> a cross-language drift in the reason string.
        """
        if self._config.service_url is None:
            # Stub-only mode: fail-closed to unknown, the caller must fail-closed
            # on_fallback(reason, identifier) argument order matches TS;
            # reason string 'serviceUrl_not_configured' (literal at TS line 227)
            self._trigger_fallback("serviceUrl_not_configured", credential_id)
            return RevocationResult(
                credentialId=credential_id,
                revoked="unknown",
                fallbackReason="serviceUrl_not_configured",
            )

        # Real managed service path: not yet implemented, left to the production implementer
        raise NotImplementedError(
            "ManagedServiceClient.check_revocation with service_url requires "
            "a custom transport injection (httpx / requests / aiohttp). "
            "Subclass ManagedServiceClient and override check_revocation()."
        )

    def _trigger_fallback(self, reason: str, identifier: str) -> None:
        """Trigger the fallback callback (literally aligned with TS ``triggerFallback``).

        Argument order: ``(reason, identifier)`` — ``reason`` first, ``identifier`` second.
        A callback that raises does not block the main path (equivalent to TS: ``onFallback?.()`` is not
        try-catch'd, but in practice production callbacks are mostly metric emission and are not expected to
        raise; here a try-except is slightly more conservative, swallowing errors to avoid breaking the
        fail-closed contract).
        """
        if self._on_fallback is None:
            return
        try:
            self._on_fallback(reason, identifier)
        except Exception:  # noqa: BLE001
            # callback side effects must not block the main path
            pass

    async def _invoke_fallback_resolve(self, did: str) -> AgentIdentityDocument | None:
        """Delegate DID resolution to the fallback_resolver Protocol.

        Protocol duck-typing contract (literally aligned with the TS interface)
        ----------------------------------------------------
        - ``fallback_resolver.resolve(did) -> Awaitable[dict | None]``
          (TS ``FederatedResolver.resolve(did)`` interface; early Python wrongly
          called ``.resolve_did(did)`` -> incompatible with interface-conforming fallback resolvers)
        - returns ``dict`` -> use pydantic ``AgentIdentityDocument.model_validate`` for
          boundary fail-closed validation; an invalid shape -> ValidationError
        - returns ``None`` -> notify the fallback callback then return ``None``
        - missing ``resolve`` method -> ManagedServiceError(MANAGED_SERVICE_CLIENT_ERROR)
        """
        if self._fallback_resolver is None:
            raise ManagedServiceError(
                ManagedServiceErrorCode.MANAGED_SERVICE_CLIENT_ERROR,
                f"No fallback_resolver configured for resolve_did({did!r})",
            )

        # Call .resolve(did) rather than .resolve_did(did); literally aligned with the TS interface
        # FederatedResolver.resolve (federation.ts:148).
        # Use a hasattr guard + ManagedServiceError wrapping to give production implementers a clear error signal
        # instead of Python's default AttributeError stack.
        if not hasattr(self._fallback_resolver, "resolve"):
            raise ManagedServiceError(
                ManagedServiceErrorCode.MANAGED_SERVICE_CLIENT_ERROR,
                "fallback_resolver missing 'resolve(did)' method "
                "(see FederatedResolver interface: federation.ts:147-152)",
            )

        resolve_method = self._fallback_resolver.resolve

        result: Any = resolve_method(did)
        if hasattr(result, "__await__"):
            result = await result

        if result is None:
            # on_fallback(reason, identifier) argument order literally aligned with TS
            self._trigger_fallback("fallback_resolver_returned_none", did)
            return None

        if isinstance(result, AgentIdentityDocument):
            return result

        if not isinstance(result, dict):
            raise ManagedServiceError(
                ManagedServiceErrorCode.MANAGED_SERVICE_CLIENT_ERROR,
                f"fallback_resolver returned non-dict: type={type(result).__name__}",
            )

        # shape validation at the SDK boundary
        # pydantic ValidationError propagates upward directly (fail-closed; no silent degradation)
        return AgentIdentityDocument.model_validate(result)


__all__ = [
    "FederatedResolver",
    "ManagedServiceClient",
    "ManagedServiceError",
]
