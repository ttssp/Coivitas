"""hcc v0.2 L1 crypto functions.

Includes the following canonicalization and hashing functions:
  - canonicalizeChainIdentity
  - concatPreimage
  - computeCanonicalPayloadHashHex
  - recomputeCanonicalPayloadHash / assertCanonicalPayloadHashConsistent

Cross-lang consistency constraints
-----------------------------------
- RFC 8785 JCS: Python `jcs.canonicalize()` <-> TS `canonicalize` npm package
- SHA-256: Python `hashlib.sha256` <-> TS `@noble/hashes/sha256`
- preimage concat order: UTF8(canonicalPayload) || UTF8(chainIdentityJcs) (both string -> UTF-8)
- final hex: 64-char lowercase (hashlib.hexdigest() defaults to lowercase; TS bytesToHex defaults to lowercase)

true-anchor guarantee: for the same (payload, chainIdentity) input, Python and TS
produce a byte-identical canonicalPayloadHash.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, cast

# RFC 8785 JCS Python binding (prefer jcs ^0.2.x; stdlib fallback equivalent implementation)
# The jcs library and json.dumps(sort_keys=True, separators=(',',':'), ensure_ascii=False)
# produce byte-identical output for string-only dicts (both sort by ascending Unicode code point).
# ChainIdentity fields are all str; both implementations conform to RFC 8785 object member ordering.
try:
    import jcs as _jcs_lib  # type: ignore[import-untyped]

    def _jcs_canonicalize(obj: dict[str, Any]) -> bytes:
        """Call the jcs PyPI library (canonical path)."""
        return _jcs_lib.canonicalize(obj)  # type: ignore[no-any-return]

except ModuleNotFoundError:
    # jcs not installed (CI/dev environment) -> stdlib equivalent implementation
    # Equivalence proof: RFC 8785 key ordering = ascending Unicode code point
    # Python sort_keys=True uses Python str Unicode ordering (consistent with RFC 8785)
    # ensure_ascii=False + UTF-8 encode = RFC 8785 UTF-8 output
    def _jcs_canonicalize(obj: dict[str, Any]) -> bytes:
        """stdlib JCS equivalent implementation (string-only dict; RFC 8785 §3.2 compliant)."""
        return json.dumps(
            obj,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")


from .types import (
    HCC_SENTINEL_HASH,
    HCC_VERSION,
    ChainIdentity,
    ChainIdentityJcs,
    HashChainEntry,
    HccError,
    HccErrorCode,
)


# ─── canonicalizeChainIdentity ─────────────────────────────────
def canonicalize_chain_identity(identity: ChainIdentity) -> ChainIdentityJcs:
    """Apply RFC 8785 JCS canonicalization to a ChainIdentity, returning a brand newtype.

    Algorithm
    ---------
    1. Include only fields present in identity (filter out undefined; a Python TypedDict only contains assigned keys)
    2. Call jcs.canonicalize() (RFC 8785 ascending field Unicode code point + JSON serialization)
    3. Return ChainIdentityJcs(bytes) via factory construction (brand guard)

    Cross-language consistency
    --------------------------
    jcs.canonicalize output = b'{"auditClass":"...","chainNamespace":"...","tenantId":"..."}'
    (fields in ascending code point order; auditClass < chainNamespace < tenantId)
    byte-identical to the UTF-8 result of TS canonicalize(identity).

    Args:
        identity: ChainIdentity TypedDict (at minimum contains chainNamespace)

    Returns:
        ChainIdentityJcs — JCS bytes brand newtype (constructible only via this factory)

    Raises:
        HccError(HCC_SCHEMA_VIOLATION): identity is missing chainNamespace
    """
    # Validate required field
    if "chainNamespace" not in identity:
        raise HccError(
            HccErrorCode.HCC_SCHEMA_VIOLATION,
            "chainIdentity.chainNamespace is required",
        )

    # Build a plain dict containing only present fields (filter out absent optional fields)
    # Note: a TypedDict is just a plain dict at runtime; identity contains no unassigned NotRequired fields
    # The cast explicitly tells pyright that all ChainIdentity values are str (guaranteed by the TypedDict definition)
    canonical_dict: dict[str, str] = cast(dict[str, str], dict(identity))

    # RFC 8785 JCS canonicalization (jcs PyPI or stdlib equivalent implementation)
    jcs_bytes: bytes = _jcs_canonicalize(canonical_dict)

    # Factory-construct the brand newtype (brand guard)
    return ChainIdentityJcs(jcs_bytes, _sentinel=ChainIdentityJcs._FACTORY_SENTINEL)


# ─── concatPreimage ─────────────────────────────────────────────
def concat_preimage(canonical_payload: str, chain_identity_jcs: ChainIdentityJcs) -> bytes:
    """Concatenate the hash preimage: UTF8(canonicalPayload) || UTF8(chainIdentityJcs).

    The first argument is a str, aligning with the TS concatPreimage(canonicalPayload: string, ...) signature.
    Both sides accept string input and concatenate after an internal encode('utf-8').

    Concatenation rule:
      preimage = UTF8(canonical_payload) + chain_identity_jcs_bytes
      Fixed order (payload first, identity second); no separator added.

    Cross-language consistency
    --------------------------
    TS side: Buffer.concat([Buffer.from(canonicalPayload, 'utf8'), Buffer.from(chainIdentityJcs, 'utf8')])
    Python side: canonical_payload.encode('utf-8') + bytes(chain_identity_jcs)
    Byte-equivalent.

    Args:
        canonical_payload: the canonicalized payload JSON string (JCS RFC 8785 output)
        chain_identity_jcs: ChainIdentityJcs brand (produced by canonicalize_chain_identity)

    Returns:
        bytes — preimage, to be fed into SHA-256
    """
    payload_bytes = canonical_payload.encode("utf-8")
    return payload_bytes + bytes(chain_identity_jcs)


# ─── computeCanonicalPayloadHashHex ─────────────────────────────
def compute_canonical_payload_hash_hex(preimage: bytes) -> str:
    """Compute SHA-256 over the preimage, returning a 64-char lowercase hex string.

    Computation rule:
      canonicalPayloadHash = sha256(preimage).hexdigest()
      Format: 64-char lowercase ASCII hex (equivalent to TS @noble/hashes/sha256 + bytesToHex output)

    Args:
        preimage: the output of concat_preimage()

    Returns:
        str — 64-char lowercase hex (e.g. "a1b2c3...")
    """
    return hashlib.sha256(preimage).hexdigest()


# ─── recompute_canonical_payload_hash ──────────────────────────
def recompute_canonical_payload_hash(entry: HashChainEntry) -> str:
    """Recompute canonicalPayloadHash from a HashChainEntry (full hash recomputation).

    Mirrors TS recomputeCanonicalPayloadHash, recomputing through the full pipeline.

    Algorithm (aligned with TS recomputeCanonicalPayloadHash):
      1. Reconstruct ChainIdentity from entry.chainIdentity -> canonicalize_chain_identity -> ChainIdentityJcs
      2. concat_preimage(entry.canonicalPayload, chain_identity_jcs) -> preimage bytes
      3. compute_canonical_payload_hash_hex(preimage) -> canonicalPayloadHash hex

    Returns the full canonicalPayloadHash (sha256 over the full preimage).

    Args:
        entry: HashChainEntry (contains canonicalPayload + chainIdentity)

    Returns:
        str — recomputed canonicalPayloadHash, lowercase hex, 64 chars

    Raises:
        HccError(HCC_SCHEMA_VIOLATION): chainIdentity is missing chainNamespace
    """
    # Reconstruct ChainIdentity from the stored dict (only present fields)
    identity: ChainIdentity = {"chainNamespace": entry.chainIdentity["chainNamespace"]}
    if "tenantId" in entry.chainIdentity:
        identity["tenantId"] = entry.chainIdentity["tenantId"]
    if "auditClass" in entry.chainIdentity:
        identity["auditClass"] = entry.chainIdentity["auditClass"]

    # Re-canonicalize chainIdentity with JCS
    chain_identity_jcs = canonicalize_chain_identity(identity)

    # Full preimage = UTF8(canonicalPayload) || chainIdentityJcsBytes
    preimage = concat_preimage(entry.canonicalPayload, chain_identity_jcs)

    # SHA-256 -> canonicalPayloadHash hex
    return compute_canonical_payload_hash_hex(preimage)


# ─── assert_canonical_payload_is_canonical ──────────────────────
def assert_canonical_payload_is_canonical(entry: HashChainEntry, entry_index: int) -> None:
    """Assert that entry.canonicalPayload is in JCS canonical form.

    Aligned with TS assertCanonicalPayloadIsCanonical.
    Defends against a non-canonical payload bypassing verify and breaking the injective invariant.

    Algorithm:
      1. JSON.loads(entry.canonicalPayload) — must be valid JSON
      2. _jcs_canonicalize(parsed) re-runs the same algorithm as the write path
      3. The result must be literally equal to entry.canonicalPayload

    Raises:
        HccError(HCC_SCHEMA_VIOLATION): canonicalPayload is not valid JSON
            (aligned with the TS canonicalize failure path; the Python side covers it with HCC_SCHEMA_VIOLATION)
        HccError(HCC_CHAIN_IDENTITY_TAMPERED): canonicalPayload is not in canonical JCS form
            (aligned with the TS preimage validation failure path; cross-lang semantically equivalent)
    """
    try:
        parsed = json.loads(entry.canonicalPayload)
    except (json.JSONDecodeError, ValueError) as exc:
        raise HccError(
            HccErrorCode.HCC_SCHEMA_VIOLATION,
            f"entries[{entry_index}].canonicalPayload is not valid JSON: {exc}",
        ) from exc

    recanonicalized = _jcs_canonicalize(parsed).decode("utf-8")
    if recanonicalized != entry.canonicalPayload:
        raise HccError(
            HccErrorCode.HCC_CHAIN_IDENTITY_TAMPERED,
            f"entries[{entry_index}].canonicalPayload is not canonical JCS form "
            f"(stored={entry.canonicalPayload!r}, canonical={recanonicalized!r}); "
            "non-canonical payload rejected to preserve injective preimage invariant",
        )


# ─── assert_canonical_payload_hash_consistent ──────────────────
def assert_canonical_payload_hash_consistent(entry: HashChainEntry, entry_index: int) -> None:
    """Assert that entry.canonicalPayloadHash matches the recomputed value (tamper detection).

    Mirrors TS assertCanonicalPayloadHashConsistent: first a canonical form check, then full hash verification.

    Algorithm (two-step fail-closed):
      Step 1: assert_canonical_payload_is_canonical(entry, entry_index) — canonical form check
      Step 2: recompute_canonical_payload_hash(entry) — full hash recomputation
      Step 3: verify literal equality; if not equal -> HccError(HCC_HASH_MISMATCH)

    Tamper detection coverage:
      - mutating any chainIdentity field -> JCS output mutates -> preimage mutates -> hash differs
      - mutating any canonicalPayload character -> preimage mutates -> hash differs

    Args:
        entry: HashChainEntry (contains canonicalPayload + chainIdentity + canonicalPayloadHash)
        entry_index: the entry's index within the entries list (used to locate the error message)

    Raises:
        HccError(HCC_SCHEMA_VIOLATION): canonicalPayload is not valid JSON
        HccError(HCC_CHAIN_IDENTITY_TAMPERED): canonicalPayload is not in canonical form
        HccError(HCC_HASH_MISMATCH): canonicalPayloadHash does not match the recomputed value
    """
    # Step 1: canonical form check
    assert_canonical_payload_is_canonical(entry, entry_index)

    # Step 2: full hash recomputation
    expected_hash = recompute_canonical_payload_hash(entry)

    # Step 3: hash comparison
    if entry.canonicalPayloadHash != expected_hash:
        raise HccError(
            HccErrorCode.HCC_HASH_MISMATCH,
            f"entries[{entry_index}].canonicalPayloadHash mismatch: "
            f"stored={entry.canonicalPayloadHash!r}, recomputed={expected_hash!r}; "
            "fail-closed on chainIdentity or canonicalPayload tampering",
        )


# ─── verify_hash_chain (hcc v0.2 full chain verification) ──────────────────
def verify_hash_chain(
    entries: list[HashChainEntry],
    *,
    trusted_checkpoint: str | None = None,
    expected_chain_identity: ChainIdentity | None = None,
) -> None:
    """Verify hash chain integrity (hcc v0.2).

    Parameter semantics:
      - payload is stored in entry.canonicalPayload (no longer passed separately)
      - trusted_checkpoint keyword-only parameter (injected from deployment config)
      - expected_chain_identity keyword-only parameter (defends against mixed-identity
        chain rejection)

    Aligned with TS verifyHashChain + VerifyHashChainOptions.checkpoint + expectedChainIdentity.

    Verification flow
    -----------------
    Step 0: non-empty check on entries + chain-level identity consistency check
    trusted_checkpoint: if not None, verify entries[-1].canonicalPayloadHash == trusted_checkpoint
    Step 1: genesis conditions (entries[0].chainPosition == 0, previousHash == sentinel)
    Step 2: reverse traversal (from the tail forward), verify monotonically increasing chainPosition + previousHash linkage
    Step 3: per-entry verification:
      Step 3.1: hccVersion == "2.0.0"
      Step 3.2+3.3: assert_canonical_payload_hash_consistent (includes canonical form + full hash)

    chain-level identity consistency check:
      All entries must share the same canonical chainIdentity (literal JCS equality); defends against
      identity-rebinding attacks (splicing different chainIdentities into a valid chain).
      If expected_chain_identity is not None, further assert that every entry equals that expected value (scope isolation).
      Mirrors TS verifyHashChain behavior.

    trusted_checkpoint (trust-anchor-provenance):
      If not None, must verify entries[-1].canonicalPayloadHash == trusted_checkpoint.
      Defends against deletion/truncation attacks.
      trusted_checkpoint is injected as a separate parameter, not stored inside HashChainEntry.

    Args:
        entries: list of HashChainEntry sorted in ascending chainPosition order
        trusted_checkpoint: externally injected canonicalPayloadHash of the last entry (deployment config; not an entry field)
        expected_chain_identity: externally injected expected chainIdentity (scope isolation guard; not an entry field)

    Raises:
        HccError(HCC_SCHEMA_VIOLATION): entries is empty or trusted_checkpoint does not match
        HccError(HCC_GENESIS_INVARIANT_VIOLATION): genesis conditions violated
        HccError(HCC_CHAIN_POSITION_NOT_MONOTONIC): chainPosition is not monotonic
        HccError(HCC_LINK_BROKEN): previousHash linkage broken
        HccError(HCC_VERSION_MISMATCH): hccVersion != "2.0.0"
        HccError(HCC_CHAIN_IDENTITY_TAMPERED): canonicalPayload is not in canonical form
            or mixed-identity chain
            or chainIdentity does not match expected_chain_identity
        HccError(HCC_HASH_MISMATCH): canonicalPayloadHash recomputation mismatch
    """
    # Step 0: non-empty check
    if not entries:
        raise HccError(HccErrorCode.HCC_SCHEMA_VIOLATION, "entries list must not be empty")

    # trusted_checkpoint verification (executed immediately after Step 0)
    if trusted_checkpoint is not None:
        if entries[-1].canonicalPayloadHash != trusted_checkpoint:
            raise HccError(
                HccErrorCode.HCC_SCHEMA_VIOLATION,
                f"trusted_checkpoint mismatch: expected={trusted_checkpoint!r}, "
                f"got={entries[-1].canonicalPayloadHash!r}",
            )

    # Step 0.5: chain-level identity consistency check
    # All entries must share the same canonical chainIdentity (literal JCS equality);
    # defends against identity-rebinding attacks (splicing different chainIdentities into a valid chain)
    # Mirrors TS verifyHashChain
    first_identity = cast(ChainIdentity, entries[0].chainIdentity)
    first_identity_jcs = canonicalize_chain_identity(first_identity)
    if expected_chain_identity is not None:
        expected_identity_jcs = canonicalize_chain_identity(expected_chain_identity)
        if bytes(first_identity_jcs) != bytes(expected_identity_jcs):
            raise HccError(
                HccErrorCode.HCC_CHAIN_IDENTITY_TAMPERED,
                f"entries[0].chainIdentity does not match expected_chain_identity; "
                f"scope isolation enforced",
            )
    for i in range(1, len(entries)):
        this_identity = cast(ChainIdentity, entries[i].chainIdentity)
        this_identity_jcs = canonicalize_chain_identity(this_identity)
        if bytes(this_identity_jcs) != bytes(first_identity_jcs):
            raise HccError(
                HccErrorCode.HCC_CHAIN_IDENTITY_TAMPERED,
                f"entries[{i}].chainIdentity differs from chain's first chainIdentity; "
                f"mixed-identity chain rejected (cross-scope identity-rebinding)",
            )

    # Step 1: genesis conditions
    genesis = entries[0]
    if genesis.chainPosition != 0:
        raise HccError(
            HccErrorCode.HCC_GENESIS_INVARIANT_VIOLATION,
            f"genesis entry chainPosition must be 0, got {genesis.chainPosition}",
        )
    if genesis.previousHash != HCC_SENTINEL_HASH:
        raise HccError(
            HccErrorCode.HCC_GENESIS_INVARIANT_VIOLATION,
            f"genesis entry previousHash must be 64-zero sentinel, got {genesis.previousHash!r}",
        )

    # Step 2: reverse traversal (tail -> front) verifying monotonic chainPosition + previousHash linkage
    for i in range(len(entries) - 1, 0, -1):
        current = entries[i]
        prev = entries[i - 1]
        # chainPosition monotonically increasing (strictly +1 per step)
        if current.chainPosition != prev.chainPosition + 1:
            raise HccError(
                HccErrorCode.HCC_CHAIN_POSITION_NOT_MONOTONIC,
                f"entries[{i}].chainPosition={current.chainPosition} != "
                f"entries[{i-1}].chainPosition={prev.chainPosition} + 1",
            )
        # previousHash linkage (current.previousHash == prev.canonicalPayloadHash)
        if current.previousHash != prev.canonicalPayloadHash:
            raise HccError(
                HccErrorCode.HCC_LINK_BROKEN,
                f"entries[{i}].previousHash={current.previousHash!r} != "
                f"entries[{i-1}].canonicalPayloadHash={prev.canonicalPayloadHash!r}",
            )

    # Step 3: per-entry verification (read directly from entry.canonicalPayload; no payload_bytes_list)
    for i, entry in enumerate(entries):
        # Step 3.1: hccVersion
        if entry.hccVersion != HCC_VERSION:
            raise HccError(
                HccErrorCode.HCC_VERSION_MISMATCH,
                f"entries[{i}].hccVersion={entry.hccVersion!r} != {HCC_VERSION!r}",
            )

        # Step 3.2+3.3: canonical form check + full hash recomputation (assert_canonical_payload_hash_consistent)
        assert_canonical_payload_hash_consistent(entry, i)


# ─── append_hash_chain_entry ────────────────────────────────────
def append_hash_chain_entry(
    payload: dict[str, object],
    chain_identity: ChainIdentity,
    prev_entry: HashChainEntry | None = None,
) -> HashChainEntry:
    """Generate a new HashChainEntry (aligned with TS appendHashChainEntry).

    Algorithm (aligned with TS append-hash-chain-entry.ts Step 1-7):
      Step 1: _jcs_canonicalize(payload) -> canonicalPayload string (RFC 8785)
      Step 2: canonicalize_chain_identity(chain_identity) -> ChainIdentityJcs
      Step 3: concat_preimage(canonicalPayload, chain_identity_jcs) -> preimage bytes
      Step 4: compute_canonical_payload_hash_hex(preimage) -> canonicalPayloadHash
      Step 5: chainPosition = (prev_entry.chainPosition + 1) if prev_entry else 0
      Step 6: previousHash = prev_entry.canonicalPayloadHash if prev_entry else HCC_SENTINEL_HASH
      Step 7: timestamp = datetime.now(timezone.utc).isoformat() (tz-aware; recommended path for Python 3.12+)

    Genesis continuity guard: if prev_entry exists, verify chain_identity == prev_entry.chainIdentity.
    Append is allowed only when chainNamespace + optional fields (tenantId / auditClass) match exactly.

    Args:
        payload: the raw payload dict (will be JCS-canonicalized)
        chain_identity: ChainIdentity (chainNamespace required)
        prev_entry: the predecessor entry (None = genesis)

    Returns:
        HashChainEntry — the new entry (all 8 fields populated)

    Raises:
        HccError(HCC_SCHEMA_VIOLATION): chainIdentity.chainNamespace is missing
        HccError(HCC_CHAIN_IDENTITY_TAMPERED): chain_identity does not match prev_entry.chainIdentity
    """
    # Genesis continuity guard (checked before canonicalize, for a fast fail)
    if prev_entry is not None:
        prev_identity = prev_entry.chainIdentity
        curr_identity = dict(chain_identity)
        if curr_identity != prev_identity:
            raise HccError(
                HccErrorCode.HCC_CHAIN_IDENTITY_TAMPERED,
                f"chain_identity must match prev_entry.chainIdentity: "
                f"curr={curr_identity!r}, prev={prev_identity!r}",
            )

    # Step 1: JCS-canonicalize payload -> canonicalPayload string
    canonical_payload_bytes = _jcs_canonicalize(payload)  # type: ignore[arg-type]
    canonical_payload_str = canonical_payload_bytes.decode("utf-8")

    # Step 2: JCS-canonicalize chainIdentity -> ChainIdentityJcs bytes brand
    chain_identity_jcs = canonicalize_chain_identity(chain_identity)

    # Step 3: preimage = UTF8(canonicalPayload) || chainIdentityJcsBytes
    preimage = concat_preimage(canonical_payload_str, chain_identity_jcs)

    # Step 4: SHA-256 -> canonicalPayloadHash hex
    canonical_payload_hash = compute_canonical_payload_hash_hex(preimage)

    # Step 5: chainPosition
    chain_position = (prev_entry.chainPosition + 1) if prev_entry is not None else 0

    # Step 6: previousHash
    previous_hash = prev_entry.canonicalPayloadHash if prev_entry is not None else HCC_SENTINEL_HASH

    # Step 7: timestamp (tz-aware; datetime.now(timezone.utc) is preferred over the deprecated utcnow())
    timestamp = datetime.now(timezone.utc).isoformat()

    # Step 8: construct HashChainEntry (8 fields)
    return HashChainEntry(
        entryId=str(uuid.uuid4()),
        canonicalPayload=canonical_payload_str,
        canonicalPayloadHash=canonical_payload_hash,
        previousHash=previous_hash,
        chainPosition=chain_position,
        chainIdentity=dict(chain_identity),
        timestamp=timestamp,
        hccVersion=HCC_VERSION,
    )


__all__ = [
    "canonicalize_chain_identity",
    "concat_preimage",
    "compute_canonical_payload_hash_hex",
    "recompute_canonical_payload_hash",
    "assert_canonical_payload_is_canonical",
    "assert_canonical_payload_hash_consistent",
    "verify_hash_chain",
    "append_hash_chain_entry",
]
