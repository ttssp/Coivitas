"""hcc v0.2 — Hash Chain Canonicalize Python SDK consumer side

Version: hccVersion == "2.0.0"

 Refactor (E-track closure)
 - new exports: assert_canonical_payload_is_canonical, append_hash_chain_entry
 - verify_hash_chain API change: removed payload_bytes_list, added trusted_checkpoint keyword-only

Export structure
--------
L0 types: ChainIdentity, ChainIdentityJcs, HashChainEntry, HccErrorCode, HccError
L1 crypto: canonicalize_chain_identity, concat_preimage,
 compute_canonical_payload_hash_hex, recompute_canonical_payload_hash,
 assert_canonical_payload_is_canonical, assert_canonical_payload_hash_consistent,
 verify_hash_chain, append_hash_chain_entry
Constants: HCC_VERSION, HCC_SENTINEL_HASH
"""

from .crypto import (
 append_hash_chain_entry,
 assert_canonical_payload_hash_consistent,
 assert_canonical_payload_is_canonical,
 canonicalize_chain_identity,
 compute_canonical_payload_hash_hex,
 concat_preimage,
 recompute_canonical_payload_hash,
 verify_hash_chain,
)
from .types import (
 HCC_SENTINEL_HASH,
 HCC_VERSION,
 ChainIdentity,
 ChainIdentityJcs,
 HashChainEntry,
 HccError,
 HccErrorCode,
)

__all__ = [
 # constants
 "HCC_VERSION",
 "HCC_SENTINEL_HASH",
 # L0 types
 "ChainIdentity",
 "ChainIdentityJcs",
 "HashChainEntry",
 "HccErrorCode",
 "HccError",
 # L1 crypto
 "canonicalize_chain_identity",
 "concat_preimage",
 "compute_canonical_payload_hash_hex",
 "recompute_canonical_payload_hash",
 "assert_canonical_payload_is_canonical",
 "assert_canonical_payload_hash_consistent",
 "verify_hash_chain",
 "append_hash_chain_entry",
]
