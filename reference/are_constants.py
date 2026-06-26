"""
Constants for the ARE reference implementation.

MINIMAL preset (documented in spec §Implementation Notes "Caveats"):
  SYNC_COMMITTEE_SIZE = 32  (quorum: 2*popcount > 32)
  Fork = Deneb, fork_version = 0x04000000
  genesis_validators_root = real mainnet value.

The signing domain (DOMAIN_SYNC_COMMITTEE, fork_version, genesis_validators_root)
uses real consensus values so signing_root is reproducible. SYNC_COMMITTEE_SIZE
is the only preset reduction relevant to the domain math (it does not enter the
domain; it only scales the bitvector/quorum).
"""

# ---- consensus domain constants (REAL mainnet) ----
DOMAIN_SYNC_COMMITTEE = bytes.fromhex("07000000")
GENESIS_VALIDATORS_ROOT = bytes.fromhex(
    "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
)

# Deneb fork (the preset fork for these vectors)
DENEB_FORK_VERSION = bytes.fromhex("04000000")

# ---- MINIMAL preset ----
SYNC_COMMITTEE_SIZE = 32

# ---- generalized indices (locked by vectors; from spec Appendix B) ----
# EXECUTION_PAYLOAD_GINDEX is real (25) on mainnet. For the reference impl's
# reduced ExecutionPayloadHeader the branch is a genuine SSZ proof; we use 25 to
# match the spec's documented value and the vector's recorded gindex.
EXECUTION_PAYLOAD_GINDEX = 25
FINALIZED_ROOT_GINDEX = 105        # Deneb (pre-Electra)
SLOTS_PER_HISTORICAL_ROOT = 8192

# generalized index for state.block_roots[i] within BeaconState (near-ancestor).
# Derived deterministically: in the reference's reduced BeaconState model we
# treat block_roots as a Vector[Bytes32, 8192] field; the leaf gindex composes
# the field's subtree-root gindex with the vector index. The concrete integer is
# LOCKED by the finalized vector (see are_generate). We pick a fixed BeaconState
# field index for block_roots in the reduced model.
# Reduced BeaconState container (this impl): {slot, block_roots, extra} -> 3
# fields -> field gindices 4,5,6 (depth-2 padded to 4). block_roots is field 1
# -> subtree root gindex 5. Within block_roots (Vector[Bytes32,8192], 13 levels)
# the leaf at index j has gindex (5 << 13) | j.
BLOCK_ROOTS_FIELD_GINDEX = 5
BLOCK_ROOTS_VECTOR_DEPTH = 13      # 2**13 == 8192


def block_roots_leaf_gindex(slot_index: int) -> int:
    """Compose the generalized index for state.block_roots[slot mod 8192]."""
    return (BLOCK_ROOTS_FIELD_GINDEX << BLOCK_ROOTS_VECTOR_DEPTH) | slot_index


# ---- slot/epoch helpers (preset SLOTS_PER_EPOCH for fork selection) ----
SLOTS_PER_EPOCH = 32
EPOCHS_PER_SYNC_COMMITTEE_PERIOD = 256
SLOTS_PER_SYNC_COMMITTEE_PERIOD = SLOTS_PER_EPOCH * EPOCHS_PER_SYNC_COMMITTEE_PERIOD


def compute_epoch_at_slot(slot: int) -> int:
    return slot // SLOTS_PER_EPOCH


def compute_sync_committee_period_at_slot(slot: int) -> int:
    return compute_epoch_at_slot(slot) // EPOCHS_PER_SYNC_COMMITTEE_PERIOD


def fork_version_at_epoch(epoch: int) -> bytes:
    # MINIMAL preset: single fork (Deneb) active for all epochs in the fixtures.
    return DENEB_FORK_VERSION
