"""
Constants for the ARE reference implementation (v0.5).

Two presets are supported (selected at runtime by the generator/runner):

  MINIMAL  — SYNC_COMMITTEE_SIZE = 32, fork Deneb (0x04000000). Fast smoke tests
             that exercise the full verification logic through the SAME real
             hexary-MPT walker and full ExecutionPayloadHeader as mainnet.
  MAINNET  — SYNC_COMMITTEE_SIZE = 512, real mainnet fork schedule. Used by the
             real-data vector (`accept_mainnet_real.json`), built from a live
             eth_getProof + LightClient finality_update + bootstrap.

The signing domain (DOMAIN_SYNC_COMMITTEE, fork_version, genesis_validators_root)
uses real consensus values so signing_root is reproducible. SYNC_COMMITTEE_SIZE
does not enter the domain; it only scales the bitvector/quorum.
"""

# ---- consensus domain constants (REAL mainnet) ----
DOMAIN_SYNC_COMMITTEE = bytes.fromhex("07000000")
GENESIS_VALIDATORS_ROOT = bytes.fromhex(
    "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
)

# ---- mainnet fork schedule (current_version, activation epoch) ----
ALTAIR_FORK_VERSION = bytes.fromhex("01000000")
BELLATRIX_FORK_VERSION = bytes.fromhex("02000000")
CAPELLA_FORK_VERSION = bytes.fromhex("03000000")
DENEB_FORK_VERSION = bytes.fromhex("04000000")
ELECTRA_FORK_VERSION = bytes.fromhex("05000000")
FULU_FORK_VERSION = bytes.fromhex("06000000")

# activation epochs (mainnet, chain_id=1)
FORK_SCHEDULE = [
    (0, GENESIS_VALIDATORS_ROOT[:0] + bytes.fromhex("00000000")),  # phase0 genesis
    (74240, ALTAIR_FORK_VERSION),
    (144896, BELLATRIX_FORK_VERSION),
    (194048, CAPELLA_FORK_VERSION),
    (269568, DENEB_FORK_VERSION),
    (364032, ELECTRA_FORK_VERSION),
    (411392, FULU_FORK_VERSION),
]

# ---- preset selection (mutated by select_preset) ----
PRESET = "MINIMAL"
SYNC_COMMITTEE_SIZE = 32
_PRESET_FORK = "deneb"   # MINIMAL fixtures are pinned to Deneb


def select_preset(name: str):
    """Switch the active preset. Affects SYNC_COMMITTEE_SIZE / quorum and the
    fork used by fork_version_at_epoch in MINIMAL mode."""
    global PRESET, SYNC_COMMITTEE_SIZE, _PRESET_FORK
    if name == "MINIMAL":
        PRESET = "MINIMAL"
        SYNC_COMMITTEE_SIZE = 32
        _PRESET_FORK = "deneb"
    elif name == "MAINNET":
        PRESET = "MAINNET"
        SYNC_COMMITTEE_SIZE = 512
        _PRESET_FORK = "mainnet-schedule"
    else:
        raise ValueError(f"unknown preset {name}")


# ---- generalized indices (locked by vectors; from spec Appendix B) ----
# EXECUTION_PAYLOAD_GINDEX is real (25) on mainnet for Capella..Fulu (BeaconBlockBody
# execution_payload field, body has <=16 fields). The reference now uses the FULL
# 17-field ExecutionPayloadHeader, so the branch is a genuine SSZ proof verified
# against a real mainnet beacon body_root.
EXECUTION_PAYLOAD_GINDEX = 25
FINALIZED_ROOT_GINDEX_PRE_ELECTRA = 105   # Deneb & earlier
FINALIZED_ROOT_GINDEX_ELECTRA = 169       # Electra, Fulu (BeaconState gained fields)
SLOTS_PER_HISTORICAL_ROOT = 8192


def finalized_root_gindex_for_attested_slot(slot: int) -> int:
    """Select FINALIZED_ROOT_GINDEX by the fork of the ATTESTED header's slot."""
    fork = fork_name_at_epoch(compute_epoch_at_slot(slot))
    if fork in ("electra", "fulu"):
        return FINALIZED_ROOT_GINDEX_ELECTRA
    return FINALIZED_ROOT_GINDEX_PRE_ELECTRA


# generalized index for state.block_roots[i] within BeaconState (near-ancestor),
# used only by the MINIMAL finalized vector against a reduced BeaconState model.
# Reduced BeaconState container (this impl): {slot, block_roots, extra} -> 3
# fields -> field gindices 4,5,6 (depth-2 padded to 4). block_roots is field 1
# -> subtree root gindex 5. Within block_roots (Vector[Bytes32,8192], 13 levels)
# the leaf at index j has gindex (5 << 13) | j.
BLOCK_ROOTS_FIELD_GINDEX = 5
BLOCK_ROOTS_VECTOR_DEPTH = 13      # 2**13 == 8192


def block_roots_leaf_gindex(slot_index: int) -> int:
    """Compose the generalized index for state.block_roots[slot mod 8192]."""
    return (BLOCK_ROOTS_FIELD_GINDEX << BLOCK_ROOTS_VECTOR_DEPTH) | slot_index


# ---- slot/epoch helpers ----
SLOTS_PER_EPOCH = 32
EPOCHS_PER_SYNC_COMMITTEE_PERIOD = 256
SLOTS_PER_SYNC_COMMITTEE_PERIOD = SLOTS_PER_EPOCH * EPOCHS_PER_SYNC_COMMITTEE_PERIOD


def compute_epoch_at_slot(slot: int) -> int:
    return slot // SLOTS_PER_EPOCH


def compute_sync_committee_period_at_slot(slot: int) -> int:
    return compute_epoch_at_slot(slot) // EPOCHS_PER_SYNC_COMMITTEE_PERIOD


def fork_name_at_epoch(epoch: int) -> str:
    names = ["phase0", "altair", "bellatrix", "capella", "deneb", "electra", "fulu"]
    out = "phase0"
    for (act_epoch, _), name in zip(FORK_SCHEDULE, names):
        if epoch >= act_epoch:
            out = name
    return out


def fork_version_at_epoch(epoch: int) -> bytes:
    if _PRESET_FORK == "deneb":
        # MINIMAL preset: single fork (Deneb) active for all fixture slots.
        return DENEB_FORK_VERSION
    # MAINNET: real schedule — last fork whose activation epoch <= epoch.
    version = bytes.fromhex("00000000")
    for act_epoch, fv in FORK_SCHEDULE:
        if epoch >= act_epoch:
            version = fv
    return version
