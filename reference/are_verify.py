"""
ARE reference verifier — implements all 10 steps of the v0.4 spec
§Verification Algorithm, in order. Returns "ACCEPT" or "REJECT@stepN".

The objects (envelope, anchor) are passed as plain dicts/objects rebuilt from a
vector JSON via are_codec.load_vector. The verifier reads ONLY untrusted
envelope/anchor fields; trusted config (genesis_validators_root, fork schedule,
head_slot, monotonic floor) is supplied via VerifierConfig.
"""

from are_ssz import (
    merkleize, uint64_root, uint256_root, bytes32_root, bytes20_root,
    boolean_root, bytevector_root, bytelist_root, mix_in_length,
    verify_merkle_branch, BeaconBlockHeader,
)
from are_mpt import (
    verify_account_inclusion, verify_account_exclusion,
    verify_storage_inclusion, verify_storage_exclusion,
    keccak256, be_to_int,
)
from are_bls import fast_aggregate_verify
from are_sig import verify_provider_sig
import are_constants as C


# read_kind
BALANCE, STORAGE, CODE, NONCE = 0, 1, 2, 3
OPTIMISTIC_HEAD, FINALIZED = 0, 1


class VerifierConfig:
    def __init__(self, chain_id, genesis_validators_root, committees,
                 head_slot, max_staleness_slots, monotonic_max_seen_slot=0,
                 dispute_mode=False, resolve_provider_key=None):
        self.chain_id = chain_id
        self.genesis_validators_root = genesis_validators_root
        # committees: dict period -> list of 48-byte pubkeys (committee for that period)
        self.committees = committees
        self.head_slot = head_slot
        self.max_staleness_slots = max_staleness_slots
        self.monotonic_max_seen_slot = monotonic_max_seen_slot
        # Step 10: dispute/audit mode means a present provider_sig MUST verify
        # (else REJECT@step10). In plain correctness mode an uncheckable sig is
        # tolerated (it carries no correctness weight) — spec §Verification step 10.
        self.dispute_mode = dispute_mode
        # resolve_provider_key(provider_key_hint, sig_alg) -> public key bytes,
        # or None if resolution fails. This stands in for the spec's INDEPENDENT
        # trust path (ENS / did: / X.509). It MUST NOT read the key from the
        # envelope; the reference resolver takes it from trusted verifier config.
        self.resolve_provider_key = resolve_provider_key


def compute_domain(domain_type: bytes, fork_version: bytes, gvr: bytes) -> bytes:
    # fork_data_root = hash_tree_root(ForkData{current_version: Bytes4,
    #                                           genesis_validators_root: Bytes32})
    fork_version_chunk = fork_version + b"\x00" * 28
    fork_data_root = merkleize([fork_version_chunk, bytes32_root(gvr)])
    return domain_type + fork_data_root[:28]


def compute_signing_root(header: BeaconBlockHeader, domain: bytes) -> bytes:
    # hash_tree_root(SigningData{object_root, domain})
    object_root = header.hash_tree_root()
    return merkleize([bytes32_root(object_root), bytes32_root(domain)])


def popcount(bits) -> int:
    return sum(1 for b in bits if b)


def anchor_hash_tree_root(anchor) -> bytes:
    """Fixed-shape ConsensusAnchor hash_tree_root (12-field container).
    Fields hashed in declared order; finality fields take zero values when
    has_finality is false."""
    if anchor.has_finality:
        finalized_root = anchor.finalized_header.hash_tree_root()
        finality_branch_root = merkleize(
            [bytes32_root(x) for x in anchor.finality_branch], limit=64)
        ancestor_root = merkleize(
            [bytes32_root(x) for x in anchor.ancestor_proof], limit=64)
    else:
        finalized_root = BeaconBlockHeader().hash_tree_root()
        finality_branch_root = merkleize([], limit=64)
        ancestor_root = merkleize([], limit=64)

    sig_bits_root = _bitvector_root(anchor.sync_committee_bits)

    chunks = [
        anchor.attested_header.hash_tree_root(),
        uint64_root(anchor.signature_slot),
        sig_bits_root,
        _bytes96_root(anchor.sync_committee_signature),
        anchor.read_block_header.hash_tree_root(),
        anchor.execution_header.hash_tree_root(),
        merkleize([bytes32_root(x) for x in anchor.execution_branch], limit=64),
        (b"\x01" if anchor.has_finality else b"\x00") + b"\x00" * 31,
        finalized_root,
        finality_branch_root,
        ancestor_root,
    ]
    return merkleize(chunks)


def _bitvector_root(bits) -> bytes:
    # Bitvector[N] -> pack N bits little-endian into ceil(N/8) bytes, then
    # merkleize the 32-byte chunks (Bitvector[32] -> 1 chunk; Bitvector[512] ->
    # 64 bytes -> 2 chunks).
    n = len(bits)
    nbytes = (n + 7) // 8
    by = bytearray(nbytes)
    for i, b in enumerate(bits):
        if b:
            by[i // 8] |= (1 << (i % 8))
    chunks = [bytes(by[j:j + 32]).ljust(32, b"\x00") for j in range(0, max(nbytes, 1), 32)]
    if not chunks:
        chunks = [b"\x00" * 32]
    return merkleize(chunks)


def _bytes96_root(sig: bytes) -> bytes:
    # Bytes96 fixed vector -> 3 chunks merkleized
    assert len(sig) == 96
    chunks = [sig[0:32], sig[32:64], sig[64:96]]
    return merkleize(chunks)


def _read_proof_root(r) -> bytes:
    """hash_tree_root of one ReadProof container (7 fields, declared order)."""
    chunks = [
        (bytes([r.read_kind]) + b"\x00" * 31),               # uint8
        bytes20_root(r.address),                              # Bytes20
        bytes32_root(r.slot),                                 # Bytes32
        bytelist_root(r.value, 128),                          # value (ByteList)
        merkleize([keccak256(n) for n in r.account_proof] or [b"\x00" * 32],
                  limit=64),                                  # List[Bytes, MAX_NODES] node roots
        merkleize([keccak256(n) for n in r.storage_proof] or [b"\x00" * 32],
                  limit=64),
        (bytes([r.presence]) + b"\x00" * 31),                # uint8
    ]
    return merkleize(chunks)


def envelope_signing_root(e) -> bytes:
    """Canonical hash_tree_root(envelope_without_provider_sig) — the pre-image the
    packager signs for provider_sig (spec §Cryptographic Primitives + step 10).

    The envelope SSZ container is merkleized field-for-field in declared order with
    `provider_sig` taken as the EMPTY ByteList (its canonical zero value), so the
    signed root is independent of the signature it carries. Every other field
    (including sig_alg and provider_key_hint) IS covered, binding the chosen
    algorithm and key hint into the signature."""
    reads_root = mix_in_length(
        merkleize([_read_proof_root(r) for r in e.reads] or [b"\x00" * 32],
                  limit=256),
        len(e.reads))
    chunks = [
        (bytes([e.version]) + b"\x00" * 31),                  # uint8
        uint64_root(e.chain_id),
        (bytes([e.anchor_type]) + b"\x00" * 31),             # uint8
        uint64_root(e.settlement_layer),
        uint64_root(e.block_number),
        uint64_root(e.beacon_slot),
        uint64_root(e.timestamp),
        bytes32_root(e.state_root),
        merkleize([                                           # ProofFormat container
            bytes([e.proof_format[0]]) + b"\x00" * 31,
            bytes([e.proof_format[1]]) + b"\x00" * 31,
            bytes([e.proof_format[2]]) + b"\x00" * 31,
        ]),
        (bytes([e.finality_status]) + b"\x00" * 31),          # uint8
        bytes32_root(e.anchor_ref),
        reads_root,
        (bytes([e.sig_alg]) + b"\x00" * 31),                 # uint8
        bytelist_root(b"", 256),                              # provider_sig ZEROED
        bytelist_root(e.provider_key_hint, 256),
    ]
    return merkleize(chunks)


def verify(envelope, anchor, cfg: VerifierConfig):
    a = anchor
    e = envelope

    # Step 1 — self-description cross-check
    if not (e.chain_id == cfg.chain_id and e.anchor_type == 0 and e.version == 1):
        return "REJECT@step1"
    if tuple(e.proof_format) != (0, 0, 0):
        return "REJECT@step1"

    # Step 2 — anchor rehydration & binding
    if anchor_hash_tree_root(a) != e.anchor_ref:
        return "REJECT@step2"

    # Step 3 — participation quorum (strict 2*participants > SYNC_COMMITTEE_SIZE)
    participants = popcount(a.sync_committee_bits)
    if not (2 * participants > C.SYNC_COMMITTEE_SIZE):
        return "REJECT@step3"

    # Step 4 — sync-committee signature
    if not (a.signature_slot > a.attested_header.slot):
        return "REJECT@step4"
    sig_period = C.compute_sync_committee_period_at_slot(a.signature_slot)
    committee = cfg.committees.get(sig_period)
    if committee is None:
        return "REJECT@step4"
    participating = [committee[i] for i, bit in enumerate(a.sync_committee_bits) if bit]
    fork_version_slot = max(a.signature_slot, 1) - 1
    fork_version = C.fork_version_at_epoch(C.compute_epoch_at_slot(fork_version_slot))
    domain = compute_domain(C.DOMAIN_SYNC_COMMITTEE, fork_version, cfg.genesis_validators_root)
    signing_root = compute_signing_root(a.attested_header, domain)
    if not fast_aggregate_verify(participating, signing_root, a.sync_committee_signature):
        return "REJECT@step4"

    # Step 5 — execution binding (cross-field)
    if not verify_merkle_branch(
            leaf=a.execution_header.hash_tree_root(),
            branch=a.execution_branch,
            gindex=C.EXECUTION_PAYLOAD_GINDEX,
            root=a.read_block_header.body_root):
        return "REJECT@step5"
    if a.execution_header.state_root != e.state_root:
        return "REJECT@step5"
    if a.execution_header.block_number != e.block_number:
        return "REJECT@step5"
    if a.execution_header.timestamp != e.timestamp:
        return "REJECT@step5"
    if a.read_block_header.slot != e.beacon_slot:
        return "REJECT@step5"
    if e.finality_status == OPTIMISTIC_HEAD:
        if not (a.read_block_header == a.attested_header):
            return "REJECT@step5"
    bound_state_root = a.execution_header.state_root

    # Step 6 — freshness contract
    if not (a.attested_header.slot >= cfg.head_slot - cfg.max_staleness_slots):
        return "REJECT@step6"
    if not (a.attested_header.slot >= cfg.monotonic_max_seen_slot):
        return "REJECT@step6"
    cfg.monotonic_max_seen_slot = max(cfg.monotonic_max_seen_slot, a.attested_header.slot)

    # Step 7 — finality entailment
    if a.has_finality != (e.finality_status == FINALIZED):
        return "REJECT@step7"
    if e.finality_status == FINALIZED:
        # (a) finalized_header from attested_header.state_root.
        # FINALIZED_ROOT_GINDEX is fork-versioned by the ATTESTED header's slot
        # (105 pre-Electra, 169 Electra+/Fulu).
        fin_gindex = C.finalized_root_gindex_for_attested_slot(a.attested_header.slot)
        if not verify_merkle_branch(
                leaf=a.finalized_header.hash_tree_root(),
                branch=a.finality_branch,
                gindex=fin_gindex,
                root=a.attested_header.state_root):
            return "REJECT@step7"
        # (b) read block is finalized_header itself or a proven ancestor
        leaf = a.read_block_header.hash_tree_root()
        d = a.finalized_header.slot - a.read_block_header.slot
        if a.read_block_header == a.finalized_header:
            if len(a.ancestor_proof) != 0:
                return "REJECT@step7"
        elif d <= C.SLOTS_PER_HISTORICAL_ROOT:   # NEAR ancestor: state.block_roots
            slot_index = a.read_block_header.slot % C.SLOTS_PER_HISTORICAL_ROOT
            gindex = C.block_roots_leaf_gindex(slot_index)
            if not verify_merkle_branch(
                    leaf=leaf,
                    branch=a.ancestor_proof,
                    gindex=gindex,
                    root=a.finalized_header.state_root):
                return "REJECT@step7"
        else:                                     # DEEP ancestor: historical_summaries
            # d > SLOTS_PER_HISTORICAL_ROOT: the read block predates the
            # finalized state's block_roots window, so it is reachable only via
            # state.historical_summaries[i].block_summary_root[slot mod 8192].
            # The verifier carries (summary_index) so it can compose the gindex;
            # we recover it from the proof length-implied path by trusting the
            # carried index on the anchor (untrusted, but a wrong index simply
            # fails the branch check below). summary_index = read_slot // 8192.
            summary_index = a.read_block_header.slot // C.SLOTS_PER_HISTORICAL_ROOT
            slot_index = a.read_block_header.slot % C.SLOTS_PER_HISTORICAL_ROOT
            gindex = C.historical_summaries_leaf_gindex(summary_index, slot_index)
            if not verify_merkle_branch(
                    leaf=leaf,
                    branch=a.ancestor_proof,
                    gindex=gindex,
                    root=a.finalized_header.state_root):
                return "REJECT@step7"

    # Step 8 — per-read Merkle verification (inclusion AND exclusion)
    for r in e.reads:
        if r.presence == 0:   # inclusion
            A = verify_account_inclusion(r.address, r.account_proof, bound_state_root)
            if A is None:
                return "REJECT@step8"
            if r.read_kind == STORAGE:
                got = verify_storage_inclusion(r.slot, r.storage_proof, A["storageRoot"])
                if got is None or got != be_to_int(r.value):
                    return "REJECT@step8"
            elif r.read_kind == BALANCE:
                if A["balance"] != be_to_int(r.value):
                    return "REJECT@step8"
            elif r.read_kind == NONCE:
                if A["nonce"] != be_to_int(r.value):
                    return "REJECT@step8"
            elif r.read_kind == CODE:
                if keccak256(r.value) != A["codeHash"]:
                    return "REJECT@step8"
            else:
                return "REJECT@step8"
        else:                 # presence == 1: exclusion
            if r.read_kind == STORAGE:
                A = verify_account_inclusion(r.address, r.account_proof, bound_state_root)
                if A is None:
                    return "REJECT@step8"
                if not verify_storage_exclusion(r.slot, r.storage_proof, A["storageRoot"]):
                    return "REJECT@step8"
            else:
                if not verify_account_exclusion(r.address, r.account_proof, bound_state_root):
                    return "REJECT@step8"
            if r.value != b"":
                return "REJECT@step8"

    # Step 9 — batch root consistency (all reads bound to the same state_root)
    # In this impl every read is verified against bound_state_root above; an
    # envelope can still carry per-read root hints that disagree. We enforce that
    # any per-read declared root matches bound_state_root.
    for r in e.reads:
        if getattr(r, "declared_state_root", None) is not None:
            if r.declared_state_root != bound_state_root:
                return "REJECT@step9"

    # Step 10 — provider signature (if present)
    provider_sig_ok = None
    if e.sig_alg != 0:
        # Resolve the verifying key through an INDEPENDENT trust path (never from
        # the envelope). The reference uses cfg.resolve_provider_key, standing in
        # for ENS/did:/X.509 resolution; it MUST source the key from trusted
        # config keyed by provider_key_hint, not from envelope bytes.
        msg = envelope_signing_root(e)
        pub = None
        if cfg.resolve_provider_key is not None:
            pub = cfg.resolve_provider_key(e.provider_key_hint, e.sig_alg)
        if pub is None:
            # resolution failed
            if cfg.dispute_mode:
                return "REJECT@step10"      # relied upon -> reject
            provider_sig_ok = False         # tolerated in correctness mode
        else:
            provider_sig_ok = verify_provider_sig(e.sig_alg, pub, msg, e.provider_sig)
            if not provider_sig_ok and cfg.dispute_mode:
                return "REJECT@step10"
            # In plain correctness mode a failed/uncheckable sig is downgraded to
            # unsigned (carries no correctness weight) — spec §Verification step 10.

    return "ACCEPT", {
        "signing_root": signing_root,
        "bound_state_root": bound_state_root,
        "participants": participants,
        "execution_payload_gindex": C.EXECUTION_PAYLOAD_GINDEX,
        "provider_sig_ok": provider_sig_ok,
    }
