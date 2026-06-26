"""
Deterministic ARE test-vector generator (v0.4, MINIMAL preset).

DETERMINISM: random.seed(SEED) seeds ALL committee key generation and all
synthetic-sibling material. BLS Sign is deterministic given the secret key, and
SHA-256/Keccak are deterministic, so re-running this script produces
BYTE-IDENTICAL vectors. The seed is documented in reference/README.md.

Emits 6 vectors into ../vectors/:
  accept_balance.json            (OPTIMISTIC, records signing_root + bound_state_root)
  accept_balance_finalized.json  (FINALIZED, near-ancestor block_roots path)
  reject_quorum_too_low.json     (step3)
  reject_bad_bls.json            (step4)
  reject_unproven_absence.json   (step8)
  reject_mixed_root_batch.json   (step9)
"""

import json
import os
import random

import are_constants as C
from are_ssz import (
    BeaconBlockHeader, ExecutionPayloadHeader, merkleize, bytes32_root,
    build_merkle_branch,
)
from are_mpt import (
    build_two_account_trie, encode_account, keccak256,
    EMPTY_STORAGE_ROOT, EMPTY_CODE_HASH, be_trim,
)
from are_bls import sk_to_pk, sign, aggregate
from are_codec import (
    Envelope, ConsensusAnchor, ReadProof,
    envelope_to_json, anchor_to_json,
)
from are_verify import (
    compute_domain, compute_signing_root, anchor_hash_tree_root, verify,
    VerifierConfig,
)

SEED = 42
VECTORS_DIR = os.path.join(os.path.dirname(__file__), "..", "vectors")

# ---- shared fixture parameters ----
CHAIN_ID = 1
ADDRESS = bytes.fromhex("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")
# NEIGHBOR shares the trie with ADDRESS as a real 2-leaf hexary branch. It must
# diverge from ADDRESS at the FIRST nibble of keccak256(addr); 0x1111…11 does
# (verified: ADDRESS->nibble 0x1, NEIGHBOR->nibble 0xe).
NEIGHBOR = bytes.fromhex("1111111111111111111111111111111111111111")
ABSENT_ADDR = bytes.fromhex("2222222222222222222222222222222222222222")
BALANCE_WEI = 10**18                      # 1 ETH
NONCE = 7
ATTESTED_SLOT = 8_999_990
SIGNATURE_SLOT = ATTESTED_SLOT + 1        # carried as DATA (attested.slot + 1)
BLOCK_NUMBER = 21_000_000
TIMESTAMP = 1_700_000_000
HEAD_SLOT = 9_000_000
MAX_STALENESS = 64


# BLS12-381 subgroup order r
BLS_CURVE_ORDER = 52435875175126190479447740508185965837690552500527637822603658699938581184513


def gen_committee(rng):
    """Generate SYNC_COMMITTEE_SIZE BLS keypairs from the seeded RNG."""
    sks, pks = [], []
    for _ in range(C.SYNC_COMMITTEE_SIZE):
        sk = rng.randrange(1, BLS_CURVE_ORDER)   # valid nonzero scalar mod r
        sks.append(sk)
        pks.append(sk_to_pk(sk))
    return sks, pks


def make_account_trie(balance=BALANCE_WEI, nonce=NONCE):
    """Real 2-leaf hexary trie {ADDRESS, NEIGHBOR}. Returns (root, proof_for_ADDRESS).
    Verified through the SAME real hexary walker as the mainnet vector."""
    acct_rlp = encode_account(nonce, balance, EMPTY_STORAGE_ROOT, EMPTY_CODE_HASH)
    neighbor_rlp = encode_account(0, 0, EMPTY_STORAGE_ROOT, EMPTY_CODE_HASH)
    root, proof_a, _proof_b = build_two_account_trie(
        ADDRESS, acct_rlp, NEIGHBOR, neighbor_rlp)
    return root, proof_a


def make_execution_header(state_root):
    return ExecutionPayloadHeader(state_root, BLOCK_NUMBER, TIMESTAMP)


def make_exec_branch(exec_header, rng):
    """Build a REAL SSZ Merkle branch for exec_header at EXECUTION_PAYLOAD_GINDEX.
    Synthetic siblings are random 32-byte values from the seeded RNG; the body
    root is the real SHA-256 reduction along the gindex path."""
    leaf = exec_header.hash_tree_root()
    depth = C.EXECUTION_PAYLOAD_GINDEX.bit_length() - 1
    siblings = [rng.randbytes(32) for _ in range(depth)]
    branch, body_root = build_merkle_branch(leaf, C.EXECUTION_PAYLOAD_GINDEX, siblings)
    return branch, body_root


def sign_committee(sks, pks, bits, signing_root):
    sigs = [sign(sks[i], signing_root) for i in range(len(sks)) if bits[i]]
    agg = aggregate(sigs)
    return agg


def build_signing_root(attested_header):
    fork_version = C.fork_version_at_epoch(
        C.compute_epoch_at_slot(max(SIGNATURE_SLOT, 1) - 1))
    domain = compute_domain(C.DOMAIN_SYNC_COMMITTEE, fork_version, C.GENESIS_VALIDATORS_ROOT)
    return compute_signing_root(attested_header, domain)


def base_optimistic_anchor(sks, pks, rng, participants=25, bad_bls=False):
    state_root, account_proof = make_account_trie()
    exec_header = make_execution_header(state_root)
    exec_branch, body_root = make_exec_branch(exec_header, rng)

    attested = BeaconBlockHeader(
        slot=ATTESTED_SLOT, proposer_index=1,
        parent_root=rng.randbytes(32), state_root=rng.randbytes(32),
        body_root=body_root)

    bits = [i < participants for i in range(C.SYNC_COMMITTEE_SIZE)]
    signing_root = build_signing_root(attested)
    agg = sign_committee(sks, pks, bits, signing_root)
    if bad_bls:
        # flip a byte in the signature -> still 96 bytes, BLS verify fails
        b = bytearray(agg)
        b[10] ^= 0xFF
        agg = bytes(b)

    anchor = ConsensusAnchor(
        attested_header=attested,
        signature_slot=SIGNATURE_SLOT,
        sync_committee_bits=bits,
        sync_committee_signature=agg,
        read_block_header=attested,          # OPTIMISTIC: read block == attested
        execution_header=exec_header,
        execution_branch=exec_branch,
        has_finality=False,
        finalized_header=BeaconBlockHeader(),
        finality_branch=[],
        ancestor_proof=[],
    )
    return anchor, state_root, account_proof, signing_root


def make_envelope(state_root, anchor, reads, finality_status=0):
    return Envelope(
        version=1, chain_id=CHAIN_ID, anchor_type=0, settlement_layer=CHAIN_ID,
        block_number=BLOCK_NUMBER, beacon_slot=ATTESTED_SLOT, timestamp=TIMESTAMP,
        state_root=state_root, proof_format=(0, 0, 0),
        finality_status=finality_status,
        anchor_ref=anchor_hash_tree_root(anchor),
        reads=reads, sig_alg=0,
    )


def balance_read(account_proof):
    return ReadProof(
        read_kind=0, address=ADDRESS, slot=b"\x00" * 32,
        value=be_trim(BALANCE_WEI), account_proof=account_proof,
        storage_proof=[], presence=0)


def cfg(committees):
    return VerifierConfig(
        chain_id=CHAIN_ID, genesis_validators_root=C.GENESIS_VALIDATORS_ROOT,
        committees=committees, head_slot=HEAD_SLOT, max_staleness_slots=MAX_STALENESS)


def write_vector(name, description, envelope, anchor, expected):
    obj = {
        "description": description,
        "preset": {
            "name": "MINIMAL",
            "SYNC_COMMITTEE_SIZE": C.SYNC_COMMITTEE_SIZE,
            "fork": "deneb",
            "fork_version": "0x" + C.DENEB_FORK_VERSION.hex(),
            "genesis_validators_root": "0x" + C.GENESIS_VALIDATORS_ROOT.hex(),
            "seed": SEED,
        },
        "envelope": envelope_to_json(envelope),
        "anchor": anchor_to_json(anchor),
        "expected": expected,
    }
    path = os.path.join(VECTORS_DIR, name)
    with open(path, "w") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
        f.write("\n")
    return path


def main():
    C.select_preset("MINIMAL")
    os.makedirs(VECTORS_DIR, exist_ok=True)
    rng = random.Random(SEED)
    sks, pks = gen_committee(rng)
    sig_period = C.compute_sync_committee_period_at_slot(SIGNATURE_SLOT)
    committees = {sig_period: pks}

    intermediates = {}

    # ---- 1. accept_balance (OPTIMISTIC) ----
    anchor, state_root, account_proof, signing_root = base_optimistic_anchor(sks, pks, rng, participants=25)
    env = make_envelope(state_root, anchor, [balance_read(account_proof)])
    res = verify(env, anchor, cfg(committees))
    assert res[0] == "ACCEPT", res
    intermediates["signing_root"] = "0x" + res[1]["signing_root"].hex()
    intermediates["bound_state_root"] = "0x" + res[1]["bound_state_root"].hex()
    write_vector("accept_balance.json",
                 "OPTIMISTIC static-balance read (Appendix A). Records intermediates "
                 "signing_root and bound_state_root; 25/32 participants.",
                 env, anchor,
                 {"result": "ACCEPT",
                  "intermediates": {
                      "signing_root": intermediates["signing_root"],
                      "bound_state_root": intermediates["bound_state_root"],
                      "execution_payload_gindex": C.EXECUTION_PAYLOAD_GINDEX,
                      "participants": 25}})

    # ---- 2. accept_balance_finalized (near-ancestor block_roots path) ----
    fin_anchor = build_finalized(sks, pks, rng, committees)
    state_root_f, account_proof_f = make_account_trie()
    env_f = make_envelope(state_root_f, fin_anchor, [balance_read(account_proof_f)], finality_status=1)
    # fix beacon_slot to read_block_header.slot
    env_f.beacon_slot = fin_anchor.read_block_header.slot
    env_f.anchor_ref = anchor_hash_tree_root(fin_anchor)
    res_f = verify(env_f, fin_anchor, cfg(committees))
    assert res_f[0] == "ACCEPT", res_f
    write_vector("accept_balance_finalized.json",
                 "FINALIZED balance read exercising the NEAR-ancestor state.block_roots "
                 "path (read_block_header distinct from finalized_header, within 8192 slots).",
                 env_f, fin_anchor,
                 {"result": "ACCEPT",
                  "intermediates": {
                      "signing_root": "0x" + res_f[1]["signing_root"].hex(),
                      "bound_state_root": "0x" + res_f[1]["bound_state_root"].hex()}})

    # ---- 3. reject_quorum_too_low (step3): 16/32 participants (2*16 == 32, not > 32) ----
    rng3 = clone_rng()
    sks3, pks3 = gen_committee(rng3)
    committees3 = {sig_period: pks3}
    anchor3, sr3, ap3, _ = base_optimistic_anchor(sks3, pks3, rng3, participants=16)
    env3 = make_envelope(sr3, anchor3, [balance_read(ap3)])
    res3 = verify(env3, anchor3, cfg(committees3))
    assert res3 == "REJECT@step3", res3
    write_vector("reject_quorum_too_low.json",
                 "Sub-quorum participation: 16/32 (2*16 == 32, not strictly > 32). "
                 "BLS aggregate is genuine but fails the §3 quorum gate.",
                 env3, anchor3, {"result": "REJECT@step3"})

    # ---- 4. reject_bad_bls (step4): valid quorum, corrupted aggregate signature ----
    rng4 = clone_rng()
    sks4, pks4 = gen_committee(rng4)
    committees4 = {sig_period: pks4}
    anchor4, sr4, ap4, _ = base_optimistic_anchor(sks4, pks4, rng4, participants=25, bad_bls=True)
    env4 = make_envelope(sr4, anchor4, [balance_read(ap4)])
    res4 = verify(env4, anchor4, cfg(committees4))
    assert res4 == "REJECT@step4", res4
    write_vector("reject_bad_bls.json",
                 "Quorum met (25/32) but the aggregate signature is corrupted -> "
                 "FastAggregateVerify fails at §4.",
                 env4, anchor4, {"result": "REJECT@step4"})

    # ---- 5. reject_unproven_absence (step8): presence==0 but account absent ----
    rng5 = clone_rng()
    sks5, pks5 = gen_committee(rng5)
    committees5 = {sig_period: pks5}
    anchor5, sr5, ap5, _ = base_optimistic_anchor(sks5, pks5, rng5, participants=25)
    # bare "zero/not found": claim presence==0 (inclusion) with a value but an
    # account_proof that does NOT commit the queried address. ABSENT_ADDR resolves
    # to an empty branch slot in the real 2-leaf trie -> proven absence, so a
    # presence==0 (inclusion) claim MUST be rejected at step 8.
    other_addr = ABSENT_ADDR
    bad_read = ReadProof(read_kind=0, address=other_addr, slot=b"\x00" * 32,
                         value=be_trim(BALANCE_WEI), account_proof=ap5,
                         storage_proof=[], presence=0)
    env5 = make_envelope(sr5, anchor5, [bad_read])
    res5 = verify(env5, anchor5, cfg(committees5))
    assert res5 == "REJECT@step8", res5
    write_vector("reject_unproven_absence.json",
                 "presence==0 (inclusion claimed) for an address the account_proof does "
                 "NOT commit -> unproven absence rejected at §8.",
                 env5, anchor5, {"result": "REJECT@step8"})

    # ---- 6. reject_mixed_root_batch (step9): two reads, one declares a different root ----
    rng6 = clone_rng()
    sks6, pks6 = gen_committee(rng6)
    committees6 = {sig_period: pks6}
    anchor6, sr6, ap6, _ = base_optimistic_anchor(sks6, pks6, rng6, participants=25)
    r1 = balance_read(ap6)
    # r2: a valid inclusion against bound_state_root (so §8 passes) but it declares
    # a DIFFERENT state_root -> the mixed-root batch must be rejected at §9.
    r2 = balance_read(ap6)
    r2.declared_state_root = bytes.fromhex("de" * 32)
    env6 = make_envelope(sr6, anchor6, [r1, r2])
    res6 = verify(env6, anchor6, cfg(committees6))
    assert res6 == "REJECT@step9", res6
    write_vector("reject_mixed_root_batch.json",
                 "Batch of 2 reads where the second declares a state_root != bound_state_root "
                 "(packager pairing reserve0@N with reserve1@N+5) -> rejected at §9.",
                 env6, anchor6, {"result": "REJECT@step9"})

    print("Generated 6 vectors.")
    print("  signing_root     =", intermediates["signing_root"])
    print("  bound_state_root =", intermediates["bound_state_root"])


_RNG_LOG = []


def clone_rng():
    """Each reject vector regenerates its own committee from a FRESH seeded RNG so
    the vectors are independent yet still fully deterministic."""
    return random.Random(SEED)


def build_finalized(sks, pks, rng, committees):
    """Build a FINALIZED anchor exercising the near-ancestor block_roots path."""
    state_root, _ = make_account_trie()
    exec_header = make_execution_header(state_root)
    exec_branch, body_root = make_exec_branch(exec_header, rng)

    read_slot = ATTESTED_SLOT
    read_block_header = BeaconBlockHeader(
        slot=read_slot, proposer_index=1,
        parent_root=rng.randbytes(32), state_root=rng.randbytes(32),
        body_root=body_root)

    # finalized_header is a LATER block (within 8192 slots) whose state.block_roots
    # accumulates read_block_header's root. Build a real branch.
    fin_slot = read_slot + 100
    leaf = read_block_header.hash_tree_root()
    slot_index = read_slot % C.SLOTS_PER_HISTORICAL_ROOT
    gindex = C.block_roots_leaf_gindex(slot_index)
    depth = gindex.bit_length() - 1
    siblings = [rng.randbytes(32) for _ in range(depth)]
    ancestor_proof, fin_state_root = build_merkle_branch(leaf, gindex, siblings)

    finalized_header = BeaconBlockHeader(
        slot=fin_slot, proposer_index=2,
        parent_root=rng.randbytes(32), state_root=fin_state_root,
        body_root=rng.randbytes(32))

    # attested_header finalizes finalized_header via finality_branch from
    # attested_header.state_root.
    fin_leaf = finalized_header.hash_tree_root()
    # MINIMAL fixtures are Deneb -> pre-Electra FINALIZED_ROOT_GINDEX (105).
    fin_gindex = C.FINALIZED_ROOT_GINDEX_PRE_ELECTRA
    fdepth = fin_gindex.bit_length() - 1
    fsiblings = [rng.randbytes(32) for _ in range(fdepth)]
    finality_branch, attested_state_root = build_merkle_branch(
        fin_leaf, fin_gindex, fsiblings)

    attested = BeaconBlockHeader(
        slot=ATTESTED_SLOT, proposer_index=1,
        parent_root=rng.randbytes(32), state_root=attested_state_root,
        body_root=rng.randbytes(32))   # body_root here unused for exec (read != attested)

    signing_root = build_signing_root(attested)
    bits = [i < 25 for i in range(C.SYNC_COMMITTEE_SIZE)]
    agg = sign_committee(sks, pks, bits, signing_root)

    anchor = ConsensusAnchor(
        attested_header=attested,
        signature_slot=SIGNATURE_SLOT,
        sync_committee_bits=bits,
        sync_committee_signature=agg,
        read_block_header=read_block_header,
        execution_header=exec_header,
        execution_branch=exec_branch,
        has_finality=True,
        finalized_header=finalized_header,
        finality_branch=finality_branch,
        ancestor_proof=ancestor_proof,
    )
    return anchor


if __name__ == "__main__":
    main()
