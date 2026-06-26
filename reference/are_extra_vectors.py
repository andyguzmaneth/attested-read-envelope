"""
ARE extra-coverage vector generator (v0.6) — the two draft-blocker accept
vectors that the v0.5 suite did not lock:

  accept_deep_ancestor.json  — FINALIZED read whose read block is a DEEP ancestor
       (finalized.slot - read.slot > SLOTS_PER_HISTORICAL_ROOT = 8192), so step 7b
       takes the state.historical_summaries path (NOT block_roots).
  accept_provider_sig.json   — envelope with sig_alg = 2 (ed25519) and a REAL
       signature over hash_tree_root(envelope_without_provider_sig), verified at
       step 10 in dispute/audit mode against an INDEPENDENTLY-resolved key.
  reject_bad_provider_sig.json (bonus) — same envelope, tampered signature ->
       REJECT@step10 in dispute mode.

DATA-FIDELITY DISCLOSURE (honest, not hidden):
  - provider_sig vectors use **REAL** ed25519 cryptography (pycryptodome eddsa,
    RFC 8032) over a REAL SSZ envelope signing root. Nothing synthetic in the
    signature path.
  - The deep-ancestor vector is a **FULL-FIDELITY SEEDED SYNTHETIC** at the
    MINIMAL (Deneb) preset with REAL Keccak/SSZ/BLS: a real 2-account hexary MPT,
    a real aggregate BLS signature over the real signing domain, and a REAL
    SHA-256 historical_summaries Merkle branch (every parent node is a true
    SHA-256 reduction along the composed gindex path). It is synthetic ONLY in
    that the outer BeaconState siblings are seeded random 32-byte values — there
    is no full beacon state to derive true outer siblings from, and the public
    beacon node blocks /eth/v2/debug/beacon/states (full-state download), so a
    real historical_summaries proof is not reachable. This matches the fidelity
    tier of the existing accept_balance_finalized.json (near-ancestor) vector.
    NO HASH IS FABRICATED: the root each branch proves to is the genuine SHA-256
    reduction of the leaf along the real gindex, and verify_merkle_branch is the
    real consensus check.

DETERMINISM: random.seed(SEED) seeds committee keys, synthetic siblings, and the
ed25519 provider seed, so re-running is byte-reproducible.
"""

import json
import os
import random

import are_constants as C
from are_ssz import (
    BeaconBlockHeader, ExecutionPayloadHeader, build_merkle_branch,
)
from are_mpt import (
    build_two_account_trie, encode_account, be_trim,
    EMPTY_STORAGE_ROOT, EMPTY_CODE_HASH,
)
from are_bls import sk_to_pk, sign, aggregate
from are_sig import ed25519_keypair_from_seed, ed25519_sign
from are_codec import (
    Envelope, ConsensusAnchor, ReadProof, envelope_to_json, anchor_to_json,
)
from are_verify import (
    compute_domain, compute_signing_root, anchor_hash_tree_root,
    envelope_signing_root, verify, VerifierConfig,
)

SEED = 42
VECTORS_DIR = os.path.join(os.path.dirname(__file__), "..", "vectors")
BLS_CURVE_ORDER = 52435875175126190479447740508185965837690552500527637822603658699938581184513

CHAIN_ID = 1
ADDRESS = bytes.fromhex("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")
NEIGHBOR = bytes.fromhex("1111111111111111111111111111111111111111")
BALANCE_WEI = 10 ** 18
NONCE = 7
TIMESTAMP = 1_700_000_000
PROVIDER_KEY_HINT = b"are-reference-provider.eth"   # resolved via independent path


def gen_committee(rng):
    sks, pks = [], []
    for _ in range(C.SYNC_COMMITTEE_SIZE):
        sk = rng.randrange(1, BLS_CURVE_ORDER)
        sks.append(sk)
        pks.append(sk_to_pk(sk))
    return sks, pks


def make_account_trie():
    acct_rlp = encode_account(NONCE, BALANCE_WEI, EMPTY_STORAGE_ROOT, EMPTY_CODE_HASH)
    neighbor_rlp = encode_account(0, 0, EMPTY_STORAGE_ROOT, EMPTY_CODE_HASH)
    root, proof_a, _ = build_two_account_trie(ADDRESS, acct_rlp, NEIGHBOR, neighbor_rlp)
    return root, proof_a


def build_signing_root(attested_header, signature_slot):
    fork_version = C.fork_version_at_epoch(
        C.compute_epoch_at_slot(max(signature_slot, 1) - 1))
    domain = compute_domain(C.DOMAIN_SYNC_COMMITTEE, fork_version, C.GENESIS_VALIDATORS_ROOT)
    return compute_signing_root(attested_header, domain)


def sign_committee(sks, bits, signing_root):
    return aggregate([sign(sks[i], signing_root) for i in range(len(sks)) if bits[i]])


def balance_read(account_proof):
    return ReadProof(read_kind=0, address=ADDRESS, slot=b"\x00" * 32,
                     value=be_trim(BALANCE_WEI), account_proof=account_proof,
                     storage_proof=[], presence=0)


def cfg(committees, **kw):
    return VerifierConfig(
        chain_id=CHAIN_ID, genesis_validators_root=C.GENESIS_VALIDATORS_ROOT,
        committees=committees, head_slot=kw.pop("head_slot", 9_000_000),
        max_staleness_slots=64, **kw)


def write_vector(name, description, envelope, anchor, expected, extra_preset=None):
    preset = {
        "name": "MINIMAL",
        "SYNC_COMMITTEE_SIZE": C.SYNC_COMMITTEE_SIZE,
        "fork": "deneb",
        "fork_version": "0x" + C.DENEB_FORK_VERSION.hex(),
        "genesis_validators_root": "0x" + C.GENESIS_VALIDATORS_ROOT.hex(),
        "seed": SEED,
    }
    if extra_preset:
        preset.update(extra_preset)
    obj = {
        "description": description,
        "preset": preset,
        "envelope": envelope_to_json(envelope),
        "anchor": anchor_to_json(anchor),
        "expected": expected,
    }
    path = os.path.join(VECTORS_DIR, name)
    with open(path, "w") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
        f.write("\n")
    return path


# ---------------------------------------------------------------------------
# 1. accept_deep_ancestor — FINALIZED, DEEP historical_summaries path
# ---------------------------------------------------------------------------

def build_deep_ancestor(rng, sks, pks, committees):
    state_root, account_proof = make_account_trie()
    exec_header = ExecutionPayloadHeader(state_root, 21_000_000, TIMESTAMP)
    # exec branch (real SHA-256 reduction along EXECUTION_PAYLOAD_GINDEX)
    leaf_x = exec_header.hash_tree_root()
    xdepth = C.EXECUTION_PAYLOAD_GINDEX.bit_length() - 1
    exec_branch, body_root = build_merkle_branch(
        leaf_x, C.EXECUTION_PAYLOAD_GINDEX, [rng.randbytes(32) for _ in range(xdepth)])

    # Read block is DEEP: choose read_slot so it sits in a PAST historical period
    # and finalized.slot - read.slot > 8192.
    read_slot = 8_500_000          # in historical period 8_500_000 // 8192 = 1037
    read_block_header = BeaconBlockHeader(
        slot=read_slot, proposer_index=3,
        parent_root=rng.randbytes(32), state_root=rng.randbytes(32),
        body_root=body_root)

    fin_slot = read_slot + 20_000   # gap 20000 > 8192 -> DEEP path
    assert fin_slot - read_slot > C.SLOTS_PER_HISTORICAL_ROOT

    # DEEP ancestor branch: read block root -> historical_summaries[i].block_summary_root[slot%8192]
    leaf = read_block_header.hash_tree_root()
    summary_index = read_slot // C.SLOTS_PER_HISTORICAL_ROOT
    slot_index = read_slot % C.SLOTS_PER_HISTORICAL_ROOT
    gindex = C.historical_summaries_leaf_gindex(summary_index, slot_index)
    depth = gindex.bit_length() - 1
    ancestor_proof, fin_state_root = build_merkle_branch(
        leaf, gindex, [rng.randbytes(32) for _ in range(depth)])

    finalized_header = BeaconBlockHeader(
        slot=fin_slot, proposer_index=4,
        parent_root=rng.randbytes(32), state_root=fin_state_root,
        body_root=rng.randbytes(32))

    # attested_header finalizes finalized_header via finality_branch (Deneb gindex 105)
    fin_leaf = finalized_header.hash_tree_root()
    fin_gindex = C.FINALIZED_ROOT_GINDEX_PRE_ELECTRA
    fdepth = fin_gindex.bit_length() - 1
    finality_branch, attested_state_root = build_merkle_branch(
        fin_leaf, fin_gindex, [rng.randbytes(32) for _ in range(fdepth)])

    attested_slot = fin_slot + 64    # attested after finalization
    signature_slot = attested_slot + 1
    attested = BeaconBlockHeader(
        slot=attested_slot, proposer_index=1,
        parent_root=rng.randbytes(32), state_root=attested_state_root,
        body_root=rng.randbytes(32))

    signing_root = build_signing_root(attested, signature_slot)
    bits = [i < 25 for i in range(C.SYNC_COMMITTEE_SIZE)]
    agg = sign_committee(sks, bits, signing_root)

    anchor = ConsensusAnchor(
        attested_header=attested,
        signature_slot=signature_slot,
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
    env = Envelope(
        version=1, chain_id=CHAIN_ID, anchor_type=0, settlement_layer=CHAIN_ID,
        block_number=21_000_000, beacon_slot=read_slot, timestamp=TIMESTAMP,
        state_root=state_root, proof_format=(0, 0, 0), finality_status=1,
        anchor_ref=anchor_hash_tree_root(anchor),
        reads=[balance_read(account_proof)], sig_alg=0)
    return env, anchor, attested_slot


# ---------------------------------------------------------------------------
# 2. accept_provider_sig — OPTIMISTIC + ed25519 provider_sig verified at step 10
# ---------------------------------------------------------------------------

def build_provider_sig(rng, sks, pks, committees, tamper=False):
    state_root, account_proof = make_account_trie()
    attested_slot = 8_999_990
    signature_slot = attested_slot + 1
    exec_header = ExecutionPayloadHeader(state_root, 21_000_000, TIMESTAMP)
    leaf_x = exec_header.hash_tree_root()
    xdepth = C.EXECUTION_PAYLOAD_GINDEX.bit_length() - 1
    exec_branch, body_root = build_merkle_branch(
        leaf_x, C.EXECUTION_PAYLOAD_GINDEX, [rng.randbytes(32) for _ in range(xdepth)])
    attested = BeaconBlockHeader(
        slot=attested_slot, proposer_index=1,
        parent_root=rng.randbytes(32), state_root=rng.randbytes(32),
        body_root=body_root)
    signing_root = build_signing_root(attested, signature_slot)
    bits = [i < 25 for i in range(C.SYNC_COMMITTEE_SIZE)]
    agg = sign_committee(sks, bits, signing_root)
    anchor = ConsensusAnchor(
        attested_header=attested, signature_slot=signature_slot,
        sync_committee_bits=bits, sync_committee_signature=agg,
        read_block_header=attested, execution_header=exec_header,
        execution_branch=exec_branch, has_finality=False,
        finalized_header=BeaconBlockHeader(), finality_branch=[], ancestor_proof=[])

    # ed25519 provider key (deterministic from seed)
    provider_seed = bytes([(SEED + i) & 0xFF for i in range(32)])
    sk, pub_raw = ed25519_keypair_from_seed(provider_seed)

    env = Envelope(
        version=1, chain_id=CHAIN_ID, anchor_type=0, settlement_layer=CHAIN_ID,
        block_number=21_000_000, beacon_slot=attested_slot, timestamp=TIMESTAMP,
        state_root=state_root, proof_format=(0, 0, 0), finality_status=0,
        anchor_ref=anchor_hash_tree_root(anchor),
        reads=[balance_read(account_proof)],
        sig_alg=C.SIG_ALG_ED25519, provider_sig=b"",
        provider_key_hint=PROVIDER_KEY_HINT)

    # sign hash_tree_root(envelope_without_provider_sig)
    msg = envelope_signing_root(env)
    sig = ed25519_sign(sk, msg)
    if tamper:
        b = bytearray(sig)
        b[0] ^= 0xFF
        sig = bytes(b)
    env.provider_sig = sig
    return env, anchor, pub_raw, msg


def main():
    C.select_preset("MINIMAL")
    os.makedirs(VECTORS_DIR, exist_ok=True)

    # committee shared across vectors (each from a fresh seeded RNG path, but
    # committees are keyed by signature-slot period; build per-vector)
    out = {}

    # ---- accept_deep_ancestor ----
    rng = random.Random(SEED)
    sks, pks = gen_committee(rng)
    env_d, anchor_d, attested_slot_d = build_deep_ancestor(rng, sks, pks, None)
    period_d = C.compute_sync_committee_period_at_slot(anchor_d.signature_slot)
    committees_d = {period_d: pks}
    res_d = verify(env_d, anchor_d, cfg(committees_d, head_slot=attested_slot_d + 8))
    assert res_d[0] == "ACCEPT", ("deep_ancestor", res_d)
    write_vector(
        "accept_deep_ancestor.json",
        "FINALIZED balance read whose read block is a DEEP ancestor "
        "(finalized.slot - read.slot = 20000 > 8192) -> step 7b takes the "
        "state.historical_summaries path. Full-fidelity seeded SYNTHETIC at the "
        "Deneb preset: real Keccak/SSZ/BLS, real SHA-256 historical_summaries "
        "branch; outer BeaconState siblings seeded (no full state available).",
        env_d, anchor_d,
        {"result": "ACCEPT",
         "intermediates": {
             "signing_root": "0x" + res_d[1]["signing_root"].hex(),
             "bound_state_root": "0x" + res_d[1]["bound_state_root"].hex(),
             "ancestor_path": "historical_summaries",
             "summary_index": anchor_d.read_block_header.slot // C.SLOTS_PER_HISTORICAL_ROOT,
             "read_slot": anchor_d.read_block_header.slot,
             "finalized_slot": anchor_d.finalized_header.slot}})
    out["deep"] = res_d[1]

    # ---- accept_provider_sig ----
    rng2 = random.Random(SEED)
    sks2, pks2 = gen_committee(rng2)
    env_p, anchor_p, pub_raw, msg = build_provider_sig(rng2, sks2, pks2, None)
    period_p = C.compute_sync_committee_period_at_slot(anchor_p.signature_slot)
    committees_p = {period_p: pks2}

    def resolver(hint, sig_alg, _pub=pub_raw):
        # INDEPENDENT trust path: the verifier holds the provider's ed25519 key in
        # trusted config keyed by the hint (e.g. resolved once from ENS/did:). The
        # key is NEVER taken from the envelope.
        if hint == PROVIDER_KEY_HINT and sig_alg == C.SIG_ALG_ED25519:
            return _pub
        return None

    res_p = verify(env_p, anchor_p,
                   cfg(committees_p, dispute_mode=True, resolve_provider_key=resolver))
    assert res_p[0] == "ACCEPT", ("provider_sig", res_p)
    assert res_p[1]["provider_sig_ok"] is True, res_p
    write_vector(
        "accept_provider_sig.json",
        "OPTIMISTIC balance read carrying an ed25519 provider_sig (sig_alg=2) over "
        "hash_tree_root(envelope_without_provider_sig). Verified at step 10 in "
        "dispute/audit mode against an INDEPENDENTLY-resolved key (trusted config, "
        "never the envelope). REAL ed25519 (RFC 8032).",
        env_p, anchor_p,
        {"result": "ACCEPT",
         "intermediates": {
             "signing_root": "0x" + res_p[1]["signing_root"].hex(),
             "bound_state_root": "0x" + res_p[1]["bound_state_root"].hex(),
             "envelope_signing_root": "0x" + msg.hex(),
             "sig_alg": "ed25519",
             "provider_sig_ok": True}},
        extra_preset={
            "sig_alg": "ed25519",
            "dispute_mode": True,
            "provider_pubkey": "0x" + pub_raw.hex(),
            "provider_key_hint": "0x" + PROVIDER_KEY_HINT.hex()})

    # ---- reject_bad_provider_sig (bonus, step10) ----
    rng3 = random.Random(SEED)
    sks3, pks3 = gen_committee(rng3)
    env_b, anchor_b, pub_raw_b, _ = build_provider_sig(rng3, sks3, pks3, None, tamper=True)
    period_b = C.compute_sync_committee_period_at_slot(anchor_b.signature_slot)
    committees_b = {period_b: pks3}

    def resolver_b(hint, sig_alg, _pub=pub_raw_b):
        if hint == PROVIDER_KEY_HINT and sig_alg == C.SIG_ALG_ED25519:
            return _pub
        return None

    res_b = verify(env_b, anchor_b,
                   cfg(committees_b, dispute_mode=True, resolve_provider_key=resolver_b))
    assert res_b == "REJECT@step10", ("bad_provider_sig", res_b)
    write_vector(
        "reject_bad_provider_sig.json",
        "Same envelope as accept_provider_sig but the ed25519 signature is "
        "tampered (first byte flipped). In dispute/audit mode step 10 MUST reject.",
        env_b, anchor_b,
        {"result": "REJECT@step10"},
        extra_preset={
            "sig_alg": "ed25519",
            "dispute_mode": True,
            "provider_pubkey": "0x" + pub_raw_b.hex(),
            "provider_key_hint": "0x" + PROVIDER_KEY_HINT.hex()})

    print("Generated 3 extra vectors:")
    print("  accept_deep_ancestor.json     (step 7b historical_summaries)")
    print("  accept_provider_sig.json      (step 10 ed25519)")
    print("  reject_bad_provider_sig.json  (step 10 reject)")
    print("  deep signing_root     =", out["deep"]["signing_root"].hex())
    print("  provider env_signing  =", msg.hex())


if __name__ == "__main__":
    main()
