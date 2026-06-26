"""
MAINNET-fidelity REAL-DATA vector generator (v0.5).

Builds `vectors/accept_mainnet_real.json` from genuine mainnet bytes captured in
`vectors/real-data/`:

  - finality_update.json   — LightClient finality_update (attested + finalized
                             headers w/ FULL execution payloads, finality_branch,
                             sync_aggregate, signature_slot) from a public
                             beacon-API (publicnode.com).
  - bootstrap_committee.json — LightClientBootstrap current_sync_committee (the
                             real 512 pubkeys for the period) — TRUSTED config.
  - eth_getproof_weth.json — real eth_getProof for WETH
                             (0xC02a…Cc2) account + storage slot 0 at the
                             finalized block (exec block 25404693), whose
                             accountProof roots to the FINALIZED header's EL
                             state_root.

NO byte is fabricated. The signature is a real BLS aggregate over 510/512 real
committee members; the account/storage proofs are real hexary MPT proofs; the
execution payload is the real 17-field header; the finality branch is real at
gindex 169 (Fulu).

This is a FINALIZED, trivial-ancestor envelope: read_block_header ==
finalized_header (the finalized header itself carries the execution payload), so
ancestor_proof is empty. The signed attested_header finalizes that header via the
real finality_branch.

Provenance:
  beacon: publicnode.com finality_update; attested slot 14640721,
          finalized slot 14640640, signature slot 14640722, period 1787,
          fork Fulu (current_version 0x06000000).
  execution: block 25404693, EL state_root
          0xf6c792621f2a4df8b83abcaf1c72aff30c571fcfb14533ebefd5327b2b53f2a1.
"""

import json
import os

import are_constants as C
from are_ssz import BeaconBlockHeader, ExecutionPayloadHeader
from are_mpt import be_trim, be_to_int
from are_codec import (
    Envelope, ConsensusAnchor, ReadProof, envelope_to_json, anchor_to_json,
)
from are_verify import anchor_hash_tree_root, verify, VerifierConfig

HERE = os.path.dirname(__file__)
RD = os.path.join(HERE, "..", "vectors", "real-data")
VECTORS_DIR = os.path.join(HERE, "..", "vectors")

WETH = bytes.fromhex("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")
CHAIN_ID = 1


def hb(s):
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


def load_committee():
    bs = json.load(open(os.path.join(RD, "bootstrap_committee.json")))
    return [hb(p) for p in bs["current_sync_committee"]["pubkeys"]]


def build_header(beacon):
    return BeaconBlockHeader(
        slot=int(beacon["slot"]),
        proposer_index=int(beacon["proposer_index"]),
        parent_root=hb(beacon["parent_root"]),
        state_root=hb(beacon["state_root"]),
        body_root=hb(beacon["body_root"]),
    )


def build_exec_header(ex):
    return ExecutionPayloadHeader(
        state_root=hb(ex["state_root"]),
        block_number=int(ex["block_number"]),
        timestamp=int(ex["timestamp"]),
        parent_hash=hb(ex["parent_hash"]),
        fee_recipient=hb(ex["fee_recipient"]),
        receipts_root=hb(ex["receipts_root"]),
        logs_bloom=hb(ex["logs_bloom"]),
        prev_randao=hb(ex["prev_randao"]),
        gas_limit=int(ex["gas_limit"]),
        gas_used=int(ex["gas_used"]),
        extra_data=hb(ex["extra_data"]),
        base_fee_per_gas=int(ex["base_fee_per_gas"]),
        block_hash=hb(ex["block_hash"]),
        transactions_root=hb(ex["transactions_root"]),
        withdrawals_root=hb(ex["withdrawals_root"]),
        blob_gas_used=int(ex["blob_gas_used"]),
        excess_blob_gas=int(ex["excess_blob_gas"]),
    )


def bits_from_hex(bits_hex, size=512):
    bb = hb(bits_hex)
    return [(bb[i // 8] >> (i % 8)) & 1 == 1 for i in range(size)]


def main():
    C.select_preset("MAINNET")
    fu = json.load(open(os.path.join(RD, "finality_update.json")))["data"]
    gp = json.load(open(os.path.join(RD, "eth_getproof_weth.json")))["result"]
    committee = load_committee()

    attested = build_header(fu["attested_header"]["beacon"])
    finalized = build_header(fu["finalized_header"]["beacon"])
    # FULL execution header is the FINALIZED header's payload (the read block).
    exec_header = build_exec_header(fu["finalized_header"]["execution"])
    exec_branch = [hb(x) for x in fu["finalized_header"]["execution_branch"]]
    finality_branch = [hb(x) for x in fu["finality_branch"]]
    sig = hb(fu["sync_aggregate"]["sync_committee_signature"])
    bits = bits_from_hex(fu["sync_aggregate"]["sync_committee_bits"])
    signature_slot = int(fu["signature_slot"])

    # FINALIZED, trivial ancestor: read_block_header == finalized_header.
    anchor = ConsensusAnchor(
        attested_header=attested,
        signature_slot=signature_slot,
        sync_committee_bits=bits,
        sync_committee_signature=sig,
        read_block_header=finalized,        # == finalized_header
        execution_header=exec_header,
        execution_branch=exec_branch,
        has_finality=True,
        finalized_header=finalized,
        finality_branch=finality_branch,
        ancestor_proof=[],                  # trivial: read block IS finalized
    )

    # Two real reads at the SAME finalized state_root: WETH balance (account
    # inclusion) + WETH storage slot 0 (storage inclusion).
    account_proof = [hb(n) for n in gp["accountProof"]]
    balance = int(gp["balance"], 16)
    sp = gp["storageProof"][0]
    storage_proof = [hb(n) for n in sp["proof"]]
    slot = hb(sp["key"])
    slot_value = int(sp["value"], 16)

    reads = [
        ReadProof(read_kind=0, address=WETH, slot=b"\x00" * 32,
                  value=be_trim(balance), account_proof=account_proof,
                  storage_proof=[], presence=0),
        ReadProof(read_kind=1, address=WETH, slot=slot,
                  value=be_trim(slot_value), account_proof=account_proof,
                  storage_proof=storage_proof, presence=0),
    ]

    envelope = Envelope(
        version=1, chain_id=CHAIN_ID, anchor_type=0, settlement_layer=CHAIN_ID,
        block_number=int(gp.get("blockNumber", 25404693)) if False else 25404693,
        beacon_slot=finalized.slot,
        timestamp=exec_header.timestamp,
        state_root=exec_header.state_root,
        proof_format=(0, 0, 0),
        finality_status=1,                 # FINALIZED
        anchor_ref=anchor_hash_tree_root(anchor),
        reads=reads, sig_alg=0,
    )

    # Verify through the reference verifier with the REAL committee as trusted
    # config and a head_slot just past the attested slot.
    period = C.compute_sync_committee_period_at_slot(signature_slot)
    cfg = VerifierConfig(
        chain_id=CHAIN_ID, genesis_validators_root=C.GENESIS_VALIDATORS_ROOT,
        committees={period: committee},
        head_slot=attested.slot + 8, max_staleness_slots=64)
    res = verify(envelope, anchor, cfg)
    assert res[0] == "ACCEPT", res
    intermediates = res[1]

    obj = {
        "description": (
            "MAINNET REAL-DATA: FINALIZED WETH balance + storage slot 0 at exec "
            "block 25404693, anchored to a real 512-member sync-committee "
            "aggregate (510 participants) on a real beacon finality_update "
            "(attested slot 14640721, finalized slot 14640640, sig slot 14640722, "
            "fork Fulu 0x06000000). Real hexary account/storage MPT proofs, real "
            "17-field ExecutionPayloadHeader, real finality_branch at gindex 169."
        ),
        "preset": {
            "name": "MAINNET",
            "SYNC_COMMITTEE_SIZE": 512,
            "fork": "fulu",
            "fork_version": "0x" + C.FULU_FORK_VERSION.hex(),
            "genesis_validators_root": "0x" + C.GENESIS_VALIDATORS_ROOT.hex(),
            "source_block_number": 25404693,
            "source_el_state_root": "0x" + exec_header.state_root.hex(),
            "source_attested_slot": attested.slot,
            "source_finalized_slot": finalized.slot,
            "source_signature_slot": signature_slot,
            "source_sync_committee_period": period,
            "bootstrap_block_root":
                "0xb0cfd5f1d92b199cdaa3fbe876ce574e1fecc9288711daaa60e7c32ca44331a7",
            "data_origin": "publicnode.com beacon-API + execution RPC (real, captured)",
        },
        "envelope": envelope_to_json(envelope),
        "anchor": anchor_to_json(anchor),
        "expected": {
            "result": "ACCEPT",
            "intermediates": {
                "signing_root": "0x" + intermediates["signing_root"].hex(),
                "bound_state_root": "0x" + intermediates["bound_state_root"].hex(),
                "participants": intermediates["participants"],
                "execution_payload_gindex": C.EXECUTION_PAYLOAD_GINDEX,
                "finalized_root_gindex": C.FINALIZED_ROOT_GINDEX_ELECTRA,
            },
        },
    }
    path = os.path.join(VECTORS_DIR, "accept_mainnet_real.json")
    with open(path, "w") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
        f.write("\n")
    print("Wrote accept_mainnet_real.json")
    print("  participants     =", intermediates["participants"], "/ 512")
    print("  signing_root     = 0x" + intermediates["signing_root"].hex())
    print("  bound_state_root = 0x" + intermediates["bound_state_root"].hex())


if __name__ == "__main__":
    main()
