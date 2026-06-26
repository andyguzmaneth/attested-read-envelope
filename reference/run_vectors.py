"""
Load all 6 ARE vectors and assert expected == actual verifier output.
Prints "N/6 passed". Exit 1 on any mismatch.
"""

import glob
import json
import os
import sys

import are_constants as C
from are_codec import envelope_from_json, anchor_from_json
from are_bls import sk_to_pk
from are_verify import verify, VerifierConfig, anchor_hash_tree_root

VECTORS_DIR = os.path.join(os.path.dirname(__file__), "..", "vectors")
SEED = 42
HEAD_SLOT = 9_000_000
MAX_STALENESS = 64
SIGNATURE_SLOT = 8_999_991


def rebuild_committees():
    """Rebuild the committee pubkeys deterministically from the seed so the
    verifier can select the period's committee (committees are trusted config,
    not carried in the vector)."""
    import random
    BLS_CURVE_ORDER = 52435875175126190479447740508185965837690552500527637822603658699938581184513
    rng = random.Random(SEED)
    pks = []
    for _ in range(C.SYNC_COMMITTEE_SIZE):
        sk = rng.randrange(1, BLS_CURVE_ORDER)
        pks.append(sk_to_pk(sk))
    period = C.compute_sync_committee_period_at_slot(SIGNATURE_SLOT)
    return {period: pks}


def main():
    committees = rebuild_committees()
    files = sorted(glob.glob(os.path.join(VECTORS_DIR, "*.json")))
    passed = 0
    total = len(files)
    for path in files:
        with open(path) as f:
            v = json.load(f)
        env = envelope_from_json(v["envelope"])
        anchor = anchor_from_json(v["anchor"])
        cfg = VerifierConfig(
            chain_id=1, genesis_validators_root=C.GENESIS_VALIDATORS_ROOT,
            committees=committees, head_slot=HEAD_SLOT,
            max_staleness_slots=MAX_STALENESS)
        res = verify(env, anchor, cfg)
        actual = res[0] if isinstance(res, tuple) else res
        expected = v["expected"]["result"]
        ok = (actual == expected)
        name = os.path.basename(path)
        print(f"  [{'PASS' if ok else 'FAIL'}] {name:36s} expected={expected:14s} actual={actual}")
        if ok:
            passed += 1
        else:
            print(f"        full result: {res}")
    print(f"\n{passed}/{total} passed")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
