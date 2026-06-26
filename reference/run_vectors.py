"""
Load every ARE vector (both MINIMAL and MAINNET presets) and assert
expected == actual verifier output. Prints "N/M passed". Exit 1 on any mismatch.

Trusted committees (never carried in a vector):
  - MINIMAL  vectors: the 32 seeded committee pubkeys, rebuilt from SEED.
  - MAINNET  vector:  the real 512 sync-committee pubkeys loaded from
                      ../vectors/real-data/bootstrap_committee.json (the trusted
                      LightClientBootstrap).

Each vector declares its preset in `preset.name`; the runner selects the active
preset (SYNC_COMMITTEE_SIZE / fork schedule) and the right committee per vector.
"""

import glob
import json
import os
import random
import sys

import are_constants as C
from are_codec import envelope_from_json, anchor_from_json
from are_bls import sk_to_pk
from are_verify import verify, VerifierConfig

VECTORS_DIR = os.path.join(os.path.dirname(__file__), "..", "vectors")
RD = os.path.join(VECTORS_DIR, "real-data")
SEED = 42
BLS_CURVE_ORDER = 52435875175126190479447740508185965837690552500527637822603658699938581184513


def minimal_committee(period):
    """Rebuild the 32 seeded MINIMAL committee pubkeys (trusted config)."""
    rng = random.Random(SEED)
    pks = []
    for _ in range(32):
        sk = rng.randrange(1, BLS_CURVE_ORDER)
        pks.append(sk_to_pk(sk))
    return {period: pks}


def mainnet_committee(period):
    """Load the real 512 sync-committee pubkeys from the trusted bootstrap."""
    bs = json.load(open(os.path.join(RD, "bootstrap_committee.json")))
    pks = [bytes.fromhex(p[2:]) for p in bs["current_sync_committee"]["pubkeys"]]
    return {period: pks}


def run_one(v):
    preset = v["preset"]["name"]
    C.select_preset(preset)
    env = envelope_from_json(v["envelope"])
    anchor = anchor_from_json(v["anchor"])
    sig_slot = anchor.signature_slot
    period = C.compute_sync_committee_period_at_slot(sig_slot)

    if preset == "MAINNET":
        committees = mainnet_committee(period)
        head_slot = anchor.attested_header.slot + 8
        max_staleness = 64
    else:
        committees = minimal_committee(period)
        head_slot = 9_000_000
        max_staleness = 64

    cfg = VerifierConfig(
        chain_id=1, genesis_validators_root=C.GENESIS_VALIDATORS_ROOT,
        committees=committees, head_slot=head_slot,
        max_staleness_slots=max_staleness)
    res = verify(env, anchor, cfg)
    return res[0] if isinstance(res, tuple) else res


def main():
    files = sorted(glob.glob(os.path.join(VECTORS_DIR, "*.json")))
    passed = 0
    total = len(files)
    for path in files:
        with open(path) as f:
            v = json.load(f)
        actual = run_one(v)
        expected = v["expected"]["result"]
        ok = (actual == expected)
        name = os.path.basename(path)
        preset = v["preset"]["name"]
        print(f"  [{'PASS' if ok else 'FAIL'}] {name:28s} ({preset:7s}) "
              f"expected={expected:14s} actual={actual}")
        if ok:
            passed += 1
        else:
            print(f"        full result mismatch")
    print(f"\n{passed}/{total} passed")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
