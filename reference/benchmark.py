"""
ARE reference benchmark harness (v0.6).

Measures the cost of the cryptographic operations in §Verification Algorithm and
reports the CLUSTERED vs SCATTERED regimes. Prints a Markdown table with the
environment stated.

Components measured (native CPython, py_ecc pure-Python BLS):
  (a) BLS FastAggregateVerify over a real/realistic 512-pubkey committee
  (b) hexary MPT account+storage proof verify (the real mainnet WETH proof)
  (c) SSZ hash_tree_root of the anchor
  (d) full end-to-end envelope verify
  (e) CLUSTERED  per-read cost: the BLS anchor verified ONCE, then N reads reuse it
      (only the per-read MPT + bookkeeping cost is charged per read)
  (f) SCATTERED per-read cost: one fresh BLS aggregate verify per distinct block

NOTE ON WASM: these numbers are NATIVE CPython with the pure-Python py_ecc BLS
backend. A production verifier (e.g. Helios in Rust/WASM with blst) is far faster
for the BLS step; WASM/native-blst figures are FUTURE work and are NOT measured
here. The dominant cost below (BLS over 512 keys in pure Python) is therefore an
UPPER BOUND, not representative of a production verifier.
"""

import json
import os
import platform
import statistics
import sys
import time

import are_constants as C
from are_codec import envelope_from_json, anchor_from_json
from are_bls import sk_to_pk, fast_aggregate_verify
from are_mpt import verify_account_inclusion, verify_storage_inclusion
from are_verify import verify, anchor_hash_tree_root, VerifierConfig

VECTORS_DIR = os.path.join(os.path.dirname(__file__), "..", "vectors")
RD = os.path.join(VECTORS_DIR, "real-data")


def _time(fn, reps):
    samples = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - t0)
    return statistics.median(samples), min(samples)


def _env_block():
    try:
        import multiprocessing
        cpus = multiprocessing.cpu_count()
    except Exception:
        cpus = "?"
    # RAM (best effort, macOS / Linux)
    ram = "?"
    try:
        if sys.platform == "darwin":
            import subprocess
            b = int(subprocess.check_output(["sysctl", "-n", "hw.memsize"]).strip())
            ram = f"{b / (1024**3):.0f} GB"
        else:
            with open("/proc/meminfo") as f:
                kb = int(f.readline().split()[1])
                ram = f"{kb / (1024**2):.0f} GB"
    except Exception:
        pass
    cpu_model = platform.processor() or platform.machine()
    try:
        if sys.platform == "darwin":
            import subprocess
            cpu_model = subprocess.check_output(
                ["sysctl", "-n", "machdep.cpu.brand_string"]).decode().strip()
    except Exception:
        pass
    return {
        "cpu": cpu_model, "logical_cpus": cpus, "ram": ram,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "bls_backend": "py_ecc (pure-Python BLS12-381)",
        "execution": "native CPython (WASM not measured — see note)",
    }


def main():
    C.select_preset("MAINNET")
    env_info = _env_block()

    # ---- load the REAL mainnet vector (real 512 committee, real MPT) ----
    mv = json.load(open(os.path.join(VECTORS_DIR, "accept_mainnet_real.json")))
    envelope = envelope_from_json(mv["envelope"])
    anchor = anchor_from_json(mv["anchor"])
    bs = json.load(open(os.path.join(RD, "bootstrap_committee.json")))
    committee = [bytes.fromhex(p[2:]) for p in bs["current_sync_committee"]["pubkeys"]]
    period = C.compute_sync_committee_period_at_slot(anchor.signature_slot)
    committees = {period: committee}

    def make_cfg():
        return VerifierConfig(
            chain_id=1, genesis_validators_root=C.GENESIS_VALIDATORS_ROOT,
            committees=committees, head_slot=anchor.attested_header.slot + 8,
            max_staleness_slots=64)

    # signing root + participating pubkeys for the isolated BLS measurement
    from are_verify import compute_domain, compute_signing_root
    participating = [committee[i] for i, b in enumerate(anchor.sync_committee_bits) if b]
    fork_version = C.fork_version_at_epoch(
        C.compute_epoch_at_slot(max(anchor.signature_slot, 1) - 1))
    domain = compute_domain(C.DOMAIN_SYNC_COMMITTEE, fork_version, C.GENESIS_VALIDATORS_ROOT)
    signing_root = compute_signing_root(anchor.attested_header, domain)
    sig = anchor.sync_committee_signature

    # the real WETH account + storage read
    r = envelope.reads[0]

    results = {}

    # (a) BLS FastAggregateVerify over the real 512 committee (510 participants)
    n_bls_reps = 3
    med, best = _time(
        lambda: fast_aggregate_verify(participating, signing_root, sig), n_bls_reps)
    results["bls_512"] = (med, best, len(participating))

    # (b) hexary MPT account + storage verify (real mainnet WETH proof)
    def mpt():
        A = verify_account_inclusion(r.address, r.account_proof, anchor.execution_header.state_root)
        verify_storage_inclusion(r.slot, r.storage_proof, A["storageRoot"])
    med, best = _time(mpt, 200)
    results["mpt"] = (med, best)

    # (c) SSZ hash_tree_root of the anchor
    med, best = _time(lambda: anchor_hash_tree_root(anchor), 200)
    results["anchor_htr"] = (med, best)

    # (d) full end-to-end envelope verify (re-verifies BLS each call)
    med, best = _time(lambda: verify(envelope, anchor, make_cfg()), n_bls_reps)
    results["e2e"] = (med, best)

    # (e/f) CLUSTERED vs SCATTERED per-read cost.
    # CLUSTERED: anchor (BLS+branches) verified once, then per read only the MPT +
    #            step-8/9 work. Charge = MPT verify per read.
    # SCATTERED: every read at a DISTINCT block -> one full BLS aggregate verify
    #            per read. Charge = BLS verify + MPT verify per read.
    per_read_clustered = results["mpt"][0]
    per_read_scattered = results["bls_512"][0] + results["mpt"][0]
    results["clustered_per_read"] = per_read_clustered
    results["scattered_per_read"] = per_read_scattered

    # ---- render ----
    def ms(x):
        return f"{x * 1000:.2f} ms"

    print("## Environment")
    for k, v in env_info.items():
        print(f"- **{k}**: {v}")
    print()
    print("## Measured (median of repeated runs)")
    print()
    print("| Operation | Median | Notes |")
    print("|---|---|---|")
    print(f"| (a) BLS FastAggregateVerify, 512-committee | {ms(results['bls_512'][0])} | "
          f"real mainnet aggregate, {results['bls_512'][2]}/512 participants, py_ecc pure-Python |")
    print(f"| (b) hexary MPT account+storage verify | {ms(results['mpt'][0])} | "
          f"real WETH `eth_getProof` (9 account + 7 storage nodes) |")
    print(f"| (c) SSZ hash_tree_root(anchor) | {ms(results['anchor_htr'][0])} | "
          f"full ConsensusAnchor incl. 17-field exec header |")
    print(f"| (d) full end-to-end envelope verify | {ms(results['e2e'][0])} | "
          f"all 10 steps; dominated by (a) |")
    print()
    print("## Clustered vs scattered (per-read amortized cost)")
    print()
    print("| Regime | Per-read cost | Meaning |")
    print("|---|---|---|")
    print(f"| **Clustered** (anchor reused) | {ms(results['clustered_per_read'])} | "
          f"BLS anchor verified once; each additional read at the same block pays only MPT |")
    print(f"| **Scattered** (distinct blocks) | {ms(results['scattered_per_read'])} | "
          f"one BLS aggregate verify per distinct block + its MPT |")
    speedup = results['scattered_per_read'] / results['clustered_per_read']
    print()
    print(f"Clustered batching is ~**{speedup:.0f}x** cheaper per read than scattered "
          f"(the BLS verify, the dominant cost, is amortized across all reads sharing one anchor).")
    print()
    print("> NATIVE py_ecc pure-Python BLS is the dominant cost and an UPPER BOUND; a "
          "production verifier using blst (native/WASM) is far faster. WASM figures are "
          "future work, not measured here.")

    # also emit a machine-readable JSON for the README/spec table generator
    out = {
        "environment": env_info,
        "results_ms": {
            "bls_512": results["bls_512"][0] * 1000,
            "mpt": results["mpt"][0] * 1000,
            "anchor_htr": results["anchor_htr"][0] * 1000,
            "e2e": results["e2e"][0] * 1000,
            "clustered_per_read": results["clustered_per_read"] * 1000,
            "scattered_per_read": results["scattered_per_read"] * 1000,
            "clustered_speedup": speedup,
        },
        "participants": results["bls_512"][2],
    }
    with open(os.path.join(os.path.dirname(__file__), "benchmark_results.json"), "w") as f:
        json.dump(out, f, indent=2)
    print("\n(wrote benchmark_results.json)")


if __name__ == "__main__":
    main()
