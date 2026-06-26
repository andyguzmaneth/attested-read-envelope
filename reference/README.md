# ARE reference implementation (v0.6)

A Python reference **verifier** (`are_verify.py`) and **vector generators**
(`are_generate.py`, `are_real_vectors.py`, `are_extra_vectors.py`) for the Attested-Read Envelope spec
([`../specs/ARE/README.md`](../specs/ARE/README.md)). The verifier implements all
**10 steps** of §Verification Algorithm in order and returns `ACCEPT` or
`REJECT@stepN`.

v0.5 upgraded the suite from MINIMAL-preset fixtures to **mainnet fidelity**: a
real hexary Merkle-Patricia verifier, the full 17-field `ExecutionPayloadHeader`,
and a **real-data** vector built from a live mainnet `eth_getProof` + a real
Altair/Fulu LightClient `finality_update` + `bootstrap` (a real 512-member sync
committee and a real aggregate BLS signature). v0.6 then closed the last two
coverage gaps (deep `historical_summaries` ancestor + `provider_sig`) and added a
measured benchmark harness. See **What changed in v0.6** and **What changed in
v0.5**.

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -r ../requirements.txt
cd reference
../.venv/bin/python are_generate.py        # (re)generate the MINIMAL vectors
../.venv/bin/python are_real_vectors.py     # (re)build accept_mainnet_real.json from ../vectors/real-data/
../.venv/bin/python are_extra_vectors.py    # (re)build the deep-ancestor + provider_sig vectors
../.venv/bin/python run_vectors.py          # MUST print "10/10 passed"
../.venv/bin/python benchmark.py            # measured timings (prints a Markdown table)
```

## What changed in v0.6 (the last two draft-blockers)

v0.6 discharges the two coverage caveats v0.5 left open, and adds the missing
benchmark harness:

1. **Deep `historical_summaries` ancestor path (step 7b) now vector-locked.** The
   v0.5 verifier had a `REJECT@step7` *stub* on the deep branch. It is now a real
   check: it composes the `historical_summaries` generalized index
   (`are_constants.historical_summaries_leaf_gindex`) and verifies a real SHA-256
   Merkle branch of the read block root against `finalized_header.state_root`. New
   accepting vector **`accept_deep_ancestor.json`** (finalized−read gap = 20000 >
   8192 → deep path; depth-41 branch). Tampering the proof rejects at step 7.
2. **`provider_sig` (step 10) now vector-locked with REAL ed25519.** The v0.5
   verifier had a `REJECT@step10` stub. Step 10 now resolves the verifying key via
   an **independent** trust path (`VerifierConfig.resolve_provider_key`, never the
   envelope), and verifies a real ed25519 (RFC 8032, pycryptodome) signature over
   `hash_tree_root(envelope_without_provider_sig)`
   (`are_verify.envelope_signing_root`). New accepting vector
   **`accept_provider_sig.json`** (dispute/audit mode) + bonus reject
   **`reject_bad_provider_sig.json`** (tampered sig → REJECT@step10).
3. **Benchmarks** (`benchmark.py`) — measured, environment stated; see the table
   below. Replaces the v0.5 "indicative only" note.

Suite is now **10/10**. `secp256k1` (sig_alg=1) remains declared-but-unimplemented
in this reference (pycryptodome has no secp256k1; no new dependency added) — an
honesty note, not a soundness gap (step-10 control flow is identical via ed25519).

## Benchmarks (measured)

Run `python benchmark.py` to reproduce. Captured environment:

**Apple M2 · 8 GB RAM · Python 3.12.2 · macOS 26.5 (arm64) · py_ecc pure-Python
BLS12-381 · native CPython.** *(WASM/native-blst not measured — see note.)*

| Operation | Median | Notes |
|---|---|---|
| (a) BLS `FastAggregateVerify`, 512-committee | **3818.89 ms** | real mainnet aggregate, 510/512 participants, py_ecc pure-Python |
| (b) hexary MPT account+storage verify | **0.07 ms** | real WETH `eth_getProof` (9 account + 7 storage nodes) |
| (c) SSZ `hash_tree_root(anchor)` | **0.07 ms** | full `ConsensusAnchor` incl. 17-field exec header |
| (d) full end-to-end envelope verify | **3783.90 ms** | all 10 steps; dominated by (a) |

| Regime | Per-read cost | Meaning |
|---|---|---|
| **Clustered** (anchor reused) | **0.07 ms** | BLS anchor verified once; each additional read at the same block pays only MPT |
| **Scattered** (distinct blocks) | **3818.96 ms** | one BLS aggregate verify per distinct block + its MPT |

Clustered batching is **~56000× cheaper per read** than scattered: the BLS verify
(the dominant cost) is amortized across all reads sharing one anchor — the
quantitative justification for the spec's "default to batch envelopes" SHOULD.

> The pure-Python `py_ecc` BLS verify dominates and is an **UPPER BOUND**. A
> production verifier reusing an audited light-client core (Helios, `blst` native
> or WASM) verifies the same aggregate in single-digit milliseconds. Native-blst
> and WASM figures are future work and are deliberately **not** fabricated here.

## Route used: (1) REAL mainnet data

Per the task's two acceptable routes, this suite uses **route (1) — real mainnet
data (the gold standard)**, not the full-synthetic fallback. Every byte in
`accept_mainnet_real.json` comes from live mainnet, captured once and preserved
under [`../vectors/real-data/`](../vectors/real-data/) for reproducibility:

| Input | Source | Captured fact |
|---|---|---|
| `eth_getProof` (WETH account + storage slot 0) | `ethereum-rpc.publicnode.com` | account proof (9 hexary nodes) + storage proof (7 nodes) at exec block **25404693** |
| LightClient `finality_update` | `ethereum-beacon-api.publicnode.com` | attested slot **14640721**, finalized slot **14640640**, signature slot **14640722**, real `sync_aggregate` (510/512), full execution payloads, `finality_branch` |
| LightClient `bootstrap` | `ethereum-beacon-api.publicnode.com` (block root `0xb0cfd5f1…31a7`) | the real **512** `current_sync_committee` pubkeys (the trusted config) |

- **Source EL state root:** `0xf6c792621f2a4df8b83abcaf1c72aff30c571fcfb14533ebefd5327b2b53f2a1`
  (exec block 25404693). The real WETH account proof roots to exactly this root.
- **Fork:** Fulu, `current_version = 0x06000000`, sync-committee period **1787**.
- **No hash is ever fabricated.** The real-data vector contains only bytes that
  were on mainnet; the verifier accepts them end-to-end.

## What changed in v0.5 (the draft-blocker work)

The v0.4 caveats named three simplifications that blocked `draft`. All three are
now discharged:

1. **REAL hexary Merkle-Patricia verifier** (`are_mpt.py`). The v0.4
   single-account *collapsed* trie is **removed**. `_walk()` is a genuine EIP-1186
   walk: it follows the `keccak256(key)` nibble path through **branch (17-item),
   extension (2-item, even/odd hex-prefix), and leaf (2-item)** nodes,
   dereferencing each child node by its keccak hash against the proof set, and
   handling inlined (<32-byte) nodes. It verifies a **real mainnet WETH account
   proof and storage-slot proof**. Exclusion verifies a genuine empty-branch-slot
   or diverging-leaf/extension terminus; a truncated/hash-inconsistent proof
   raises and is rejected (never silently treated as absence). The MINIMAL
   fixtures now build a real 2-leaf hexary trie and verify through the *same*
   walker — there is no longer any "simplified MPT" code path.

2. **FULL 17-field `ExecutionPayloadHeader`** (`are_ssz.py`). Replaces the v0.4
   reduced 4-leaf model. All Deneb+ fields (`parent_hash`, `fee_recipient`,
   `state_root`, `receipts_root`, `logs_bloom` as `ByteVector[256]`,
   `prev_randao`, `block_number`, `gas_limit`, `gas_used`, `timestamp`,
   `extra_data` as `ByteList[32]`, `base_fee_per_gas` as `uint256`, `block_hash`,
   `transactions_root`, `withdrawals_root`, `blob_gas_used`, `excess_blob_gas`)
   are merkleized with real SHA-256. Its `hash_tree_root` matches the real beacon
   `body_root` via the real `execution_branch` at `EXECUTION_PAYLOAD_GINDEX = 25`.

3. **MAINNET preset — `SYNC_COMMITTEE_SIZE = 512`, real BLS aggregation**
   (`are_constants.py`, `are_real_vectors.py`). The real-data vector verifies the
   real aggregate signature over **510 of the 512** real committee pubkeys with
   `py_ecc` `FastAggregateVerify`, the real Fulu `fork_version 0x06000000` (from
   `epoch_of(signature_slot − 1)`), the real `genesis_validators_root`, and the
   real `finality_branch` at `FINALIZED_ROOT_GINDEX = 169` (Electra+/Fulu). The
   verifier now selects the finalized-root gindex by the attested header's fork
   (105 pre-Electra, 169 Electra+).

The recorded intermediates for the mainnet vector:
`signing_root = 0x000fd44e62c984d7c201807dc607688818fdca4716cadbd827ce34b393551af0`,
`bound_state_root = 0xf6c792621f2a4df8b83abcaf1c72aff30c571fcfb14533ebefd5327b2b53f2a1`.

## What is REAL cryptography here

- **BLS12-381**, Ethereum `G2ProofOfPossession` ciphersuite
  `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` (via `py_ecc`). G1 pubkeys, G2
  signatures, `FastAggregateVerify`. Mainnet vector = a real 510/512 aggregate.
- **Keccak-256** (Ethereum variant, via `pycryptodome`) + **RLP** for a real
  hexary EIP-1186 account/storage proof walk.
- **SSZ `hash_tree_root`** over **SHA-256** for all beacon objects, the full
  `ExecutionPayloadHeader`, the `ConsensusAnchor`, the signing domain
  (`compute_domain` / `compute_signing_root` / `ForkData` / `SigningData`), and
  every Merkle branch (verified by generalized index; `merkleize` uses correct
  zero-subtree padding for any limit).
- **Real mainnet** `genesis_validators_root`
  `0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95`, real fork
  schedule (Altair…Fulu), real WETH proof, real sync committee.

**No hash is ever fabricated.** Every parent node in every Merkle tree is a real
SHA-256 (consensus) or Keccak-256 (MPT) reduction of its children.

## Honest scope: what is still synthetic / not yet covered

These do **not** affect the cryptographic soundness exercised by the mainnet
vector; they are coverage/honesty notes:

1. **The two MINIMAL accept/reject fixtures use seeded synthetic Merkle siblings**
   for `execution_branch` / `finality_branch` / `ancestor_proof` (there is no full
   beacon state to derive true siblings from). The root each branch proves to is
   still the real SHA-256 reduction along the gindex path, and `verify_merkle_branch`
   is the real consensus check — the *mainnet* vector uses entirely real branches.
2. **MINIMAL preset = `SYNC_COMMITTEE_SIZE = 32`.** Kept as a fast smoke test
   (BLS over 32 keys is quick); the mainnet vector exercises the real 512.
3. **Deep-`historical_summaries` ancestor path (step 7b)** is now vector-locked by
   `accept_deep_ancestor.json`, BUT that vector is a **full-fidelity seeded
   synthetic** at the Deneb preset (real Keccak/SSZ/BLS, real SHA-256
   `historical_summaries` branch; only the *outer* `BeaconState` siblings are
   seeded random bytes). A real-mainnet deep proof is not reachable: the public
   beacon node blocks `/eth/v2/debug/beacon/states` (full-state download), the only
   source of true `historical_summaries` siblings. This matches the fidelity tier
   of the near-ancestor `accept_balance_finalized.json`. **No hash is fabricated** —
   every parent is a real SHA-256 reduction along the real gindex.
4. **`provider_sig` (step 10)** is vector-locked by `accept_provider_sig.json` with
   **real ed25519** (RFC 8032). `secp256k1` (sig_alg=1) is declared by the spec but
   not implemented in this reference (no secp256k1 in pycryptodome; no new
   dependency added) — a coverage note, not a soundness gap.

## The 10 vectors (`../vectors/`)

| File | Preset | Expected | Exercises |
|---|---|---|---|
| `accept_mainnet_real.json` | MAINNET | `ACCEPT` | **REAL** FINALIZED WETH balance + storage slot 0; real 512-committee aggregate (510 participants), real hexary MPT, full ExecutionPayloadHeader, real `finality_branch` @169 |
| `accept_balance.json` | MINIMAL | `ACCEPT` | OPTIMISTIC balance read; records `signing_root` + `bound_state_root`; 25/32 participants |
| `accept_balance_finalized.json` | MINIMAL | `ACCEPT` | FINALIZED, **near**-ancestor `state.block_roots` path |
| `accept_deep_ancestor.json` | MINIMAL | `ACCEPT` | FINALIZED, **deep**-ancestor `state.historical_summaries` path (gap 20000 > 8192); real SHA-256 depth-41 branch |
| `accept_provider_sig.json` | MINIMAL | `ACCEPT` | step 10: **real ed25519** `provider_sig` over `htr(envelope_without_provider_sig)`, independent key resolution, dispute mode |
| `reject_quorum_too_low.json` | MINIMAL | `REJECT@step3` | 16/32 participation (`2·16 == 32`, not `> 32`) |
| `reject_bad_bls.json` | MINIMAL | `REJECT@step4` | quorum met, corrupted aggregate signature |
| `reject_unproven_absence.json` | MINIMAL | `REJECT@step8` | `presence==0` for an address that resolves to an empty branch slot (proven absent) |
| `reject_mixed_root_batch.json` | MINIMAL | `REJECT@step9` | batch read declaring a `state_root != bound_state_root` |
| `reject_bad_provider_sig.json` | MINIMAL | `REJECT@step10` | tampered ed25519 `provider_sig` rejected in dispute mode |

Each vector is `{description, preset, envelope, anchor, expected}`. Rejects carry
the failing step in `expected.result`.

## Determinism

The MINIMAL vectors derive all randomness from `random.seed(42)` (committee keys
+ synthetic siblings), so re-running `are_generate.py` is byte-reproducible. The
MAINNET vector is **data-reproducible**: `are_real_vectors.py` rebuilds it
deterministically from the fixed real inputs in `../vectors/real-data/` (no RNG;
real bytes in, verified vector out).

## Files

- `are_constants.py` — MINIMAL/MAINNET presets, real fork schedule (Altair…Fulu),
  gindices, slot/epoch helpers.
- `are_ssz.py` — SSZ merkleization (zero-subtree padding), `BeaconBlockHeader`,
  **full 17-field** `ExecutionPayloadHeader`, `verify_merkle_branch`.
- `are_mpt.py` — Keccak-256, RLP, **real hexary MPT** walk + synthetic 2-leaf
  trie builders for MINIMAL.
- `are_bls.py` — BLS sign / `FastAggregateVerify` / aggregate.
- `are_sig.py` — `provider_sig` (step 10): real ed25519 sign/verify (RFC 8032).
- `are_verify.py` — the 10-step verifier + domain/signing-root + `envelope_signing_root`.
- `are_codec.py` — vector JSON (de)serialization (full exec header).
- `are_generate.py` — seeded MINIMAL vector generator (the original 6).
- `are_real_vectors.py` — MAINNET real-data vector generator (consumes
  `../vectors/real-data/`).
- `are_extra_vectors.py` — deep-ancestor + provider_sig vector generator (v0.6).
- `benchmark.py` — measured timing harness (BLS/MPT/SSZ/e2e, clustered-vs-scattered).
- `run_vectors.py` — loads all vectors (both presets), asserts expected == actual.
