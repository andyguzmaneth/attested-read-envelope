# ARE reference implementation (v0.4, MINIMAL preset)

A Python reference **verifier** (`are_verify.py`) and **vector generator**
(`are_generate.py`) for the Attested-Read Envelope spec
([`../specs/ARE/README.md`](../specs/ARE/README.md)). The verifier implements all
**10 steps** of §Verification Algorithm in order and returns `ACCEPT` or
`REJECT@stepN`.

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -r ../requirements.txt
cd reference
../.venv/bin/python are_generate.py     # (re)generate ../vectors/*.json
../.venv/bin/python run_vectors.py      # MUST print "6/6 passed"
```

## Determinism

All randomness comes from a **single fixed seed**: `random.seed(42)` (the seed is
the constant `SEED = 42` in `are_generate.py` and `run_vectors.py`). It seeds:

- **committee key generation** — the 32 BLS secret keys are drawn from the seeded
  RNG (reduced mod the BLS12-381 subgroup order), and
- **synthetic Merkle siblings** for the `execution_branch`, `finality_branch`, and
  `ancestor_proof`.

BLS `Sign` is deterministic given the key, and SHA-256/Keccak are deterministic,
so **re-running `are_generate.py` produces byte-identical `vectors/*.json`** (the
build is reproducible; verified by regenerate-and-diff). `run_vectors.py`
rebuilds the same committee pubkeys from the seed (committees are trusted config,
not carried inside a vector).

`signature_slot` is carried as **data** (`attested_header.slot + 1` in the
fixtures) and is *not* recomputed by the verifier; `fork_version` is computed by
the verifier from `epoch_of(max(signature_slot, 1) - 1)`, per v0.4.

## What is REAL cryptography here

- **BLS12-381**, Ethereum `G2ProofOfPossession` ciphersuite
  `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` (via `py_ecc`). G1 pubkeys, G2
  signatures, `FastAggregateVerify`.
- **Keccak-256** (Ethereum variant, via `pycryptodome`) + **RLP** for the
  EIP-1186 account/storage proof nodes.
- **SSZ `hash_tree_root`** over **SHA-256** for all beacon objects, the
  `ConsensusAnchor`, the signing domain (`compute_domain` / `compute_signing_root`
  / `ForkData` / `SigningData`), and every Merkle branch (verified by
  generalized index).
- **Real mainnet** `genesis_validators_root`
  `0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95` and the
  Deneb `fork_version` `0x04000000`.

**No hash is ever fabricated.** Every parent node in every Merkle tree is a real
SHA-256 (consensus) or Keccak-256 (MPT) reduction of its children.

## Honest simplifications (documented, not hidden)

These are the deliberate reductions vs a mainnet-512 production verifier. They
let the verification *logic* be exercised end-to-end while staying small and
deterministic; each is also flagged in the spec's §Implementation Notes caveats.

1. **MINIMAL preset.** `SYNC_COMMITTEE_SIZE = 32` (quorum `2·popcount > 32`), not
   512. A single fork (Deneb) is active for all fixture slots, so
   `fork_version_at_epoch` returns the Deneb version.
2. **Single-account MPT** (`are_mpt.py`). The state/storage trie collapses to a
   single leaf node `RLP([keccak256(key), value])`; `state_root =
   keccak256(RLP(node))`. This is **real Keccak over real RLP** — but it is NOT a
   full hexary trie with branch/extension nodes. Inclusion verifies the node
   hashes to the root and commits the queried key; exclusion verifies a genuine
   divergent-key terminal node (not a truncated path). A full-MPT fixture is
   deferred to `draft`.
3. **Reduced `ExecutionPayloadHeader`** (`are_ssz.py`). Modeled as a 4-leaf SSZ
   container `{state_root, block_number, timestamp, extra_root}` instead of the
   17-field mainnet header. The `execution_branch` is therefore a genuine SSZ
   Merkle proof against a real leaf — just a narrower object. We keep
   `EXECUTION_PAYLOAD_GINDEX = 25` to match the spec's documented value.
4. **Synthetic Merkle siblings.** For `execution_branch`, `finality_branch`, and
   `ancestor_proof`, the *sibling* hashes are seeded-random 32-byte values (there
   is no full beacon state to derive true siblings from), but the **root each
   branch proves to is the real SHA-256 reduction along the gindex path** — so
   the branch genuinely commits to the leaf. `verify_merkle_branch` is the real,
   unmodified consensus check.
5. **Reduced `BeaconState` for the near-ancestor path.** The
   `accept_balance_finalized.json` vector exercises the v0.4 near-ancestor
   `state.block_roots` path. The `block_roots` leaf generalized index is composed
   as `(BLOCK_ROOTS_FIELD_GINDEX << 13) | (slot mod 8192)` against a reduced
   `BeaconState` model; the concrete integer is **locked by that vector**.
6. **Steps 4 (deep-ancestor branch), 10 (provider_sig) not exercised by accepts.**
   The shipped vectors use the near-ancestor path and `sig_alg == 0`. The
   deep-`historical_summaries` branch and provider-signature verification are
   present in the verifier's control flow but not covered by an accepting vector.

## The 6 vectors (`../vectors/`)

| File | Expected | Exercises |
|---|---|---|
| `accept_balance.json` | `ACCEPT` | OPTIMISTIC balance read; records `signing_root` + `bound_state_root`; 25/32 participants |
| `accept_balance_finalized.json` | `ACCEPT` | FINALIZED, near-ancestor `state.block_roots` path |
| `reject_quorum_too_low.json` | `REJECT@step3` | 16/32 participation (`2·16 == 32`, not `> 32`) |
| `reject_bad_bls.json` | `REJECT@step4` | quorum met, corrupted aggregate signature |
| `reject_unproven_absence.json` | `REJECT@step8` | `presence==0` for an address the proof doesn't commit |
| `reject_mixed_root_batch.json` | `REJECT@step9` | batch read declaring a `state_root != bound_state_root` |

Each vector is `{description, preset, envelope, anchor, expected}`. Rejects carry
the failing step in `expected.result`.

## Files

- `are_constants.py` — preset + domain constants, gindices, slot/epoch helpers.
- `are_ssz.py` — SSZ merkleization, `BeaconBlockHeader`, reduced
  `ExecutionPayloadHeader`, `verify_merkle_branch` / `build_merkle_branch`.
- `are_mpt.py` — Keccak-256, RLP, single-account trie inclusion/exclusion.
- `are_bls.py` — BLS sign / `FastAggregateVerify` / aggregate.
- `are_verify.py` — the 10-step verifier + domain/signing-root computation.
- `are_codec.py` — vector JSON (de)serialization.
- `are_generate.py` — seeded vector generator (run to (re)produce vectors).
- `run_vectors.py` — loads all 6 vectors, asserts expected == actual.
