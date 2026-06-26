# Changelog

All notable changes to the Attested-Read Envelope spec. Status remains `raw`/experimental throughout.

## v0.5.0-experimental — 2026-06-26
Upgraded the reference suite from MINIMAL-preset fixtures to **mainnet fidelity using REAL mainnet data**
(route 1, the gold standard). This discharges the three v0.4 caveats that blocked `draft`.
- **REAL hexary Merkle-Patricia verifier** (`reference/are_mpt.py`). Replaces the v0.4 single-account *collapsed*
  trie with a genuine EIP-1186 walk over branch (17-item) / extension (2-item, even-odd hex-prefix) / leaf nodes,
  dereferencing each child by its keccak hash and handling inlined nodes. Verifies a **real mainnet `eth_getProof`**
  for WETH (`0xC02a…Cc2`): a 9-node account proof + 7-node storage-slot-0 proof against the finalized EL state
  root. Exclusion verifies a genuine empty-branch-slot / diverging terminus; truncated/inconsistent proofs are
  rejected. The "simplified MPT" code path is **gone** — MINIMAL fixtures now use a real 2-leaf hexary trie and the
  same walker.
- **FULL 17-field Deneb+ `ExecutionPayloadHeader`** (`reference/are_ssz.py`). All fields (`logs_bloom` as
  `ByteVector[256]`, `extra_data` as `ByteList[32]`, `base_fee_per_gas` as `uint256`, blob fields, …) merkleized
  with real SHA-256; `hash_tree_root` matches a **real beacon `body_root`** via `execution_branch` @ gindex 25.
- **MAINNET preset (`SYNC_COMMITTEE_SIZE = 512`) + real BLS aggregate.** New `accept_mainnet_real.json`
  (`reference/are_real_vectors.py`) verifies a real aggregate over **510/512** real period-1787 committee pubkeys,
  real Fulu `fork_version 0x06000000`, real `genesis_validators_root`, real `finality_branch` @ gindex 169
  (Electra+/Fulu). Provenance: beacon `finality_update` (attested slot 14640721, finalized 14640640, sig slot
  14640722) + `bootstrap` + execution `eth_getProof` at **exec block 25404693**, EL state root
  `0xf6c792621f2a4df8b83abcaf1c72aff30c571fcfb14533ebefd5327b2b53f2a1`. Raw source bytes preserved under
  `vectors/real-data/`. Recorded intermediates: `signing_root = 0x000fd44e…51af0`, `bound_state_root =
  0xf6c79262…53f2a1`.
- **Fork support extended to Fulu** (the real data's fork; shares Electra's SSZ layout). The verifier now selects
  `FINALIZED_ROOT_GINDEX` by the attested header's fork (105 pre-Electra, 169 Electra+).
- **`run_vectors.py` now covers both presets** — 7/7 passing (1 MAINNET real + 2 MINIMAL accept + 4 MINIMAL
  reject). No fabricated hashes anywhere.
- **Remaining for `draft`:** benchmarks (CPU/RAM, native-vs-WASM, clustered-vs-scattered); accept-vector coverage
  for the deep `historical_summaries` ancestor path and `provider_sig`.

## v0.4.0-experimental — 2026-06-26
Third external multi-agent grading round (2 fresh Claude instances + Codex gpt-5.5) of v0.3. Applies the
converged fix set and ships the long-open reference implementation.
- **Fork-version off-by-one fixed.** The signing-domain `fork_version` is now selected by
  `epoch_of(max(signature_slot, 1) − 1)` (matching consensus-specs `fork_version_slot`), not the signature
  slot's own epoch — the old form breaks the domain at a fork-activation boundary.
- **Explicit `signature_slot` field** added to `ConsensusAnchor` as a carried datum (`MUST > attested_header.slot`;
  `== attested+1` only when that slot is not skipped). The committee period is selected by the signature slot;
  `attested+1` is no longer assumed (skipped slots push it later).
- **Near-ancestor `state.block_roots` path** added to `ancestor_proof` (`d ≤ SLOTS_PER_HISTORICAL_ROOT = 8192`),
  alongside the existing deep `historical_summaries` path; both rooted at `finalized_header.state_root`, with the
  block-root leaf-identity note.
- **Concrete Electra gindices** printed (Appendix B): `FINALIZED_ROOT` 105 Deneb / 169 Electra; committee 54/55
  Deneb / 86/87 Electra; `EXECUTION_PAYLOAD` 25; scope narrowed to Deneb + Electra (dropped the "nothing
  unprinted" overclaim).
- **`proof_format` MUST be `{0,0,0}`** with a normative reject for any other combination (carried from v0.3, now
  enforced by the reference verifier).
- **SHIPPED seeded reference implementation + 6 passing vectors** (`reference/`, `vectors/`): a Python verifier
  implementing all 10 §Verification steps (real BLS12-381 / Keccak-256+RLP / SSZ `hash_tree_root`, real mainnet
  `genesis_validators_root`), `random.seed(42)` over committee key generation for byte-identical regeneration,
  and 2 accept + 4 reject vectors (`run_vectors.py` → 6/6). The §Implementation Notes intermediates
  (`signing_root`, `bound_state_root`) are the generator's deterministic output. Documented simplifications:
  MINIMAL-32 preset, single-account MPT, reduced `ExecutionPayloadHeader`, synthetic-but-real-hashed Merkle
  siblings. Mainnet-512 vectors / full-MPT / benchmarks remain for `draft`.

## v0.3.0-experimental — 2026-06-26
External multi-agent grading (2 fresh Claude instances + Codex gpt-5.5) of v0.2 unanimously gated FAIL and
converged on a fixable defect set; this revision applies it.
- **execution_header + execution_branch** added to `ConsensusAnchor`: `state_root`, `block_number`, and
  `timestamp` are now verified SSZ leaves. (v0.2 asserted `execution_block_number(read_block_header)` with no
  backing field — flagged by two graders.)
- **ancestor_proof re-rooted at `finalized_header.state_root`** via `historical_summaries` (v0.2 rooted it at
  `hash_tree_root(finalized_header)` — a hard crypto break: a conforming FINALIZED verifier would reject all
  valid envelopes).
- **Sync-committee handoff/domain rewritten via `signature_slot = attested_header.slot + 1`**; committee period
  and `fork_version` both selected by the signature slot (fixes the period/fork-boundary case).
- **Pinned the mainnet fork-version schedule and SSZ generalized indices** (new Appendix B).
- Dropped a non-normative "MUST read this section".
- Open: concrete test vectors (D9), the one remaining gating gap, pending the reference implementation.

## v0.2.0-experimental — 2026-06-26
Independent multi-agent grading (3 reviewers) caught real defects in v0.1.0; this revision fixes them.
- **Reconciled the Verification Algorithm with the SSZ structs (gating D10 fix).** v0.1 step 7 referenced a
  nonexistent `block_number_header` and step 8 referenced nonexistent combined `*_or_*` fields. Added
  `read_block_header` to `ConsensusAnchor`; rewrote the finality and inclusion/exclusion paths to use only
  fields that exist, with explicit roots.
- **Made `ConsensusAnchor` a fixed-shape container (D8).** Added a `has_finality` flag; finality fields take
  canonical zero/empty values when absent, so `hash_tree_root(ConsensusAnchor)` is byte-canonical.
- **Pinned the signing domain (D4/D8).** Printed mainnet `genesis_validators_root` and the `fork_version`
  selection rule so `signing_root` is reproducible from the document.
- **Fixed `proof_format = {0,0,0}` in v0.1** with a normative reject rule for any other combination.
- Open: concrete test vectors (D9) pending the reference implementation.

## v0.1.0-experimental — 2026-06-26
- Initial raw draft: envelope structure, sync-committee anchor, verification algorithm, freshness contract,
  residual-trust model, prior-art positioning (Pureth/Colibri/Helios/Kevlar).
