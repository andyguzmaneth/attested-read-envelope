# Changelog

All notable changes to the Attested-Read Envelope spec. Status remains `raw`/experimental throughout.

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
