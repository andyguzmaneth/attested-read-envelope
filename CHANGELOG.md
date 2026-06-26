# Changelog

All notable changes to the Attested-Read Envelope spec. Status remains `raw`/experimental throughout.

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
