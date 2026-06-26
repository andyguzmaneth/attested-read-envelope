# Changelog

All notable changes to the Attested-Read Envelope spec. Status remains `raw`/experimental throughout.

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
