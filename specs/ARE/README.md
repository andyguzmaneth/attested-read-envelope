---
date: 2026-06-26
slug: ARE
title: ARE/ATTESTED-READ-ENVELOPE
name: Attested-Read Envelope for Verifiable Ethereum State Reads
status: draft
category: Standards Track
tags: [private-reads, spec, coss, attested-read-envelope, sync-committee, eip-1186, verifiable-reads, correctness]
editor: Andy Guzman <andres.guzmantoledo@ethereum.org>
contributors:
  - Andy Guzman <andres.guzmantoledo@ethereum.org>
---

<!-- COSS note: `slug` is a placeholder identifier; a numeric slug is assigned on submission to the registry.
`status: draft` (promoted from raw at rev 0.8): the design can be demonstrated — a reference verifier + 10
passing conformance vectors (incl. a real-mainnet case) exist. Per 1/COSS, draft is a contract between editors
and implementers; changes are now made in consultation with implementers, not unilaterally. -->

> **Editor's note:** this remains an experimental, unaudited draft published for open discussion. `draft` status
> signals the design is stable enough to implement against, NOT that it is finalized or endorsed by the EF.

<!-- Document revision 0.4 (2026-06-26): from a second external multi-agent grading round (2 fresh Claude
instances + Codex gpt-5.5) of v0.3. Fixed a live fork_version off-by-one (now epoch of max(signature_slot,1)-1,
matching consensus-specs); made signature_slot an explicit carried anchor field (not attested+1, which breaks on
skipped slots); added the near-ancestor state.block_roots path for ancestor_proof (v0.3 only covered deep
history) with the block-root leaf-identity note; printed concrete Electra gindices and scoped v0.1 to Deneb+
Electra, removing the "nothing unprinted" overclaim; SHIPPED concrete test vectors + a Python reference verifier
(reference/, vectors/) — 2 accept + 4 reject, all passing. Mainnet-512 vectors / full-MPT / benchmarks remain
for draft. -->

<!-- Document revision 0.5 (2026-06-26): upgraded the reference suite from MINIMAL-preset fixtures to MAINNET
fidelity using REAL mainnet data (route 1). Discharged the three v0.4 draft-blocker caveats: (a) a REAL hexary
Merkle-Patricia verifier (branch/extension/leaf, hex-prefix path walk) replacing the v0.4 single-account
collapsed trie — verifies a real eth_getProof for WETH (account + storage slot 0) against the finalized EL
state_root; (b) the FULL 17-field Deneb+ ExecutionPayloadHeader, whose hash_tree_root matches a real beacon
body_root via execution_branch @25; (c) a real 512-member sync committee with a real aggregate BLS signature
(510/512), real Fulu fork_version 0x06000000, real finality_branch @169. New accept_mainnet_real.json built from
live beacon-API + execution-RPC bytes (raw inputs preserved under vectors/real-data/). Extended the supported-fork
set to include Fulu (the real data's fork). 7 vectors now pass (1 MAINNET real + 2 MINIMAL accept + 4 MINIMAL
reject). REMAINING for draft: benchmarks (CPU/RAM, native-vs-WASM, clustered-vs-scattered); accept coverage for the
deep-historical_summaries ancestor path and provider_sig. -->

<!-- Document revision 0.6 (2026-06-26): discharged the final two v0.5 draft-blocker caveats. (1) BENCHMARKS:
added reference/benchmark.py and replaced the "indicative only" note with a MEASURED table (environment stated:
Apple M2, 8 GB, Python 3.12.2, py_ecc pure-Python BLS, native; WASM/blst noted as future, not fabricated) — BLS
FastAggregateVerify over the real 512 committee = 3.82 s (upper bound), MPT+storage = 0.07 ms, and clustered vs
scattered per-read (~56000x cheaper clustered). (2) ACCEPT COVERAGE: the v0.5 verifier had STUBS (REJECT@step7 on
the deep ancestor path, REJECT@step10 on provider_sig); both are now real checks locked by accepting vectors —
accept_deep_ancestor.json (FINALIZED, historical_summaries path, gap 20000 > 8192, real SHA-256 depth-41 branch;
full-fidelity seeded synthetic since the public node blocks full-state download) and accept_provider_sig.json
(real ed25519 over hash_tree_root(envelope_without_provider_sig), independent key resolution, dispute mode), plus
reject_bad_provider_sig.json. Suite 7/7 -> 10/10. status: left raw (editor's call). -->

<!-- Document revision 0.7 (2026-06-26): zkspec-rubric review pass. Fixed a D10 cross-section contradiction in
how fork_version is selected for the signing domain: §Cryptographic Primitives and §Interoperability said "the
signature slot's epoch" while §Verification step 4 (correctly) said max(signature_slot,1)−1 — reconciled all
three to step 4. Also corrected §Interoperability's stale "signature_slot = attested+1 rule" to match the struct
(signature_slot is a carried field > attested_header.slot). Pointed Appendix A at the real-mainnet vector for
concrete bytes. No struct or algorithm change. -->

<!-- Document revision 0.8 (2026-06-26): editor promoted status raw → draft. Justification: the design "can be
demonstrated" (1/COSS's bar) — a runnable reference verifier + 10/10 conformance vectors incl. a real-mainnet
case. No technical/struct/algorithm change in this revision; status + framing only. -->

**Protocol scope: v0.1 · Document revision: 0.8 (2026-06-26) · Status: draft.**

# Change Process

This document is governed by the [1/COSS](https://github.com/privacy-ethereum/zkspecs/tree/main/specs/1) (COSS).

# Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).

# Abstract

The Attested-Read Envelope (ARE) is a self-describing, serializable object that carries an Ethereum state
read **together with the cryptographic material that lets any party verify the read offline, against the
consensus, without trusting the server that produced it**. An envelope binds a returned value (e.g. an account
balance or a storage slot) to (a) an EIP-1186 Merkle-Patricia proof against an execution-layer `state_root`, and
(b) an Ethereum beacon-chain Altair sync-committee attestation that anchors that `state_root` to a signed beacon
block header. A verifier holding only a trusted light-client bootstrap can check an envelope with no network
access and no trust in the packager.

ZK is **not** used in this version; the verifiable property is achieved with Merkle proofs and BLS
signature verification. (A future version MAY replace the proof half with a succinct proof; see Known
Limitations.) The envelope's novel contribution over existing verify-and-discard light clients is that it is a
**portable, offline-replayable artifact**: a verifier can persist an envelope and re-verify it months later as
dispute or audit evidence, optionally with a packager signature for non-repudiation.

**In scope (v0.1):** verifiable reads of *static execution-state trie values* on Ethereum L1 — the results of
`eth_getBalance`, `eth_getStorageAt`, `eth_getCode`, and `eth_getTransactionCount` — at a specified block, with
an explicit freshness contract.

**Out of scope (v0.1), each deferred to the proof shape it actually requires:**
- **Computed reads** (`eth_call`, `eth_estimateGas`): their result is the output of EVM execution, not a trie
  value, and has no Merkle proof. Deferred to a future witness-set / re-execution or ZK-EVM proof object.
- **Logs and receipts** (`eth_getLogs`, receipts): anchored to `receiptsRoot`, not `state_root`, and the threat
  is *omission* (completeness), which an inclusion proof cannot defend. Deferred to Pureth (EIP-7745).
- **L2 state:** the L1 sync committee does not attest L2 roots. Deferred to per-rollup anchor variants.
- **Deep-history audit replay** beyond the available committee-provenance window. See §Known Limitations.
- **Mempool / pending / gas-oracle reads** (`pending`, `eth_gasPrice`, `feeHistory`, `txpool_*`): no committed
  `state_root` exists. These are a **permanent non-goal at every version**, not a deferral.

# Relationship to Prior Art

This spec does **not** claim to invent verifiable state reads, a consensus light-client anchor, or a "trustless
packager." Each of those is established prior art. The novel, defensible contribution is **(a) a standardized,
self-describing wire format** for an attested read and **(b) audit-log / dispute non-repudiation semantics** for
a persisted envelope.

| Prior work | What it already does | What ARE adds |
|---|---|---|
| **EIP-1186 `eth_getProof`** | Returns account + storage Merkle proofs against `state_root`. | ARE embeds an EIP-1186 proof; it does not redefine it. ARE adds the consensus anchor, freshness contract, and persistence semantics around it. |
| **Pureth (EIP-7919, and EIP-7745/7708)** | EF-track meta effort to make RPC responses provable via SSZ-committed objects; explicitly delegates `state_root` trust to a separate light client. | ARE supplies exactly that delegated anchor (the sync-committee attestation) plus audit semantics. ARE SHOULD consume Pureth SSZ proof objects where they exist rather than define parallel ones. |
| **Colibri / C4** (`corpus-core`, prod 2025) | Ships value + Merkle proof + sync-committee attestation in one serialized `EthSyncProof`. | ARE's verification core is mechanically similar; ARE's delta is the standardized interoperable wire schema and the dispute/audit non-repudiation profile, not the cryptography. |
| **Helios, Kevlar** | In-process light clients that verify a read then discard the proof. | ARE makes the proof a **first-class, persistable, transferable artifact** rather than ephemeral verification state. |

This section normatively scopes the contribution: claims of novelty are restricted to the wire format and audit
semantics. It is not an implementation requirement.

# Motivation

Read access is where privacy, integrity, and censorship-resistance first fail. A user or agent that cannot
independently confirm that a returned balance, nonce, code, or storage slot matches canonical Ethereum state is
trusting the RPC endpoint — a spoofable, centralized chokepoint. Existing light clients (Helios, Kevlar) solve
the *live* verification problem but discard the evidence, so a read cannot later be **shown** to a third party.

Four named gaps motivate ARE:

1. **No portable evidence.** "The chain told me X at block N" is unprovable after the fact once the light
   client has discarded its proof. Disputes (an agent acting on a balance, a compliance attestation) need a
   replayable artifact.
2. **No standard wire format.** Colibri, Helios, and ad-hoc `eth_getProof` consumers each shape the bundle
   differently; nothing interoperates.
3. **Implicit, unstated freshness assumptions.** A correctness proof for block N silently invites the reader to
   assume N is the chain head. It is not, and a single artifact cannot prove that it is (see §Security).
4. **Unscoped "verifiable RPC" claims** that conflate trie reads (provable) with computed reads and logs
   (different proof shapes), getting dismissed as naive. ARE scopes itself to where the cryptography is sound.

# Specification

## System Requirements

A conforming implementation MUST provide:

### 1. Envelope data model

A serializable object (the **envelope**) carrying a single read or a batch of reads at one block, defined in
§Envelope Structure.

### 2. Consensus anchor

An Altair sync-committee attestation object (the **anchor**) sufficient to verify that the read's `state_root`
belongs to a beacon block header signed by a sync committee, defined in §Cryptographic Primitives and
§Verification Algorithm.

### 3. Trusted bootstrap

A verifier MUST be initialized with a `LightClientBootstrap` (a trusted, recent finalized beacon block root,
its sync committee, and the branch proving the committee) obtained out-of-band within the weak-subjectivity
period. The bootstrap MUST NOT be sourced from the same untrusted packager that produces envelopes unless the
verifier independently anchors it (e.g. against a checkpoint published by a trusted party). For **offline
replay**, the verifier MUST co-persist the bootstrap (or a finalized checkpoint and committee-provenance chain)
alongside the envelope; see §Audit-Log / Offline Replay.

### 4. Freshness oracle (client-side)

A verifier MUST maintain its own monotonic view of the chain head (its own light-client head, never a packager
field) so it can enforce the freshness contract in §Verification Algorithm step 6.

## Cryptographic Primitives

Every primitive is named with its full parameters. All values that feed a hash or signature pre-image are
pinned here.

- **Execution-state hashing / proof:** Keccak-256 (Ethereum variant, **not** NIST SHA3-256), as used by the
  EIP-1186 Merkle-Patricia Trie. Trie nodes are RLP-encoded. The proof format is exactly EIP-1186
  `accountProof` and `storageProof` (arrays of RLP-encoded MPT nodes).
- **Consensus serialization / hashing:** SSZ with `hash_tree_root` over SHA-256 (per the Ethereum consensus
  specification). All beacon objects (headers, branches, committee) are SSZ.
- **Sync-committee signature:** BLS over the BLS12-381 curve, Ethereum consensus parametrization — public keys
  in G1 (48-byte compressed), signatures in G2 (96-byte compressed), `hash_to_curve` per the consensus spec's
  `BLSSignature` with ciphersuite `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`. The aggregate public key is the
  G1 sum of the participating committee members' keys.
- **Signing domain:** `compute_domain(DOMAIN_SYNC_COMMITTEE = 0x07000000, fork_version, genesis_validators_root)`.
  The `fork_version` and `genesis_validators_root` MUST be taken from the **verifier's own trusted chain
  configuration**, never from envelope bytes (see §Security, domain pinning). For `chain_id = 1` (Ethereum
  mainnet) these are pinned network constants and MUST be:
  - `genesis_validators_root = 0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95`;
  - `fork_version` selected from the mainnet fork schedule by the epoch of the slot **before** the signature
    slot — `fork_version_slot = max(signature_slot, 1) − 1`, matching consensus-specs (see Verification step 4) —
    using the `current_version` of the fork active at that epoch. (Keying off the signature slot's *own* epoch is
    an off-by-one that breaks the domain at a fork-activation boundary.) The mainnet schedule
    (`chain_id = 1`) is pinned here so `signing_root` is reproducible from this document alone:

    | Fork | `current_version` | Activation epoch (mainnet) |
    |---|---|---|
    | Altair | `0x01000000` | 74240 |
    | Bellatrix | `0x02000000` | 144896 |
    | Capella | `0x03000000` | 194048 |
    | Deneb | `0x04000000` | 269568 |
    | Electra | `0x05000000` | 364032 |
    | (later forks) | per consensus-specs `MAINNET` `*_FORK_VERSION` | per `*_FORK_EPOCH` |

    A verifier MUST use the value for `fork_version_slot`'s epoch, not the latest. For other `chain_id`s the
    verifier MUST source the equivalent `*_FORK_VERSION` / `*_FORK_EPOCH` constants from the consensus-specs
    config for that network.
- **Sync committee size:** `SYNC_COMMITTEE_SIZE = 512`. Period length
  `EPOCHS_PER_SYNC_COMMITTEE_PERIOD = 256` (`SLOTS_PER_SYNC_COMMITTEE_PERIOD = 8192`, ≈ 27 hours).
- **Encoding of the envelope itself:** SSZ. This is the canonical wire encoding; every conforming serializer
  MUST produce identical bytes for identical field values. JSON MAY be used for transport display but is NOT
  the canonical form for hashing or `provider_sig`.
- **`provider_sig` (OPTIONAL):** signature by the packager over `hash_tree_root(envelope_without_provider_sig)`.
  Scheme is `secp256k1` ECDSA OR `ed25519`, declared by a `sig_alg` discriminant. The verifying key MUST be
  anchored independently of the envelope (ENS record, `did:` document, or X.509 chain) — never asserted by the
  packager inline.

**Concatenation:** wherever this document writes `||`, it denotes SSZ container composition (for consensus
objects) or EIP-1186 node ordering (for the MPT proof). Ad-hoc byte concatenation is NOT used in any
pre-image; there are therefore no length-prefixing ambiguities to resolve beyond those already fixed by SSZ and
RLP.

## Envelope Structure

The canonical SSZ container. A `batch` envelope binds many reads to **one** anchor and **one** `state_root`.

```text
AttestedReadEnvelope {
    version:           uint8                     # = 1 for v0.1
    chain_id:          uint64                     # self-description; verifier cross-checks its own config
    anchor_type:       uint8                     # = 0 (L1_SYNC_COMMITTEE) in v0.1; reserved for L2 variants
    settlement_layer:  uint64                     # = chain_id in v0.1; distinct for future L2 anchors

    block_number:      uint64
    beacon_slot:       uint64                     # the slot of the anchored beacon header
    timestamp:         uint64                     # execution payload timestamp (unix seconds) — for staleness
    state_root:        Bytes32                    # execution-layer state root claimed for this read

    proof_format:      ProofFormat                # { trie_type, hash_fn, encoding } — see below
    finality_status:   uint8                     # 0 = OPTIMISTIC_HEAD, 1 = FINALIZED

    anchor_ref:        Bytes32                    # hash_tree_root of the ConsensusAnchor (rehydrated separately)
    reads:             List[ReadProof, MAX_READS] # 1..MAX_READS reads, ALL against this state_root

    sig_alg:           uint8                      # 0 = none, 1 = secp256k1, 2 = ed25519
    provider_sig:      Bytes                      # OPTIONAL; empty iff sig_alg == 0
    provider_key_hint: Bytes                      # OPTIONAL; how to resolve the verifying key (e.g. ENS name)
}

ReadProof {
    read_kind:   uint8        # 0=balance, 1=storage, 2=code, 3=nonce
    address:     Bytes20
    slot:        Bytes32       # used iff read_kind == 1 (storage); else zero
    value:       Bytes         # canonical value bytes (see read_kind encoding rules below)
    account_proof: List[Bytes, MAX_NODES]   # EIP-1186 accountProof (RLP MPT nodes)
    storage_proof: List[Bytes, MAX_NODES]   # EIP-1186 storageProof (RLP MPT nodes); empty unless storage
    presence:    uint8         # 0 = present (inclusion), 1 = absent (exclusion / proof-of-absence)
}

ProofFormat {
    trie_type: uint8    # 0 = hexary-MPT (current), 1 = binary-7864 (reserved, future)
    hash_fn:   uint8    # 0 = keccak256, 1 = blake3 (reserved), 2 = poseidon2 (reserved)
    encoding:  uint8    # 0 = RLP, 1 = SSZ (reserved)
}

# ConsensusAnchor is a FIXED-shape SSZ container: every field is always present, so
# hash_tree_root(ConsensusAnchor) is byte-canonical across implementations. When has_finality
# == false, the finality fields take their canonical zero/empty values (see below). Referenced by
# envelope.anchor_ref; NOT inlined per envelope on the wire.
ConsensusAnchor {
    attested_header:    BeaconBlockHeader      # sync-committee-signed header
    signature_slot:     uint64                  # slot of the block that CONTAINS the sync aggregate; MUST be
                                               # > attested_header.slot (== attested_header.slot + 1 only when that
                                               # slot is not skipped). Selects the signing committee period AND fork.
    sync_committee_bits: Bitvector[512]
    sync_committee_signature: Bytes96          # BLS aggregate over the attested_header signing root

    read_block_header:  BeaconBlockHeader      # beacon header of the read block; OPTIMISTIC: MUST equal attested_header
    execution_header:   ExecutionPayloadHeader  # execution payload header of read_block_header; carries the EL
                                               # state_root, block_number, AND timestamp (Capella+ LightClientHeader form)
    execution_branch:   List[Bytes32, MAX_BRANCH]  # proves hash_tree_root(execution_header) == the execution_payload
                                               # leaf of read_block_header.body_root (gindex EXECUTION_PAYLOAD_GINDEX)

    has_finality:       boolean                 # presence flag — keeps the container fixed-shape for canonical hashing
    finalized_header:   BeaconBlockHeader       # zeroed iff has_finality == false
    finality_branch:    List[Bytes32, MAX_BRANCH]  # empty iff has_finality == false; proves hash_tree_root(finalized_header)
                                               # from attested_header.state_root (gindex FINALIZED_ROOT_GINDEX)
    ancestor_proof:     List[Bytes32, MAX_BRANCH]  # empty iff has_finality == false; proves hash_tree_root(read_block_header)
                                               # is reachable from finalized_header.STATE_ROOT via historical_summaries
}
```

Constants for v0.1: `MAX_READS = 256`, `MAX_NODES = 64`, `MAX_BRANCH = 64`. `ExecutionPayloadHeader` and
`BeaconBlockHeader` are the standard consensus-spec SSZ containers (their field layouts are fork-versioned; see
the generalized-index table in §Appendix B).

**`proof_format` is fixed in v0.1.** A conforming v0.1 envelope MUST set
`proof_format = {trie_type: 0, hash_fn: 0, encoding: 0}` (hexary-MPT / Keccak-256 / RLP). A v0.1 verifier MUST
reject any envelope whose `proof_format` is not exactly `{0, 0, 0}`. The non-zero discriminant values are
reserved for future versions (binary trie, alternative hashes, SSZ proofs) and carry no normative meaning in
v0.1.

**`has_finality` MUST equal (`finality_status == FINALIZED`).** When `has_finality == false`, the canonical
zero values are: `finalized_header` = the all-zero `BeaconBlockHeader`, and `finality_branch` = `ancestor_proof`
= the empty list. This fixes `hash_tree_root(ConsensusAnchor)` byte-for-byte in the OPTIMISTIC case.

**`value` encoding by `read_kind` (pin one canonical form):**
- `balance` (0): the account balance as a big-endian byte string with **no leading zero bytes** (`0x` for zero).
- `nonce` (3): big-endian, no leading zero bytes.
- `code` (2): the raw bytecode bytes; `value` MUST hash (Keccak-256) to the account's `codeHash`.
- `storage` (1): the 32-byte slot value, RLP-decoded from the storage-trie leaf (EIP-1186 semantics:
  leading-zero-trimmed big-endian inside the RLP), re-expanded to canonical big-endian no-leading-zero bytes.

## Protocol Flow (packager side)

A packager produces an envelope as follows. The packager is untrusted; these steps describe construction, not a
trust obligation.

1. Resolve the read(s) at a chosen `block_number` against an execution node; obtain each value and its EIP-1186
   `accountProof`/`storageProof` (including exclusion proofs where the account or slot is absent).
2. Obtain, from a beacon node, the `ConsensusAnchor`: the sync-committee-signed `attested_header`, the
   `signature_slot` (the slot whose block carries the aggregate), the
   `sync_committee_bits` + aggregate signature, the `read_block_header` (equal to `attested_header` in OPTIMISTIC
   mode), its `execution_header` (carrying the EL `state_root`, `block_number`, `timestamp`), and the
   `execution_branch` proving `execution_header` against `read_block_header.body_root`.
3. If a FINALIZED envelope is requested, set `has_finality = true` and include: the `finality_branch` proving
   `hash_tree_root(finalized_header)` from `attested_header.state_root`, and the `ancestor_proof` proving
   `hash_tree_root(read_block_header)` is reachable from **`finalized_header.state_root`** via
   `historical_summaries` (empty when `read_block_header == finalized_header`). Otherwise set
   `has_finality = false` and zero those fields.
4. Set `proof_format = {0,0,0}`, `finality_status`, `anchor_type`, `chain_id`, `timestamp`, `beacon_slot`.
5. The packager MAY sign `hash_tree_root` of the envelope (all fields except `provider_sig`) and set
   `sig_alg`, `provider_sig`, `provider_key_hint`.
6. Serialize with SSZ.

# Verification Algorithm

The heart of this spec. A verifier holding a trusted bootstrap and its own head view MUST perform **all** of the
following, in order, and MUST reject the envelope if any step fails. This replaces a ZK circuit's
constraint list; each numbered item is a soundness constraint.

### Verifier inputs

**Trusted (verifier-held, never from the envelope):**
- `genesis_validators_root`, the active `fork_version` schedule (chain config).
- The sync committee(s) for the relevant period(s), reachable from the trusted `LightClientBootstrap`.
- The verifier's own monotonic chain-head slot `head_slot` and a configured `MAX_STALENESS_SLOTS`.

**Untrusted (from the envelope / anchor):** all envelope and `ConsensusAnchor` fields.

### Operations (the verifier MUST enforce, in order)

1. **Self-description cross-check.** `assert(envelope.chain_id == verifier.chain_id)` and
   `assert(envelope.anchor_type == 0)` and `assert(envelope.version == 1)`. Reject unknown `anchor_type`/`version`.

2. **Anchor rehydration & binding.** `assert(hash_tree_root(ConsensusAnchor) == envelope.anchor_ref)`.

3. **Sync-committee participation quorum.**
   ```
   participants := popcount(anchor.sync_committee_bits)
   assert(2 * participants > SYNC_COMMITTEE_SIZE)      # strictly > 256 of 512
   ```
   A merely "valid BLS aggregate" is INSUFFICIENT: a genuinely-signed sub-quorum (e.g. 200/512) verifies but does
   not meet the protocol's safety threshold. This check is mandatory and MUST NOT be skipped.

4. **Sync-committee signature.** The signature lives in the block at `anchor.signature_slot` (a carried field,
   NOT computed as `attested + 1` — a skipped slot pushes it later). Select the committee by the signature slot's
   period, and the signing-domain fork by the slot **before** the signature slot (matching consensus-specs
   `fork_version_slot = max(signature_slot, 1) − 1`):
   ```
   assert(anchor.signature_slot > anchor.attested_header.slot)
   sig_period := compute_sync_committee_period_at_slot(anchor.signature_slot)
   # committee active during sig_period: store.current_sync_committee if sig_period == store finalized period,
   # else store.next_sync_committee (the standard Altair current/next handoff, relative to the store period)
   committee := select_committee(sig_period)
   participating_pubkeys := [ committee.pubkeys[i] for i where sync_committee_bits[i] ]
   fork_version_slot := max(anchor.signature_slot, 1) - 1
   domain  := compute_domain(DOMAIN_SYNC_COMMITTEE, fork_version_at_epoch(compute_epoch_at_slot(fork_version_slot)), genesis_validators_root)
   signing_root := compute_signing_root(anchor.attested_header, domain)
   assert(bls.FastAggregateVerify(participating_pubkeys, signing_root, anchor.sync_committee_signature) == true)
   ```
   The committee period comes from the signature slot; the `fork_version` comes from `signature_slot − 1` (these
   differ at a fork-activation boundary — using the signature slot's own epoch is an off-by-one that breaks the
   domain at that boundary). `fork_version` and `genesis_validators_root` come from trusted config, never the envelope.

5. **Execution binding (cross-field).** Prove the `execution_header` against the signed beacon header, then read
   `state_root`/`block_number`/`timestamp` from it — do NOT trust the envelope's copies as bare fields:
   ```
   assert(verify_merkle_branch(
       leaf   = hash_tree_root(anchor.execution_header),
       branch = anchor.execution_branch,
       gindex = EXECUTION_PAYLOAD_GINDEX,                 # see Appendix B (fork-versioned)
       root   = anchor.read_block_header.body_root ) == true)
   assert(anchor.execution_header.state_root  == envelope.state_root)
   assert(anchor.execution_header.block_number == envelope.block_number)
   assert(anchor.execution_header.timestamp    == envelope.timestamp)
   assert(anchor.read_block_header.slot         == envelope.beacon_slot)
   if envelope.finality_status == OPTIMISTIC_HEAD:
       assert(anchor.read_block_header == anchor.attested_header)   # the signed header IS the read block
   ```
   Let `bound_state_root := anchor.execution_header.state_root` (now proven to be committed by `read_block_header`).
   Every quantity asserted here is a verified SSZ leaf; nothing is taken from the envelope on trust.

6. **Freshness contract.** Freshness is NOT proven by the envelope; it is enforced here by the verifier:
   ```
   assert(anchor.attested_header.slot >= head_slot - MAX_STALENESS_SLOTS)
   assert(anchor.attested_header.slot >= verifier.monotonic_max_seen_slot)   # reject regressions / replays
   verifier.monotonic_max_seen_slot := max(verifier.monotonic_max_seen_slot, anchor.attested_header.slot)
   ```
   This single step defeats stale-but-valid and block-level replay. `head_slot` and `monotonic_max_seen_slot`
   MUST originate from the verifier's own consensus view, never an envelope field.

7. **Finality entailment (if claimed).** First `assert(anchor.has_finality == (envelope.finality_status == FINALIZED))`.
   If `envelope.finality_status == FINALIZED`:
   ```
   # (a) finalized_header is the checkpoint finalized by the signed attested_header (Altair finality_branch):
   assert(verify_merkle_branch(
       leaf   = hash_tree_root(anchor.finalized_header),
       branch = anchor.finality_branch,
       gindex = FINALIZED_ROOT_GINDEX,                    # see Appendix B (fork-versioned: 105 pre-Electra, 169 Electra+)
       root   = anchor.attested_header.state_root ) == true)
   # (b) the read block is finalized_header itself, or a proven ancestor reachable from the FINALIZED STATE.
   #     LEAF IDENTITY: for a BeaconBlockHeader, hash_tree_root(header) == the block root accumulated in state,
   #     so the ancestor leaf below is that block root.
   leaf := hash_tree_root(anchor.read_block_header)
   d := anchor.finalized_header.slot - anchor.read_block_header.slot
   if anchor.read_block_header == anchor.finalized_header:
       assert(anchor.ancestor_proof is empty)            # trivial case
   elif d <= SLOTS_PER_HISTORICAL_ROOT:                  # NEAR ancestor (within 8192 slots): use state.block_roots
       assert(verify_merkle_branch(
           leaf, anchor.ancestor_proof,
           gindex = BLOCK_ROOTS_GINDEX composed with (read_block_header.slot % SLOTS_PER_HISTORICAL_ROOT),
           root   = anchor.finalized_header.state_root ) == true)
   else:                                                 # DEEP ancestor: use state.historical_summaries
       assert(verify_merkle_branch(
           leaf, anchor.ancestor_proof,
           gindex = HISTORICAL_SUMMARIES_GINDEX composed with (read_block_header.slot, block_summary index),
           root   = anchor.finalized_header.state_root ) == true)
   ```
   The ancestor proof is rooted at **`finalized_header.state_root`** (NOT `hash_tree_root(finalized_header)`),
   because both accumulators that link an ancestor to the finalized chain — `block_roots` for blocks within the
   most recent `SLOTS_PER_HISTORICAL_ROOT = 8192` slots, and `historical_summaries` for older blocks — live in
   `BeaconState`. The common FINALIZED case (read block within minutes of finality) takes the **`block_roots`**
   path; the deep-history case takes `historical_summaries`. Gindices in §Appendix B. An envelope labelled
   FINALIZED without a verifiable `finality_branch` + `ancestor_proof` MUST be rejected. An `OPTIMISTIC_HEAD`
   envelope MUST NOT be accepted as dispute/audit evidence (see §Verifier obligations).

8. **Per-read Merkle verification (inclusion AND exclusion).** For each `ReadProof r` in `envelope.reads`, the
   account trie is rooted at `bound_state_root` (from step 5) and, for storage, at the account's `storageRoot`:
   ```
   if r.presence == 0:                                   # inclusion
       account A := verify_account_inclusion(r.address, r.account_proof, root = bound_state_root)
       assert(A != null)
       if r.read_kind == STORAGE:
           assert(verify_storage_inclusion(r.slot, r.storage_proof, root = A.storageRoot) == r.value)
       else:   # BALANCE | NONCE | CODE
           assert(field_of(A, r.read_kind) == decode(r.value))   # CODE: keccak256(r.value) == A.codeHash
   else:                                                 # presence == 1: exclusion / proof-of-absence
       if r.read_kind == STORAGE:
           # slot absent from the account's storage trie
           account A := verify_account_inclusion(r.address, r.account_proof, root = bound_state_root)
           assert(A != null)
           assert(verify_storage_exclusion(r.slot, r.storage_proof, root = A.storageRoot) == true)
       else:
           # account absent from the state trie
           assert(verify_account_exclusion(r.address, r.account_proof, root = bound_state_root) == true)
       assert(r.value == 0x)                             # an absent read MUST carry the empty value
   ```
   A bare "zero / not found" value with `presence == 0` and no inclusion proof MUST be rejected. The verifier
   MUST NOT default-accept an unproven absence; `verify_account_exclusion` / `verify_storage_exclusion` MUST
   verify a terminal/divergent-path proof against the same root (truncated MPT paths are a forgery vector).

9. **Batch root consistency.** `assert(all reads in envelope.reads verified against the same bound_state_root)`.
   Mixed-root batches MUST be rejected (prevents a packager pairing `reserve0` at N with `reserve1` at N+5).

10. **Provider signature (if present).** If `envelope.sig_alg != 0`: resolve the verifying key via
    `provider_key_hint` through an **independent** trust path; then
    `assert(verify(key, hash_tree_root(envelope_without_provider_sig), provider_sig))`. A failed resolution or
    signature MUST cause rejection only when `provider_sig` is being relied upon (dispute/audit mode); in plain
    correctness mode an absent/uncheckable signature is acceptable (it carries no correctness weight).

If all steps pass, the verifier has established: *each value in `reads` is the true Ethereum state at
`block_number`, whose header was signed by ≥2/3 of the period's sync committee, and (if FINALIZED) is a finalized
ancestor* — **subject to the residual trust in §Security**. It has NOT established that `block_number` is the
current head beyond the bound enforced in step 6.

# Prover (Packager) obligations

## Packager MUST
- Produce a `state_root` and proofs that correspond to the same block; never mix roots within one envelope.
- Include exclusion proofs for absent accounts/slots; never emit a bare zero value without `presence == 1` proof.
- Set `finality_status` truthfully and include the finality material when claiming FINALIZED.

## Packager SHOULD
- Default to **batch** envelopes for multiple reads at one block (one anchor amortizes the cost).
- Serve the `ConsensusAnchor` as a separate content-addressed object so repeated reads at one block reuse it.

## Packager MAY
- Sign the envelope (`provider_sig`) when operating in an accountable / non-anonymous deployment.

# Verifier obligations

## Verifier MUST
- Perform every step of §Verification Algorithm, in order; reject on any failure.
- Enforce the ≥2/3 participation quorum (step 3) and the freshness contract (step 6).
- Source `head_slot`, `monotonic_max_seen_slot`, `fork_version`, and `genesis_validators_root` from its own
  trusted state, never from envelope bytes.
- Reject a FINALIZED claim lacking verifiable finality material; reject an `OPTIMISTIC_HEAD` envelope when
  evaluating dispute/audit evidence.

## Verifier SHOULD
- Cache verified `ConsensusAnchor`s by slot to amortize BLS verification across clustered reads.
- Strip `provider_sig`, `provider_key_hint`, and any transport-binding metadata before persisting an envelope in
  a privacy-preserving (no-log) profile.

## Verifier MAY
- Persist verified envelopes as audit evidence (see §Audit-Log / Offline Replay), subject to the privacy
  profile chosen.

# Error Handling

Implementations MUST handle (reject and surface):
- Quorum failure (participation ≤ 256/512).
- BLS signature verification failure.
- State-root binding failure (branch or block↔slot mismatch).
- Staleness / monotonicity failure (freshness contract).
- Invalid or missing FINALIZED material when FINALIZED is claimed.
- Merkle inclusion failure; unproven absence.
- Mixed-root batch.

Implementations SHOULD handle:
- `provider_sig` resolution failure (reject only in dispute/audit mode; otherwise downgrade to unsigned).

Error responses MUST include: an error code, an error message, and (when available) the failing step number from
§Verification Algorithm.

# Interoperability Constraints

Every value that MUST match across independent implementations for an envelope to verify identically:
- SSZ serialization of the envelope and all consensus objects (`hash_tree_root` over SHA-256).
- Keccak-256 (Ethereum variant) and RLP for the MPT proof; the EIP-1186 `accountProof`/`storageProof` node
  ordering.
- BLS12-381 with the Ethereum ciphersuite `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`; G1 pubkeys, G2
  signatures; aggregate-pubkey-sum semantics.
- `DOMAIN_SYNC_COMMITTEE = 0x07000000`; `SYNC_COMMITTEE_SIZE = 512`;
  `EPOCHS_PER_SYNC_COMMITTEE_PERIOD = 256`; `signature_slot` is a carried field `> attested_header.slot` (it is
  `attested+1` only when that slot is not skipped). The committee period is selected by the **signature slot**;
  the `fork_version` by **`max(signature_slot, 1) − 1`** (Verification step 4) — the two are not the same slot.
- The mainnet `fork_version`/activation-epoch schedule and `genesis_validators_root` (§Cryptographic Primitives).
- The SSZ generalized indices for `execution_branch`, `finality_branch`, and `ancestor_proof` (§Appendix B),
  selected by the slot's fork.
- The `value` canonical encoding per `read_kind` (no-leading-zero big-endian; code hashes to `codeHash`).
- `proof_format` discriminants and their meaning (fixed to `{0,0,0}` in v0.1).

Each constraint above points to a concrete pinned parameter; none is left as "agree on the same X" without
printing X.

# Security Considerations

## Threat model
A malicious or compromised packager (RPC provider, proxy, CDN, or peer) that may return any bytes, withhold
data, choose which block to answer at, replay old responses, or collude with others. A network adversary that
can drop or reorder messages. The sync committee is assumed honest-majority per the consensus protocol; its
compromise is analyzed below.

## Trust assumptions
- **Correctness reduces to: fewer than 1/3 of the relevant period's 512-member sync committee colluding,
  GIVEN the verifier enforces the ≥2/3 participation quorum (Verification step 3).** Without the quorum check,
  the bound collapses. This is the named security parameter of v0.1.
- A trusted `LightClientBootstrap` within the weak-subjectivity period. "A forged signature fails BLS verify" is
  true **only relative to the correct committee** — an attacker who supplies both bootstrap and envelope can walk
  a verifier onto a forged committee. The bootstrap's trust path is therefore load-bearing and MUST be
  independent of the packager.
- Soundness of Keccak-256 / Merkle-Patricia proofs and of BLS12-381 aggregate signatures.
- Correct domain separation: `fork_version` and `genesis_validators_root` from the verifier's own config. A
  spec that read these from the envelope would let a packager forge the signing domain.
- **No slashing exists for sync-committee light-client forgery** (cf. EIP-7657 / consensus-specs discussion):
  the only deterrent against a colluding committee+packager is `provider_sig` accountability, not protocol
  penalties. Implementers MUST NOT assume economic finality protects a read.

## Freshness (the central limitation — stated, not hidden)
**A single envelope proves correctness-at-block-N. It cannot prove N is the head. Proving "latest" from one
artifact is information-theoretically impossible — a verifier can always be shown an older, genuinely-valid
block.** The sync committee attests that header N is *valid*, not that it is the *tip* or *canonical/finalized*.
Four attacks pass every BLS/MPT check and are defeated only by the §Verification step 6 freshness contract
and step 7 finality entailment:

| Attack | Mechanism | Defended by |
|---|---|---|
| Stale-but-valid | True value for an old block N−k before a state change landed | Step 6 (max-staleness + monotonic head-floor) |
| Reorg | Sync committee signed an optimistic head later orphaned | Step 7 (FINALIZED required for evidence) + step 6 |
| Replay | Re-emit a previously valid envelope for a new request | Step 6 monotonicity (block-level); request-level binding is delegated, see Limitations |
| Finality-downgrade | Always serve cheap reorg-able head while consumer assumes finality | Explicit `finality_status` + step 7 |

The freshness bound is only as tight as the verifier's last consensus sync; an offline verifier inside the
~27 h window can itself hold a stale head. This is disclosed, not solved, in v0.1.

## Privacy guarantees and cross-axis interactions
ARE is a **Correctness** mechanism and provides **no Origin or Content privacy by itself**. Implementers MUST
NOT treat it as a privacy feature. Specific hazards:
- **`eth_getProof` is anti-PIR:** requesting a proof for a specific address/slot reveals exactly that address/slot
  to the packager — the opposite of query privacy. Composition with a PIR or anon-RPC layer is open research and
  out of scope here.
- **`provider_sig` is a non-repudiation hazard:** a signed envelope is a portable, court-admissible receipt that
  a specific party resolved a specific address/slot. It MUST be default-off and used only in deliberately
  accountable deployments. A persisted *signed* audit log is strictly more incriminating than browser history;
  the *unsigned* envelope is equally replayable yet reconstructible from public chain data and therefore
  non-incriminating.
- **Packager-anonymous default:** correctness derives entirely from public chain facts; the default path MUST NOT
  require packager identity. `provider_key_hint` stamps a serving node into a durable artifact and can deanonymize
  small-anonymity-set AAL/KPS peers. Group/ring signatures over a provider set are a RECOMMENDED future direction
  for accountability-without-identification.
- **Transport binding is delegated.** v0.1 does NOT define a `transport_binding` field. Request-level replay and
  session binding are the responsibility of the transport layer (e.g. an anonymizing transport that owns session
  integrity). A naive server-held binding would create a cross-relay correlation token and is deliberately
  excluded. See Known Limitations.

## Linkability
A persisted, signed envelope links {packager identity, address, slot, time} permanently. An unsigned envelope
links {address, slot, block} — all public — and is not additionally identifying. Verifiers operating in a
high-risk profile MUST use the no-log default and strip optional identifying fields before any persistence.

# Known Limitations

**Scope: static L1 trie reads only (v0.1).** `eth_call`, logs/receipts, and L2 are structurally unsupported, not
merely unspecified; each needs a different proof shape (see §Abstract, §Relationship to Prior Art).

**Request-level freshness/replay binding (v0.1).** With no `transport_binding`, an envelope is bound to a block
(step 6) but not to a specific request nonce. A future version MAY add a client-supplied nonce committed by the
packager. Until then, request-level anti-replay is delegated to the transport.

**Offline-replay trust is weaker than live (v0.1).** Replay correctness depends on co-persisted
committee-provenance; see below. An audit envelope's evidentiary weight is "a ≥2/3 committee for period P signed
header N", downgraded to "canonical" only if FINALIZED material is present and re-verifiable.

**Sync-committee soft anchor (v0.1).** No slashing protects light-client reads; correctness rests on the
honest-supermajority-of-committee assumption plus the quorum check, not economic finality.

**Trie-format migration (v0.1).** EIP-7864 (binary trie) and a future RLP→SSZ migration change the objects the
proof commits to. Pre-fork roots are immutable (EIP-7748 freezes rather than deletes), so the risk is
**verifier-code availability** for old `proof_format`s, not proof invalidation. A durable audit log obliges
maintaining legacy verifiers or re-anchoring old entries via a future succinct proof-of-history.

# Audit-Log / Offline Replay

A verifier MAY persist a verified envelope as evidence. To remain re-verifiable offline it MUST co-persist, in
addition to the envelope and its `ConsensusAnchor`:
- the trusted `LightClientBootstrap` (or a finalized checkpoint) the verification was rooted in, and
- the committee-provenance needed to reach `anchor.attested_header`'s period from that checkpoint (a chain of
  `LightClientUpdate`s across period handoffs).

Replay cost scales with the number of distinct periods spanned (one committee handoff verification per period),
not the number of reads. The evidentiary claim of a replayed envelope is precisely: *"the sync committee for
period P, at ≥2/3 participation, signed header N committing this value"* — and "canonical" only when FINALIZED
material verifies. Implementations MUST NOT overstate a replayed OPTIMISTIC envelope as canonical.

# Implementation Notes

Reference implementation: a Python reference verifier + vector generators ship in [`reference/`](../../../../reference/)
(real Keccak-256/RLP **hexary-MPT walk**, real BLS12-381 via `py_ecc`, SSZ `hash_tree_root` over the **full
17-field** `ExecutionPayloadHeader`). As of v0.5 it verifies a **real mainnet** envelope (real `eth_getProof` +
real LightClient `finality_update`/`bootstrap`), not only synthetic fixtures. A production implementation SHOULD
reuse an audited Altair light-client verifier (e.g. the Helios verification core) for steps 3–7 and an EIP-1186
verifier for step 8, so ARE is a thin wire-format and audit layer over audited components rather than new
cryptography.

**Test vectors (conformance contract).** v0.1 ships concrete vectors in [`vectors/`](../../../../vectors/), each
a fixed `{envelope, anchor}` → expected accept/reject (with the failing step for rejects). The MINIMAL vectors are
generated by `reference/are_generate.py` and `reference/are_extra_vectors.py`, the MAINNET real-data vector by
`reference/are_real_vectors.py`, and all are re-checked by `reference/run_vectors.py` (**10/10 passing**):
1. **`accept_mainnet_real.json` (MAINNET, REAL DATA)** — a FINALIZED WETH balance + storage-slot-0 read at exec
   **block 25404693**, anchored to a real LightClient `finality_update` (attested **slot 14640721**, finalized
   **slot 14640640**, signature **slot 14640722**, sync-committee **period 1787**, fork **Fulu**
   `0x06000000`). Verified end-to-end: a real **512**-member sync committee, a real aggregate BLS signature with
   **510/512** participants, a **real hexary MPT** account+storage proof against the real EL state root
   `0xf6c792621f2a4df8b83abcaf1c72aff30c571fcfb14533ebefd5327b2b53f2a1`, the **full 17-field**
   `ExecutionPayloadHeader` (`execution_branch` @ `EXECUTION_PAYLOAD_GINDEX = 25`), and a real `finality_branch`
   @ `FINALIZED_ROOT_GINDEX = 169`. Recorded intermediates:
   `signing_root = 0x000fd44e62c984d7c201807dc607688818fdca4716cadbd827ce34b393551af0`,
   `bound_state_root = 0xf6c792621f2a4df8b83abcaf1c72aff30c571fcfb14533ebefd5327b2b53f2a1`. Raw source bytes are
   preserved under [`vectors/real-data/`](../../../../vectors/real-data/).
2. `accept_balance.json` — MINIMAL accepting static-balance read (Appendix A), OPTIMISTIC; 25/32 participants;
3. `accept_balance_finalized.json` — MINIMAL FINALIZED, **near**-ancestor `state.block_roots` path;
4. `accept_deep_ancestor.json` — MINIMAL FINALIZED, **deep**-ancestor `state.historical_summaries` path
   (finalized−read gap 20000 > `SLOTS_PER_HISTORICAL_ROOT` 8192); a real SHA-256 depth-41 `historical_summaries`
   branch (full-fidelity seeded synthetic — see Caveats);
5. `accept_provider_sig.json` — MINIMAL OPTIMISTIC read carrying a **real ed25519** `provider_sig` (`sig_alg = 2`)
   over `hash_tree_root(envelope_without_provider_sig)`, verified at step 10 in dispute/audit mode against an
   independently-resolved key;
6. `reject_quorum_too_low` (step 3), `reject_bad_bls` (step 4), `reject_unproven_absence` (step 8),
   `reject_mixed_root_batch` (step 9), `reject_bad_provider_sig` (step 10) — one MINIMAL vector per failure class.

**Caveats — v0.6 status (honest, not hidden).** The three v0.4 simplifications were **discharged in v0.5 by the
mainnet real-data vector**, with real mainnet bytes throughout (no fabricated hashes):
- ✅ **Mainnet-512 committee + real BLS aggregate** — `accept_mainnet_real.json` verifies a real 510/512 aggregate
  over the real period-1787 committee. *(The 4 MINIMAL `SYNC_COMMITTEE_SIZE = 32` vectors remain as fast smoke
  tests only.)*
- ✅ **Full hexary MPT** — the verifier is now a real EIP-1186 branch/extension/leaf walker; it verifies a real
  mainnet `eth_getProof` (WETH account + storage). The v0.4 "simplified single-account MPT" code path is
  **removed**.
- ✅ **Full `ExecutionPayloadHeader`** — the real 17-field Deneb+ header, matched against a real beacon `body_root`
  via `execution_branch` @25.

**Discharged in v0.6 (both former draft-blockers):**
- ✅ **Benchmarks** — measured, environment stated (no longer indicative). Harness: `reference/benchmark.py`.
  **Apple M2 · 8 GB RAM · Python 3.12.2 · macOS 26.5 (arm64) · `py_ecc` pure-Python BLS12-381 · native CPython.**

  | Operation | Median | Notes |
  |---|---|---|
  | BLS `FastAggregateVerify`, 512-committee | **3818.89 ms** | real mainnet aggregate, 510/512 participants, pure-Python |
  | hexary MPT account+storage verify | **0.07 ms** | real WETH `eth_getProof` (9 account + 7 storage nodes) |
  | SSZ `hash_tree_root(anchor)` | **0.07 ms** | full `ConsensusAnchor` incl. 17-field exec header |
  | full end-to-end envelope verify | **3783.90 ms** | all 10 steps; dominated by the BLS verify |

  | Regime | Per-read cost | Meaning |
  |---|---|---|
  | **Clustered** (anchor reused) | **0.07 ms** | BLS anchor verified once; extra reads at the same block pay only MPT |
  | **Scattered** (distinct blocks) | **3818.96 ms** | one BLS aggregate verify per distinct block + its MPT |

  Clustered batching is **~56000× cheaper per read** than scattered — the quantitative basis for the §Packager
  "default to batch" SHOULD. The pure-Python `py_ecc` BLS verify is the dominant cost and an **UPPER BOUND**; a
  production verifier reusing an audited light-client core (Helios, `blst` native/WASM) verifies the same aggregate
  in single-digit ms. **Native-blst and WASM figures are future work and are deliberately not fabricated here.**
- ✅ **Accept coverage for the deep `historical_summaries` ancestor path (step 7b) and `provider_sig` (step 10)** —
  both are now locked by accepting vectors (`accept_deep_ancestor.json`, `accept_provider_sig.json`); the v0.5
  deep-path / provider-sig stubs are replaced by real checks (see §Implementation Notes vector list).

**Remaining before `draft` (honest assessment):** nothing structurally blocks `draft`. Two residual notes, neither
a soundness gap:
- The **deep-ancestor vector is a full-fidelity seeded synthetic** at the Deneb preset (real Keccak/SSZ/BLS, real
  SHA-256 `historical_summaries` branch; only the *outer* `BeaconState` siblings are seeded — a real mainnet deep
  proof is unreachable because the public beacon node blocks full-state download, the only source of true siblings).
  The mainnet real-data vector remains the gold-standard end-to-end case.
- `provider_sig` coverage uses **ed25519** (real RFC 8032); **secp256k1** (sig_alg=1) is spec-declared but not
  implemented in the reference. Step-10 control flow is identical across both; this is a reference-coverage note.

**Promoted to `status: draft` at rev 0.8** by the editor: the design can be demonstrated (reference verifier +
10/10 conformance vectors incl. a real-mainnet case), which is COSS's bar for `raw → draft`. Draft is a contract
between editors and implementers — subsequent changes are made in consultation, not unilaterally. This does not
imply audit or EF endorsement; the residual notes above stand.

# References

- [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt)
- [EIP-1186 — `eth_getProof`](https://eips.ethereum.org/EIPS/eip-1186)
- [EIP-7919 — Pureth Meta](https://eips.ethereum.org/EIPS/eip-7919); EIP-7745 (logs), EIP-7708
- [EIP-7864 — binary state trie](https://eips.ethereum.org/EIPS/eip-7864); EIP-7748 (state-conversion freeze)
- Ethereum consensus specs — [Altair sync protocol & light client](https://github.com/ethereum/consensus-specs/tree/dev/specs/altair/light-client)
- [Colibri / C4 — corpus-core](https://github.com/corpus-core/colibri-stateless)
- Helios (a16z) light client; Kevlar
- BLS12-381 ciphersuite: IETF `draft-irtf-cfrg-bls-signature` (POP variant)

# Glossary

## Envelope
The `AttestedReadEnvelope` SSZ container carrying one or more reads at a single block plus the material to verify
them.

## Anchor / ConsensusAnchor
The sync-committee attestation object binding `state_root` to a signed beacon header; referenced by `anchor_ref`,
rehydrated separately to avoid per-read duplication.

## Packager
The (untrusted) party that assembles an envelope: an RPC provider, proxy, CDN, or peer — or the client itself.

## Quorum
≥2/3 participation of the 512-member sync committee (`2 * popcount(bits) > 512`), the participation threshold the
verifier MUST enforce.

## Freshness contract
The verifier-side check (Verification step 6) that bounds how stale an accepted envelope may be, using the
verifier's own head view and a monotonic floor. The protocol does not and cannot prove "latest".

## Finality status
Whether the envelope is anchored to an `OPTIMISTIC_HEAD` (reorg-able) or a `FINALIZED` header; only FINALIZED
envelopes are admissible as dispute/audit evidence.

# Appendix A — Worked verification example (static balance read)

A verifier holds a trusted bootstrap for period P and `head_slot = 9_000_000`, `MAX_STALENESS_SLOTS = 64`.
It receives an OPTIMISTIC single-read envelope: `read_kind = balance`, `address = 0xabcd…`, `value = 0x0de0b6b3a7640000`
(1 ETH), `block_number = 21_000_000`, `beacon_slot = 8_999_990`, `state_root = 0x1111…`.

Verification trace (the normative sequence; this example is symbolic — for a full set of concrete bytes see the
real-mainnet vector `vectors/accept_mainnet_real.json` and the recorded intermediates in §Implementation Notes):
1. chain_id=1/anchor_type=0/version=1 match; `proof_format == {0,0,0}` → pass.
2. `hash_tree_root(ConsensusAnchor) == anchor_ref` → pass (`has_finality = false`, finality fields zeroed).
3. `popcount(bits) = 401`; `2*401 = 802 > 512` → quorum pass.
4. `anchor.signature_slot = 8_999_991` (carried field; `> 8_999_990` → pass); committee for
   `compute_sync_committee_period_at_slot(8_999_991)` selected; aggregate 401 pubkeys; `domain` from mainnet
   `genesis_validators_root` + fork_version at `epoch_of(8_999_991 − 1)`; `FastAggregateVerify(signing_root, sig)
   == true` → pass.
5. `verify_merkle_branch(hash_tree_root(execution_header), execution_branch, EXECUTION_PAYLOAD_GINDEX,
   read_block_header.body_root)` → pass; `execution_header.state_root == 0x1111…`,
   `execution_header.block_number == 21_000_000`, `execution_header.timestamp == envelope.timestamp`,
   `read_block_header.slot == 8_999_990` → all pass; OPTIMISTIC ⇒ `read_block_header == attested_header` → pass.
   `bound_state_root := 0x1111…`.
6. `8_999_990 ≥ 9_000_000 − 64`? → **9_000_000 − 64 = 8_999_936; 8_999_990 ≥ 8_999_936 → pass.** Monotonic floor
   updated.
7. `has_finality == false` and finality_status = OPTIMISTIC → consistent; skip; envelope NOT admissible as evidence.
8. `presence=0`: `verify_account_inclusion(0xabcd…, account_proof, root=bound_state_root)` → account A;
   `A.balance == 0x0de0b6b3a7640000` → pass.
9. single read → batch consistency trivially holds.
10. sig_alg = 0 → no signature check.
→ **ACCEPT** as a correctness-only, optimistic (reorg-able) read. The verifier MAY display the balance but MUST
treat it as head-relative, not finalized, and MUST NOT archive it as canonical evidence.

# Appendix B — SSZ generalized indices (fork-versioned)

Every Merkle branch in `ConsensusAnchor` is verified against a **fixed generalized index**, selected by the fork
of a specific slot (named per branch below). Independent verifiers MUST walk identical paths. v0.1 normatively
supports the **Deneb, Electra, and Fulu** forks on mainnet (Fulu shares Electra's `BeaconState`/`BeaconBlockBody`
SSZ layout, hence its gindices; the v0.5 real-data vector is a Fulu envelope and **locks** `EXECUTION_PAYLOAD = 25`
and `FINALIZED_ROOT = 169` against real mainnet bytes). The concrete gindices are:

| Branch | Constant | Deneb (& Capella) | Electra | Gindex selected by | Proves |
|---|---|---|---|---|---|
| `execution_branch` | `EXECUTION_PAYLOAD_GINDEX` | `25` | `25` (unchanged — `BeaconBlockBody` ≤ 16 fields) | `read_block_header` slot's fork | `execution_header` == `body.execution_payload` |
| `finality_branch` | `FINALIZED_ROOT_GINDEX` | `105` | `169` | **`attested_header` slot's fork** | `hash_tree_root(finalized_header)` from `attested_header.state_root` |
| `ancestor_proof` (near, `d ≤ 8192`) | `get_generalized_index(BeaconState, 'block_roots', slot mod 8192)` | derive | derive | `finalized_header` slot's fork | read block root in `state.block_roots[slot mod 8192]` |
| `ancestor_proof` (deep, `d > 8192`) | `get_generalized_index(BeaconState, 'historical_summaries', i, 'block_summary_root', slot mod 8192)` | derive | derive | `finalized_header` slot's fork | read block root in `state.historical_summaries[i].block_summary_root[…]` |
| committee (bootstrap) | `CURRENT_SYNC_COMMITTEE_GINDEX` / `NEXT_SYNC_COMMITTEE_GINDEX` | `54` / `55` | `86` / `87` | bootstrap header's fork | sync committee from a trusted bootstrap/update |

`SLOTS_PER_HISTORICAL_ROOT = 8192`. Three gindices are grader-/spec-verified integers (`EXECUTION_PAYLOAD = 25`;
`FINALIZED_ROOT = 105` Deneb / `169` Electra; committee `54/55` Deneb / `86/87` Electra). The two `ancestor_proof`
indices are given as the **deterministic SSZ derivation** `get_generalized_index(BeaconState_<fork>, …)` rather
than a hardcoded integer: the derivation is reproducible from the fork's `BeaconState` definition, and the
concrete integers are **locked by the test vectors** (§Implementation Notes) so two implementers converge. The
state-relative gindices changed at Electra because `BeaconState` gained fields (deeper tree);
`EXECUTION_PAYLOAD_GINDEX` is block-body-relative and stays `25` while the body has ≤ 16 fields.

A verifier MUST reject a branch whose length/index is inconsistent with the gindex for the selecting fork. The
authoritative source is the `ethereum/consensus-specs` `light-client` constants; the values above are the
`MAINNET` selection for the v0.1-supported forks and are locked by the test vectors (§Implementation Notes). A
fork outside the supported set MUST be rejected by a v0.1 verifier until its gindices are added (this is a scope
boundary, not a deferral — the table above is complete for the forks v0.1 claims to support).

# Copyright

Copyright and related rights waived via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).
