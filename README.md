# Attested-Read Envelope (ARE)

![Attested-Read Envelope — abstract verifiable-read landscape](assets/are-cover.png)

> ⚠️ **EXPERIMENTAL — `raw`-status draft (rev 0.6) — NOT AN OFFICIAL STANDARD.**
> Published for open discussion. Not audited. Subject to change or removal. Do not build production systems
> against it. It does not represent a finalized position of the Ethereum Foundation or any team.

A self-describing, offline-replayable envelope for **verifiable Ethereum state reads** — a returned value bound
to (a) an EIP-1186 Merkle-Patricia proof against an execution `state_root` and (b) an Altair sync-committee
attestation anchoring that root to a signed beacon header. A verifier holding only a trusted light-client
bootstrap can check an envelope offline, with no trust in the server that produced it, and can **persist** it as
dispute/audit evidence.

The only claimed contribution over prior art (EIP-1186, Pureth/EIP-7919, Colibri/C4, Helios, Kevlar) is
**(a)** a standardized wire format and **(b)** audit-log / dispute non-repudiation semantics.

## Status

| | |
|---|---|
| Lifecycle | `raw` (COSS) — document rev 0.6 |
| Scope (v0.1) | Static L1 trie reads: `eth_getBalance` / `eth_getStorageAt` / `eth_getCode` / `eth_getTransactionCount` |
| Out of scope | `eth_call` (computed), logs/receipts, L2, mempool — each needs a different proof shape |
| Reference impl | ✅ Python — real Keccak/RLP hexary MPT, real BLS12-381 (`py_ecc`), SSZ |
| Test vectors | ✅ **10/10 pass** — incl. one from **real mainnet bytes** (block 25404693) |
| Benchmarks | ✅ measured (see below) |

## What's here

- [`specs/ARE/README.md`](specs/ARE/README.md) — the full specification (structs, 10-step verification algorithm, security model, generalized indices).
- [`reference/`](reference/) — a runnable reference verifier + deterministic vector generator + benchmark harness.
- [`vectors/`](vectors/) — 10 conformance vectors (5 accept incl. a real-mainnet case, 5 reject — one per failure class), each re-checked by `reference/run_vectors.py`.
- [`CHANGELOG.md`](CHANGELOG.md) — the v0.1 → v0.6 history (four external grading rounds: Codex + fresh-context reviewers).

## Run the vectors

```bash
cd reference
python3 -m venv .venv && . .venv/bin/activate && pip install -r ../requirements.txt
python run_vectors.py     # 10/10
python benchmark.py       # measured costs
```

## Vectors

| Vector | Preset | Expected |
|---|---|---|
| `accept_balance` / `accept_balance_finalized` | minimal | ACCEPT (optimistic / near-ancestor finalized) |
| `accept_deep_ancestor` | minimal | ACCEPT (deep `historical_summaries` path) |
| `accept_provider_sig` | minimal | ACCEPT (signed, evidence mode) |
| **`accept_mainnet_real`** | **mainnet** | ACCEPT — real `eth_getProof` (WETH) + real 512-committee sync aggregate |
| `reject_quorum_too_low` / `reject_bad_bls` / `reject_unproven_absence` / `reject_mixed_root_batch` / `reject_bad_provider_sig` | minimal | REJECT at steps 3 / 4 / 8 / 9 / 10 |

## Benchmarks

Apple M2 · 8 GB RAM · Python 3.12 · pure-Python BLS (`py_ecc`), native CPython (WASM/`blst` is future, not measured):

| Operation | Median |
|---|---|
| BLS `FastAggregateVerify`, real 512-committee | ~3819 ms |
| hexary MPT account+storage verify (real WETH proof) | 0.07 ms |
| SSZ `hash_tree_root(anchor)` | 0.07 ms |
| **Clustered** per-read (anchor reused) | 0.07 ms |
| **Scattered** per-read (one BLS per block) | ~3819 ms |

Clustered batching is ~56,000× cheaper per read — the quantitative basis for the spec's "default to batch"
SHOULD. The pure-Python BLS dominates and is an upper bound (production uses `blst`).

## Honest limitations

- A single envelope proves *correctness at block N*, never that *N is the head* — freshness is an enforced
  client-side contract, not a property of the artifact (see the spec's Security Considerations).
- The `accept_deep_ancestor` vector's outer `BeaconState` siblings are synthetic (the public beacon
  `debug/beacon/states` endpoint is closed, so a real deep `historical_summaries` proof can't be fetched); its
  Keccak/SSZ/BLS and the depth-41 branch are real. The mainnet vector is the gold-standard end-to-end case.
- `provider_sig` coverage is ed25519; secp256k1 (`sig_alg=1`) is spec-declared but not yet in the reference.

## License

[CC0 1.0](LICENSE) — public domain dedication.
