# Attested-Read Envelope (ARE)

![Attested-Read Envelope — abstract verifiable-read landscape](assets/are-cover.png)


> ⚠️ **EXPERIMENTAL — DRAFT — NOT AN OFFICIAL STANDARD.**
> This is an early, unreviewed `raw`-status draft (v0.1) published for open discussion. It has **not** been
> audited, has **no** reference implementation, ships **no** test vectors yet, and is **subject to change or
> removal at any time**. Do not build production systems against it. It does not represent a finalized position
> of the Ethereum Foundation or any team.

A self-describing, offline-replayable envelope for **verifiable Ethereum state reads** — a returned value bound
to (a) an EIP-1186 Merkle-Patricia proof against an execution `state_root` and (b) an Altair sync-committee
attestation anchoring that root to a signed beacon header. A verifier holding only a trusted light-client
bootstrap can check an envelope offline, with no trust in the server that produced it, and can **persist** it as
dispute/audit evidence.

## Status

| | |
|---|---|
| Lifecycle | `raw` (COSS) — v0.1 |
| Scope (v0.1) | Static L1 trie reads only: `eth_getBalance` / `eth_getStorageAt` / `eth_getCode` / `eth_getTransactionCount` |
| Out of scope | `eth_call` (computed), logs/receipts, L2, deep-history replay — each needs a different proof shape |
| Reference impl | **None yet** (the gating gap before `draft`) |
| Test vectors | **None yet** |

## What's here

- [`specs/ARE/README.md`](specs/ARE/README.md) — the full specification.

## The honest caveats

This draft deliberately does **not** claim to invent verifiable reads, a consensus anchor, or a "trustless
server." That is prior art (EIP-1186, Pureth/EIP-7919, Colibri/C4, Helios, Kevlar). The only claimed
contribution is **(a)** a standardized wire format and **(b)** audit-log / dispute non-repudiation semantics.

The central limitation is stated up front in the spec: a single envelope proves *correctness at block N*, never
that *N is the head*. Freshness is an enforced client-side contract, not a property of the artifact. See the
spec's Security Considerations.

## License

[CC0 1.0](LICENSE) — public domain dedication.
