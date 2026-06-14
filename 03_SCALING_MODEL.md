# MF-SPV — Scaling Model (derivations + simulator targets)

Every number here is derived from stated parameters. None is an assumption. The simulator
(`mfspv/bench`) must reproduce these; deviations are bugs, not tuning.

## Parameters
- Block interval `t = 600 s` (BSV ~10-min average; the design does not change it).
- Header size `H = 80 bytes` (BSV header; unchanged).
- Blocks/year `≈ 144 × 365 = 52,560`.
- Subtree capacity `S = 2^20 = 1,048,576` TXIDs (Teranode, observed up to ~1e6/subtree).
- Digest `d = 32 bytes` (SHA-256d).

## Derivations
`T(r) = r · t` transactions per block.
`depth(r) = ceil(log2 T(r))`  — full L0→L2 inclusion path length (subtree split adds no hashes).
`proof(r) = d · depth(r)` bytes — core (L0–L2) inclusion proof size.
`subtrees(r) = ceil(T(r) / S)`; `L1len = ceil(log2 min(T,S))`; `L2len = depth − L1len`.
Header dataset `= H × 52,560 ≈ 4.2 MB / year`, independent of `r`.

## Target table (simulator must match exactly)
| r (tx/s) | T = r·600 | depth = ⌈log₂T⌉ | proof = 32·depth (B) | subtrees = ⌈T/2²⁰⌉ | L1 len | L2 len |
|---|---|---|---|---|---|---|
| 1e6  | 6.00e8  | 30 | 960   | 573        | 20 | 10 |
| 1e7  | 6.00e9  | 33 | 1056  | 5,723      | 20 | 13 |
| 1e8  | 6.00e10 | 36 | 1152  | 57,221     | 20 | 16 |
| 1e9  | 6.00e11 | 40 | 1280  | 572,205    | 20 | 20 |
| 1e10 | 6.00e12 | 43 | 1376  | 5,722,046  | 20 | 23 |
| **1e11** | **6.00e13** | **46** | **1472**  | **57,220,459**  | **20** | **26** |
| 1e12 | 6.00e14 | 50 | 1600  | 572,204,590 | 20 | 30 |

(For `T < 2²⁰` a block is a single subtree and `L1len = depth`, `L2len = 0`; not reached above 1e6.)
**1e11 = 100 billion tx/s is the required operating point.** Going from 1e10→1e11
adds **3 hashes (96 B)**; the proof is **1472 B** and `depth = 46 ≪ 255`. 1e12 is
headroom at `depth = 50`. The logarithmic law does not break anywhere in this range.

## Running at 100 billion tx/s — capacity (derived)

Two separate costs, never conflated:

- **Edge (SPV verification).** Per-payment cost is `depth = 46` hash compressions on
  a ~1472 B proof — measured **~13.7 µs / verify** on a commodity software core
  (3.4 M SHA-256d/s/core). Verification is **stateless and embarrassingly parallel**
  (no shared state, no network on the hot path), so aggregate capacity scales
  **linearly with cores**: an 8-core box sustains ~0.45 M verifies/s; an N-core
  fabric sustains `N × ~80k/s`. This is **independent of `r`** — 100 billion tx/s
  does not raise edge cost beyond the +3-hash log term.
- **Sealing (Teranode's job, the Merkle commitment part).** A block of `T` tx needs
  `T−1` internal Merkle hashes (the subtree split adds none), i.e. the *marginal*
  Merkle hash rate to seal at rate `r` is **`r` hashes/s** (`(T−1)/600`), or **`~2r`**
  including leaf/TXID hashing. At `r = 1e11` that is **~2×10¹¹ SHA-256d/s**
  network-wide ≈ **~2,000 hardware-accelerated (SHA-NI) cores** (≈ 58,000 pure-software
  cores), sharded across **~95,367 subtrees/s** of 2²⁰ TXIDs each. This is exactly
  Teranode's horizontal-scale model; `r` is bounded by Teranode validation/propagation,
  not by SPV (Result 4.4). The simulator's `bench.PlanCapacity` reproduces these
  figures from a measured per-core hash rate; `bench.VerifyThroughput` measures the
  edge sustaining the rate.

## Headline results to validate
- **R1.** Inclusion proof grows by **13 hashes (416 B)** from 1e6 to 1e10 tx/s. Logarithmic.
- **R2.** Header dataset is **constant 4.2 MB/yr** across all `r`.
- **R3.** Verification work ∝ `depth` (≤43 hash compressions + 1 header lookup) — sub-millisecond on
  commodity hardware; must be shown to grow logarithmically, not linearly, in `T`.
- **R4.** Per-payment network cost for the proof is **0** (sender-pushed). The simulator records the
  bytes that WOULD traverse the network under a pull model (legacy SPV path fetch) versus 0 here.

## Comparison rows the simulator should also emit (for the paper's evaluation section)
For each `r`, also compute the **pull-model** cost a verifier would pay to fetch the Merkle path
from the network (legacy SPV / TxChain regime), to quantify what the push model removes. And the
**FlyClient-style** saving ceiling (= full header dataset, R2), to show it does not scale with `r`
(Result 4.3 in `01_ARCHITECTURE.md`).

## What is NOT modelled here (stated)
- Teranode internal validation/propagation throughput limits (these, not SPV, bound `r`).
- Signature verification cost on Bob (independent of `r`; per-payment constant).
- Reorg frequency / re-anchor cost (policy-dependent; see TEST_PLAN §T3.4).
