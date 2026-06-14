# MF-SPV — Merkle-Forest SPV (BSV / Teranode)

A complete, dependency-free Go implementation of the Merkle-Forest SPV design in
this folder (`01_ARCHITECTURE.md`, `02_MODULE_SPECS.md`, `03_SCALING_MODEL.md`,
`04_TEST_PLAN.md`, `PAPER.md`).

**BSV only.** No BTC parameter, code path, or assumption appears anywhere. The
module has **zero external dependencies** — it builds and tests entirely offline,
including the secp256k1 signer.

## What this is

A five-level Merkle commitment hierarchy that reuses Teranode's existing subtree
structure, ships inclusion proofs sender-pushed with the payment, and freezes the
historical proof at block-sealing:

```
 L0  field            ->  MTxID = TXID          (Merkle tree over tx FIELDS; US 2022/0216997)
 L1  TXID             ->  subtree root          (Teranode subtree, <= 2^20 TXIDs)
 L2  subtree root     ->  block Merkle root     (built over subtree roots)
 L3  block root       ->  80-byte header        (PoW-sealed)  -- core ends here, no consensus change
 L4  header           ->  off-header accumulator (MMR root in the generation tx)  -- OPTIONAL
```

Double-spend is kept **orthogonal** to the proof: a valid inclusion proof is a
fail-fast against spam/error, never double-spend protection. Acceptance at the
point of sale combines inclusion (local) with a live UTXO query, a PoW-attested
alert layer, and a merchant risk parameter τ.

## Layout (build order)

| Package            | Design ref                | Role |
|--------------------|---------------------------|------|
| `commitment`       | §commitment / T1          | SHA-256d Merkle core; L0–L2 build & verify; depth law |
| `crypto`           | (spend authorisation)     | self-contained secp256k1 ECDSA, RFC 6979, low-S |
| `accumulator`      | §accumulator / T2         | L4 MMR over headers; `VerifyAnchor`; absent-period honesty |
| `teranode`         | §teranode_adapter / T6    | read-only `ProofSource`/`HeaderChain`/`UTXOClient` + in-memory `MockNode` |
| `bundle`           | §bundle / T3              | the sender-held proof object; `Build/Serialize/Verify/Reanchor` |
| `payment`          | §3.2                      | `Tx3`, sighash, the Alice→Bob push message |
| `walletalice`      | §wallet_alice / T4        | offline customer wallet (`Sign/FillTemplate/Export`) |
| `walletbob`        | §wallet_bob / T4,T5       | point-of-sale till (`AcceptPayment/Broadcast`, `RiskPolicy`) |
| `dsalert`          | §dsalert / T5             | evidence-gated, PoW-attested double-spend alert layer |
| `bench`            | §bench / T7               | scaling simulator reproducing the derived table |
| `cmd/mfspv`        | —                         | demonstration runner |
| `adversarial`      | 04_TEST_PLAN A1–A5        | consolidated red-team rejections |

## Run

```sh
go test ./...               # 74 tests: T1–T7, A1–A5, RT-1..7, KAT, differential, property, Monte-Carlo
go test -shuffle=on ./...   # order-independent (06_EVALUATION_DESIGN §3.4)
go run ./cmd/mfspv          # scaling table + capacity + one full push payment
go run ./cmd/mfspv -eval    # emit environment.json + claims.csv, tagged M/D/S (06 §8 reproduce)
```

The evaluation follows `06_EVALUATION_DESIGN.md` (publication-grade, ACM-artifact
standard): known-answer tests against published vectors (double-SHA256, the secp256k1
2G constant, the RFC 6979 nonce), a differential Merkle oracle over odd cardinalities,
property tests at 10⁵ cases, Monte-Carlo inclusion-forgery (10⁶ trials, 0 accepted,
Clopper–Pearson `p_upper ≤ 4.6×10⁻⁶`), and a scaling-law regression that statistically
rejects linear-in-T (R²(log)=0.999 vs R²(T)=0.40). `claims.csv` maps every claim ID to
its falsifying test.

Demonstration output (abridged):

```
r      T=r*600        depth proofB  subtrees    L1 L2  push pull
1e+06  600000000      30    960     573         20 10  0    960
1e+10  6000000000000  43    1376    5722046     20 23  0    1376
1e+11  60000000000000 46    1472    57220459    20 26  0    1472   <- 100 billion tx/s
Header dataset: 4204800 bytes/year (~4.2 MB/yr), constant in r.

== Running at 100 billion tx/s (1e11) — capacity ==
This machine: 3.46 M SHA-256d/s/core (software path).
r=1e+11  seal: 2.00e+11 hashes/s, ~57829 cores @sw / ~2000 cores @SHA-NI | edge proof: 1472 B
Edge @1e11 (depth 46, 1472 B): 81920 verifies/s/core, 450560 verifies/s on 8 cores (stateless, linear).
Bob decision: accepted=true ...
After double-spend: accepted=false reason="double-spend:utxo-spent" (inclusion still true)
```

### Scaling to 100 billion tx/s (10¹¹) and beyond

At 10¹¹ tx/s the inclusion proof is **depth 46 / 1472 bytes** — just **3 hashes
(96 B) more than 10¹⁰**, and `46 ≪ 255` (the one-byte depth ceiling). 10¹² is
headroom at depth 50 / 1600 B. The verifier's cost is logarithmic and **decoupled
from throughput** by construction, so there is no SPV-side ceiling.

"Running at that level" means two measurable things, both delivered:

- **Edge (verification fabric):** per-payment verification is ~13.7 µs (depth-46
  fold) and **stateless / embarrassingly parallel** — aggregate capacity scales
  linearly with cores (`bench.VerifyThroughput`, `ProfileEdge`). 100 billion tx/s
  does not raise per-payment cost.
- **Sealing (Teranode's sharded job):** building the Merkle forest for 10¹¹ tx/s
  needs **~2×10¹¹ SHA-256d/s network-wide ≈ ~2,000 SHA-NI cores** across
  ~95,367 subtrees/s — derived, not asserted, by `bench.PlanCapacity` from a measured
  hash rate. This is exactly Teranode's horizontal-scale model; `r` is bounded by
  Teranode validation/propagation, not by SPV (Result 4.4).

## How the falsifiable claims are enforced in code

- **R1 (proof +416 B over 1e6→1e10):** `bench.TestR1_ProofGrowth`.
- **R2 (header dataset constant 4.2 MB/yr):** `bench.TestT7_3_HeaderConstant` / `I-BE3`.
- **R3 (verify ∝ depth, not T):** `bench.TestT7_4_LogarithmicVerify` measures real fold time.
- **R4 (push proof bytes = 0):** `bench.TestT7_5_PushVsPull`.
- **Depth law `depth == ceil(log2 T)`:** integer `commitment.CeilLog2`, asserted in `T1.3`/`T7`.
- **Frozen core (anti-Utreexo):** `bundle.TestT3_3_FrozenCore` asserts byte-equality across `Reanchor`.
- **Inclusion ≠ double-spend:** `bundle.TestT3_5` and `walletbob.TestT4_4` — a spent output's proof
  still verifies but is not accepted.
- **Absent-period honesty (I-A3):** `accumulator.TestT2_3_GapHonesty` — a height in a gap returns
  `inGap == true`, never a false "in chain".
- **No keys at till (I-BB2):** `walletbob.StorePrivateKey` always errors; `TestT4_3`.

## Security posture

Inclusion soundness reduces to SHA-256d collision/preimage resistance: every
`Verify` recomputes the path bottom-up and compares to the header's committed root;
no input but the true sibling set folds to the root. Every adversarial test
(`adversarial/`) asserts a **rejection** — forged paths, off-chain headers,
evidence-free alert floods, and orphaned anchors are all refused. The L4 branch is
gated: `VerifyBlockInChain` is trusted only when `VerifyAnchor` confirms the
accumulator root is committed in a PoW-sealed generation transaction (I-A2).

### Two honest implementation notes (stated, not hidden)

1. **`03_SCALING_MODEL.md` / `PAPER.md` subtree count for 1e10 was off by one.**
   The tables printed `5,722,045` (the floor); the *derived* `ceil(6e12 / 2^20)`
   is `5,722,046` (remainder 942,080 ≠ 0). Per the design's own rule ("every
   number is derived; deviations are bugs"), the code emits the correct value and
   the two docs were corrected to match. Every other table cell was already exact.

2. **The secp256k1 signer uses `math/big` and is therefore not constant-time.**
   It is correct (deterministic RFC 6979 nonces, low-S, on-curve checks, round-trip
   tested) and dependency-free, but side-channel hardening is a production task.
   The MF-SPV inclusion-soundness claims rest on the Merkle layer, not on the
   signer; the signer provides the spend authorisation the push protocol needs. For
   deployment inside Teranode, swap `crypto` for the node's audited secp256k1.

The `teranode` package ships an in-memory `MockNode` that builds *real* subtree and
block Merkle trees and a *real* header accumulator, so the bundle and wallet layers
are exercised against genuine cryptographic structures. Wiring `ProofSource` /
`HeaderChain` / `UTXOClient` to a pinned Teranode revision (01_ARCHITECTURE §7
dependency #2) is the remaining integration step; the interfaces are read-only by
construction (I-TA1).
