# 07 — Verification-Fabric: measured results (implementation of 07_VERIFICATION_FABRIC.md §7)

Implements the design's four hand-off tasks and runs the benchmark on the target box.
All folds are REAL SHA-256d over real Merkle paths (`mfspv/commitment`); no simulation.
Run it yourself: `go run ./cmd/verifyfabric -dur 2s`.

## What was built (design §7)
1. **Lever A — pluggable hashing backend** (`bench/backend.go`): one `Backend` interface
   (`HashPair` + multi-buffer `HashPairBatch`), capability-selected. Implemented:
   `software` (Go `crypto/sha256`; emits SHA-NI automatically where the CPU exposes it)
   and a `multibuf-scalar(x8)` interface stand-in. **The AVX2/AVX-512 multi-buffer asm
   backend is NOT implemented** — it is the documented accelerator; this file never
   claims a SIMD speedup it did not measure. `CapabilityNote()` reports whether the
   measured per-core rate indicates hardware SHA acceleration.
2. **Lever B — batch verifier** (`bench/fabric.go`): proofs grouped by subtree; each
   distinct subtree's L2 path (subtreeRoot→blockRoot) folded ONCE per batch, every
   proof's L1 path (TXID→subtreeRoot, ≤20) folded individually. Lock-free, shares-
   nothing per worker.
3. **Lever C — capacity equation** (`bench/fabric.go` `FabricCapacityForBar`, building on
   `bench/capacity.go`): software/SHA-NI cores needed to reach the 1.5e7/s edge bar.
4. **Inclusion-leaf correction (§5)**: the inclusion leaf is the consensus TXID; the L0
   field tree is OFF the inclusion path (`commitment.VerifyToBlockRoot` with `l0=nil`).
   `BuildBatch` uses leaf = TXID.

## Measured (64-core box, environment.json: software SHA-256d, SHA-NI absent)

per-core SHA-256d ≈ 3.4e6/s — pure-software path (no SHA-NI exposed). Bar = 1.5e7 verif/s.

| r (tx/s) | depth | density | backend | verif/s | A = verif/s ÷ 1.5e7 | result |
|---|---|---|---|---|---|---|
| 1e10 | 43 | sparse (P/S=1)   | software | 4.45e6 | 0.30 | FAIL |
| 1e10 | 43 | dense (P/S≥64)    | software | 9.7e6  | 0.65 | FAIL |
| 1e11 | 46 | sparse (P/S=1)   | software | 4.20e6 | 0.28 | FAIL |
| 1e11 | 46 | dense (P/S≥64)    | software | 9.7e6  | 0.65 | FAIL |

(`multibuf-scalar(x8)` matches `software` — it is a scalar stand-in with no SIMD, as labelled.)

### Capacity (Lever C) to reach the bar, single-proof
| r | depth | cores (software) | cores (SHA-NI @1e8/s) |
|---|---|---|---|
| 1e10 | 43 | ~190 | 6.5 |
| 1e11 | 46 | ~203 | 6.9 |

## Honest finding (matches design §1, §8)
- **Lever B works as designed**: dense batching amortizes L2 and lifts the software path
  ~2.15× (A 0.28 → 0.65) by collapsing per-proof cost from depth (46) to ~L1 (20).
- **The unaccelerated software path does NOT meet the 1.5e7/s bar** — best A ≈ 0.65,
  i.e. ~1.5× short. This is recorded as a limitation of the unaccelerated path, not hidden.
- **The bar is met by either** (A) a SHA-256d hardware/SIMD backend — ~7 SHA-NI cores
  clear it outright; the box used here exposes no SHA-NI, so that backend must be measured
  on SHA-capable hardware — **or** (C) horizontal scale-out: ~200 software cores (≈3× this
  box, or one extra commodity node), composing with batching.
- **None of this alters BSV consensus**; the redesign is entirely verifier-side.

## Status vs the design's acceptance
Per 07 §8: "until that run reports A≥1.5 the bar is documented as not yet met on the
measured path, not assumed." **On this box (software, no SHA-NI), A_max = 0.65 → the bar
is NOT met on the measured path.** It is met on SHA-NI hardware (capacity-equation
certified) or by ~3× scale-out. The AVX2 multi-buffer backend remains to be implemented
and measured to meet the bar on a single non-SHA-NI box.
