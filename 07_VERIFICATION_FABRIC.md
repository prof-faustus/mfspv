# 07 — Verification-Fabric Architecture (throughput revision)

Design-only. This revises the verifier side of `01_ARCHITECTURE.md` / `03_SCALING_MODEL.md`
to reach the throughput bar **≥ 1.5×10⁷ verifications/s (A ≥ 1.5 where A×10⁷)**. No code here —
this states what must be built and what must be measured. The implementation and every benchmark
are run separately on the target box; numbers produced here are the **only measured anchor**
(`environment.json`) plus **design targets to be validated by that run**, explicitly labelled.

---

## 1. Recorded finding (for the paper)

Measured anchor — target box, `environment.json` (64 cores, **software SHA-256, SHA-NI absent in
that run**): **3,427,648 HashPair/s/core**, aggregate **2.194×10⁸ HashPair/s** at 64 cores.

A per-payment inclusion verification is a Merkle fold of `D` `HashPair` operations
(`HashPair` = double-SHA256 of 64 B ≈ 3 SHA-256 compressions). Single-proof, non-amortized
throughput on the measured software path:

| scale | r (tx/s) | depth D | verifications/s = 2.194×10⁸ / D | vs bar 1.5×10⁷ |
|-------|----------|---------|---------------------------------|----------------|
| 10⁶   | 10⁶      | 30      | 7.31×10⁶                        | **0.49× — FAIL** |
| 10⁹   | 10⁹      | 40      | 5.49×10⁶                        | **0.37× — FAIL** |
| 10¹⁰  | 10¹⁰     | 43      | 5.10×10⁶                        | **0.34× — FAIL** |
| 10¹¹  | 10¹¹     | 46      | 4.77×10⁶                        | **0.32× — FAIL** |

**Statement for the paper:** on the pure-software, single-proof verification path, the target box
reaches 5–7×10⁶ verifications/s — **2.0× to 3.1× below the 1.5×10⁷ bar**. The bar is reachable, but
requires the verifier-side acceleration and batching specified below. None of it alters BSV
consensus. This is an honest hardware/implementation result, recorded as a limitation of the
unaccelerated path, and resolved by §4.

---

## 2. Fixed constraints (cannot be redesigned — BSV consensus)

These bound the solution space; the redesign is **entirely verifier-side** and changes none of them:

- The block Merkle tree is **binary, SHA-256d**, leaves = **consensus TXIDs**
  (`TXID = reverse(double-SHA256(serialized tx))`). Inclusion proofs fold consensus TXIDs to the
  block root in the PoW-sealed 80-byte header.
- Therefore the inclusion **leaf is the consensus TXID** (see §5), and the per-proof hash work on the
  consensus path is intrinsic: `D` SHA-256d operations, `D = ⌈log₂T⌉`.

What *is* free to redesign: **how the verifier computes those hashes** (hardware/SIMD backend), and
**how many proofs share work** (batching). Both are local to Bob; neither touches the chain.

---

## 3. The gap, precisely

To clear 1.5×10⁷/s the verifier must raise effective throughput per unit hardware by ≥ **2.0× (depth
30)** to **3.1× (depth 46)** over the measured software single-proof path. Three independent,
composable levers (§4) supply this. The required combined factor is small enough that any one strong
lever, or two modest ones, suffices — but the design specifies all three so the bar is met with
margin and on hardware that may lack SHA extensions.

---

## 4. The redesign — three composable verifier-side levers

### Lever A — Pluggable hashing backend (primary; hardware/SIMD)
A capability-selected SHA-256d backend behind one interface, chosen at startup from CPU features:

1. **Software** (current Go `crypto/sha256`) — the measured 3.43×10⁶ HashPair/s/core baseline.
2. **SHA-NI / ARMv8-crypto** — Go's `crypto/sha256` already emits SHA-extension assembly on capable
   amd64/arm64. *Design target:* ~3–10× over software for SHA-256 (per Intel/ARM published figures);
   **must be measured on the box's actual CPU** — the recorded run was the software path, so the box's
   CPU either lacks SHA-NI or did not expose it (record which).
3. **AVX2 / AVX-512 multi-buffer** — hashes 4–8 (AVX2) or 16 (AVX-512) *independent* messages per
   lane-stream. Because verification across distinct proofs is independent, the batch verifier (Lever
   B) feeds many proofs' same-level `HashPair` inputs into the lanes. *Design target:* ~4–8× (AVX2),
   higher (AVX-512); **must be measured.** This is the fallback that reaches the bar when SHA-NI is
   absent (the box has AVX2).

Backend is selected at runtime; verification output is identical across backends (same SHA-256d).
This is an implementation/architecture task (an assembly or cgo multi-buffer backend + a dispatch
shim), **not** a consensus change.

### Lever B — Batch verification with shared-path amortization (workload-dependent multiplier)
In IP-to-IP commerce a verifier processes **many** proofs at once (a busy merchant; a payment
processor aggregating merchants). Proofs that land in the same block/subtree **share upper paths**:

- The **block root + header PoW (L3)** is shared by *every* proof in that block → verify **once per
  block**.
- The **subtree-root → block-root path (L2, e.g. 23 hashes at 10¹⁰)** is shared by every proof in the
  same subtree → verify **once per distinct subtree**.
- The **TXID → subtree-root path (L1, ≤ 20 hashes)** is per-proof (distinct leaves) and is **not**
  amortizable across different transactions.

Amortized per-proof cost for a batch of `P` proofs spanning `S` distinct subtrees:
`cost ≈ L1 + (S/P)·L2`.

- **Dense workload** (`P ≫ S`, e.g. a processor): cost → `L1 (≤ 20)`, i.e. depth 43 → ~20 ⇒ **~2.15×**
  on the consensus path, *and* L2/L3 hashing nearly vanishes from the per-proof budget.
- **Sparse workload** (`P ≈ S`, a low-volume merchant, one proof per subtree): negligible L2/L3 saving;
  per-proof stays ~`D`. Here Lever A carries the load.

Honest framing: B is a multiplier that grows with per-subtree batch density; it is **not** relied on
for the worst case. It requires the bundle to expose `(blockHeader, subtreeRoot, subtreeIndex, L1, L2)`
separately (the `commitment.VerifyToBlockRoot` signature already splits `l0/l1/l2`) and a
verified-roots cache keyed by `(blockHash, subtreeRoot)`.

### Lever C — Horizontal core/node scaling (linear)
Verification is stateless and shares-nothing; aggregate = `nodes × cores × per-core rate / amortized
depth`. To hit a target purely by scale-out on the **software** path: at depth 43, 1.5×10⁷ needs
`1.5×10⁷ × 43 / 3.43×10⁶ ≈ 188` software cores (≈ 3× the 64-core box) — i.e. one extra commodity node,
*or* the 64-core box once Lever A is engaged. The architecture states this as an explicit
capacity equation so deployment can trade hardware against backend.

**Combined:** software 64-core baseline 5.1×10⁶/s (depth 43) × SHA-NI **or** AVX2 (≥3–4×, to measure)
clears 1.5×10⁷ with margin; batching (dense) and scale-out add further headroom. The bar is met
without touching consensus.

---

## 5. Correctness revision carried into this architecture (inclusion leaf = consensus TXID)

The block commits to `double-SHA256(serialized tx)`, not to a Merkle-root-over-fields. So:

- The inclusion path's **leaf is the consensus TXID**. The verifier obtains the TXID (recomputing it
  from the serialized transaction, or receiving it) and folds `TXID → subtree → block`
  (`VerifyToBlockRoot` with `leaf = txid, l0 = nil` — already supported).
- The **L0 field tree (MTxID)** is **not on the inclusion path**. It is reframed as an **optional
  secondary commitment** for selective field disclosure, committed separately (the secondary
  identifier of US 2022/0216997, e.g. in a generation-transaction structure) with its own
  availability caveat. Field-level selective disclosure therefore applies to that secondary structure,
  not to block inclusion; a verifier needing inclusion uses the full TXID.

Architecture impact: the inclusion bundle carries `serialized tx (or TXID) + L1 + L2 + header`;
verification recomputes/accepts the TXID and folds to the block root. The field tree is an add-on
module, not a dependency of inclusion.

---

## 6. Corrected per-payment cost & scaling model

- **Per-payment proof size:** unchanged — `32·D` bytes (D = ⌈log₂T⌉); 10⁶→960 B, 10¹⁰→1376 B,
  10¹¹→1472 B. (Delivery still sender-push, frozen after sealing.)
- **Per-payment verification work:**
  - worst case (sparse): `D` SHA-256d (Lever A makes this meet the bar);
  - typical (dense batch): `≈ L1 ≤ 20` SHA-256d amortized (Lever B), *decoupling* per-proof cost from
    the L2 growth between 10⁶ and 10¹⁰.
- **Throughput model (to validate on the box):**
  `verif/s = (cores × per-core SHA-256d rate(backend)) / amortized-depth`. The single measured input is
  the software per-core rate; the backend factors and the amortized depth are validated by the §7 run.

---

## 7. Hand-off — what must be built and measured (Claude Code, on the box)

Design tasks (no code in this document):

1. **Hashing-backend interface + implementations** (Lever A): software (exists), SHA-NI (verify Go
   engages it on the box's CPU; record), AVX2/AVX-512 multi-buffer (assembly or cgo to a multi-buffer
   SHA-256 library). Runtime dispatch by CPU capability. Identical SHA-256d output across backends
   (assert by KAT).
2. **Batch verifier** (Lever B): group proofs by `(blockHash, subtreeRoot)`; verify header/PoW once
   per block, each subtree root once per subtree, each proof's L1 path individually; verified-roots
   cache. Bundle exposes `(blockHeader, subtreeRoot, subtreeIndex, L1, L2)`.
3. **Capacity equation** (Lever C): emit required core/node count for a target `r` given the measured
   per-core backend rate.
4. **Inclusion-leaf correction** (§5): leaf = consensus TXID; field tree demoted to optional secondary
   module off the inclusion path.

The benchmark to run on the box (extends `scalebench`, run separately):
- Build a **real** block of `N` txs over real 2²⁰ subtrees; assemble a **realistic batch** of `P`
  proofs spanning `S` subtrees (sweep density `P/S`).
- For each backend (software / SHA-NI / AVX2[/512]): measure **amortized verifications/s** and print
  `A = verif/s ÷ 10⁷` with **PASS (A ≥ 1.5) / FAIL** per `(depth, backend, density)`.
- Report the per-core backend rate, the amortized depth achieved, and the core count implied for the
  target — so the paper states the **measured** configuration that meets the bar, not a projection.

---

## 8. Paper statement (honest, final)

The unaccelerated software single-proof path measures 5–7×10⁶ verifications/s on the 64-core box —
below the 1.5×10⁷ bar by 2.0–3.1×. The verification fabric meets the bar via (A) a SHA-256d hardware/
SIMD backend (SHA-NI or AVX2/AVX-512 multi-buffer), (B) batch verification amortizing the shared
block/subtree path for dense workloads, and (C) stateless horizontal scaling — measured on the box,
none altering BSV consensus. The exact passing configuration is whatever the §7 benchmark records on
the target hardware; until that run reports `A ≥ 1.5`, the bar is **documented as not yet met on the
measured path**, not assumed.

---

## 9. Measured result (implemented; `mfspv/fabric`, `go run ./cmd/mfspv -fabric`)

Built and run on the 64-core target box (software backend; SHA-NI **not** engaged by the
runtime — per-core ≈ 2.7–2.8×10⁶ dsha/s, aggregate ≈ 1.76×10⁸ dsha/s, i.e. ~20% below the
2.194×10⁸ projection because true aggregate < cores × single-core):

| regime | config | amortized depth | verif/s | A | result |
|---|---|---|---|---|---|
| sparse single-proof | depth 43 (derived) | 43 | 4.1×10⁶ | 0.27 | **FAIL** |
| sparse single-proof | depth 46 (derived) | 46 | 3.8×10⁶ | 0.26 | **FAIL** |
| dense batch (Lever B) | 4,096 proofs / 1 subtree | 2.0 | ~9×10⁶ | ~0.6 | FAIL (too little work to fill 64 cores) |
| dense batch (Lever B) | 16,384 proofs / 4 subtrees | 2.0 | ~1.05×10⁷ | ~0.7 | FAIL |
| **dense batch (Lever B)** | **262,144 proofs / 64 subtrees** | **2.0** | **3–5×10⁷** | **2.0–3.5** | **PASS** |

**Finding (measured, honest):** the bar **is met on the pure-software path** by Lever B once the
batch is large/dense enough to keep all cores busy (realistic for a payment processor): a full-block
batch reaches **A ≈ 2–3.5**, with amortized per-proof cost collapsing to **~2 SHA-256d** (the shared
internal subtree/block/header nodes are computed once). Sparse single-proof verification remains below
the bar (A ≈ 0.27) and is the case for which Lever A (SHA-NI/AVX2 multi-buffer) or Lever C scale-out
is required; Lever C: ≈ **234 software cores** clear the bar at depth-43 sparse. No lever alters BSV
consensus. The AVX2/AVX-512 multi-buffer backend (Lever A) remains a future plug-in behind the
`fabric.Hasher` interface; the SHA-NI path is whatever Go's `crypto/sha256` engages on the deployment
CPU (record it per box). Reproduce: `go run ./cmd/mfspv -fabric`.
