# 06 — Evaluation Design (publication-grade)

This is the authoritative experimental-evaluation design for MF-SPV. It supersedes the
functional/adversarial checklist in `04_TEST_PLAN.md` (whose `T*`/`A*` IDs are referenced and
extended here) and is written to the standard expected of an empirical-evaluation section and
artifact submission at a top ACM venue (CCS / IMC / artifact-evaluation track).

**Governing discipline (non-negotiable, applied throughout):**

1. **No claim without a falsifiable experiment.** Every empirical claim in `PAPER.md` is restated
   as a hypothesis `H1` with an explicit null `H0` that the experiment *can reject*, a metric, and a
   **pre-registered** pass/fail predicate fixed before any run.
2. **Measured / Derived / Simulated are labelled per result and never conflated.** A single machine
   cannot build a 6×10¹²-leaf block; the design states exactly what is *measured*, what is
   *derived* from measured primitives by a stated closed form, and what is *simulated* on real but
   feasibly-sized structures. Any projection to 10⁶–10¹⁰ tx/s is **Derived**, with its measured
   inputs and formula shown.
3. **No invented numbers.** This document specifies *what to measure and the predicate*. It contains
   no measurement results. Numbers the artifact currently prints (e.g. a per-core SHA-256d rate) are
   **outputs to be regenerated** by the reproduction harness, not claims made here.
4. **Security pass = REJECTION.** Every adversarial experiment asserts that a forgery / invalid input
   is refused. A Monte-Carlo forgery test bounds the *implementation* false-accept rate; it is **not**
   a cryptographic proof — soundness rests on the stated reduction to SHA-256d (§5.1).
5. **Deterministic facts get exact checks, not statistics.** Integer laws (e.g. `depth = ⌈log₂T⌉`)
   are verified by exact equality over a grid plus a proof-by-construction note. Statistics are used
   **only** for quantities measured with noise (latency, throughput).
6. **BSV only.** No BTC parameter, code path, or library appears in the artifact or the harness.

---

## 1. Evaluation questions

- **EQ1 (Correctness).** Does every level of the commitment hierarchy build and verify correctly, and
  do the primitives match independent references and published test vectors?
- **EQ2 (Soundness/Security).** Are forged inclusion proofs, invalid chains, ungated L4 anchors,
  coverage-gap queries, evidence-free alerts, and spent-output acceptances all *rejected*?
- **EQ3 (Scaling laws).** Do the proof-size and verification-cost laws hold, and is the
  verification cost provably **logarithmic in T, not linear** — to the point of statistically
  rejecting the linear-in-T model?
- **EQ4 (Capacity/throughput).** What is the measured per-payment verification cost and its
  core-parallel scaling, and what network sealing rate does a given `r` *derive* (Result 4.4)?
- **EQ5 (Delivery model).** Is the per-payment proof network cost zero under push (R4), and how does
  it compare to the pull baseline?
- **EQ6 (Honesty/limitations).** Are the disclosed limitations (absent-period gaps,
  inclusion ≠ double-spend, non-constant-time signer, MockNode-not-Teranode) *exercised and
  visible in code*, not merely prose?
- **EQ7 (Reproducibility).** Can an independent reviewer regenerate every table/figure from raw
  measurements with fixed seeds, within a stated tolerance, on commodity hardware?

---

## 2. Claims → Hypotheses → Experiments matrix (the spine)

Columns: paper claim · `H1` · falsifiable `H0` · metric · pre-registered predicate · class
(M=measured, D=derived, S=simulated) · primary validity threat.

| ID | Claim (PAPER.md) | H1 | H0 (rejectable) | Metric | Predicate (pass) | Class | Threat |
|----|------------------|----|-----------------|--------|------------------|-------|--------|
| X-R1 | proof = 32·depth; +416 B over 1e6→1e10 | size is exactly 32·⌈log₂(600r)⌉ | size deviates from 32·depth for some r | bytes(serialized core path) | exact equality at all r in grid; Δ(1e6,1e10)=416 B | D+S | extrapolation |
| X-R2 | header dataset ≈4.2 MB/yr, constant in r | dataset = 80·`blocks/yr`, ∂/∂r = 0 | dataset varies with r | bytes/yr | identical across all r; equals 80·52,560 | D | calendar/block-interval assumption |
| X-R3 | verify ∝ depth (log T), **not** T | latency ≈ a+b·log₂T, b>0; linear-in-T rejected | latency linear in T fits as well or better | ns/verify vs depth and vs T | F-test/ΔAIC rejects linear-in-T at α=0.01; R²(log) ≥ 0.98 | M+S | cache effects at large trees |
| X-R4 | push proof network bytes = 0 | bytes pulled by verifier = 0 under push | verifier must fetch >0 bytes | wire bytes in push path | exactly 0; pull baseline >0 and grows with depth | M | model realism of "already held" |
| X-DL | depth = ⌈log₂T⌉ (L1/L2 split adds no hashes) | integer equality for all r | some r gives depth ≠ ⌈log₂T⌉ | int depth from real tree | exact equality over grid 1e6…1e12 | S | none (deterministic) |
| X-CAP | seal needs ≈2·T·h/600 hashes/s | network hash-rate = 2·(measured hashes/leaf)/600·r | rate deviates from formula | derived hashes/s | matches formula given measured per-hash cost | M+D | Teranode horizontal-scale assumption (inherited) |
| X-FROZEN | L0–L3 path byte-frozen after sealing | bytes identical pre/post Reanchor | any path byte changes on Reanchor | byte-diff | byte-identical; only anchor/selection changes | M | — |
| X-PRIV | reveal one field, not whole tx | L0 path discloses only the revealed field | other field bytes recoverable from bundle | field bytes in serialized bundle | only revealed field + its path present | M | — |
| S1…S9 | §7 security properties | see §5 | see §5 | rejection rate / bound | all forgeries REJECTED; §5 bounds met | M | adversary-model scope |

Every row maps to a concrete experiment in §4–§6. A row with no green predicate is a failing claim.

---

## 3. Methodology and reproducibility controls

### 3.1 Platform specification and environmental controls
The harness records, into a machine-readable `environment.json` emitted with every run:
CPU model and microarchitecture; physical/logical core count; base/turbo frequency; **CPU governor
forced to `performance` and turbo/boost disabled** for timed runs (recorded either way); **SHA-NI
presence detected and reported** (the SHA-256d path differs by ~50× between software and SHA-NI, so
both are reported and never mixed); RAM and last-level-cache size; OS, kernel, libc; Go toolchain
version (1.26) and `GOARCH/GOOS`; git commit hash of the artifact; container image digest.
Timed benchmarks run pinned to isolated cores (`taskset`/`isolcpus` or a cgroup), single NUMA node,
with `GOMAXPROCS` fixed and stated, and `GOGC` fixed (default 100) with an alternate `GOGC=off`
sensitivity run reported.

### 3.2 Timing protocol
All latency/throughput use `testing.B` plus a custom monotonic-clock harness:
- A warm-up phase whose samples are discarded (stated count); steady-state thereafter.
- **≥10 independent process invocations** per configuration; within each, `b.N` auto-scaled by the
  Go benchmark framework. `b.ReportAllocs()` always on.
- Report **median, p1, p99, and IQR** of the per-invocation distribution, plus **coefficient of
  variation**; never a bare mean. Aggregate across configurations with the **geometric mean**.
- Comparisons (e.g. push vs pull, sw vs SHA-NI, before/after an optimisation) use **`benchstat`**
  over the ≥10 runs and report the p-value and the CI on the delta; a difference is reported only if
  `benchstat` shows it at p<0.05.
- Outlier policy: **none discarded**; the full distribution is published. A CV above a
  pre-registered ceiling (e.g. 0.10 for microbenchmarks) marks the run *environmentally unstable* and
  it is rerun, not trimmed.

### 3.3 Statistical analysis plan
- Point estimates always accompanied by a 95% CI (bootstrap over invocations).
- **Monte-Carlo soundness (S1, S3, S9):** with `K` independent random forgeries and **zero**
  accepted, the one-sided upper confidence bound on the true implementation false-accept probability
  `p` at confidence `1−α` is `p_upper = 1 − α^(1/K)` (Clopper–Pearson, 0 successes). `K` is chosen to
  hit a pre-registered `p_upper` target (e.g. `K = 10⁶ ⇒ p_upper ≈ 4.6×10⁻⁶` at 99%). This bounds
  *implementation* error only; the cryptographic guarantee is the §5.1 reduction.
- **Scaling-law falsification (X-R3):** fit two models over the feasibly-built tree sizes —
  `latency = a + b·log₂T` and `latency = a' + b'·T` — and **reject linear-in-T** by an F-test on
  nested/non-nested comparison and by ΔAIC ≥ 10; require `R²(log) ≥ 0.98` and `b'` not significantly
  positive once `log₂T` is in the model. Pre-registered before measurement.
- All thresholds in this document are **pre-registered**; changing one after seeing results is a
  protocol violation and must be disclosed.

### 3.4 Determinism and seeds
Synthetic data (random fields, tree shapes, forgery attempts) is generated from a **fixed,
recorded RNG seed** per experiment; the same seed reproduces the same inputs. Test execution is
order-independent (no shared mutable global state); `go test -shuffle=on` must pass. The reduction
target Go version is pinned so `go test ./...` is bit-deterministic for correctness tests.

---

## 4. Correctness evaluation (EQ1)

### 4.1 Known-answer tests (KAT)
- **SHA-256d:** verify `DoubleSHA256` against published Bitcoin/BSV SHA-256d test vectors (the
  implementer pulls the canonical vectors; no vector hex is invented here). Predicate: exact match.
- **secp256k1 / ECDSA / RFC 6979:** verify `crypto.Sign`/`Verify` against the **published RFC 6979
  deterministic-ECDSA test vectors** for secp256k1 and against known BSV signature vectors; verify
  low-S normalisation and 33-byte compressed-key (de)serialisation against vectors. Predicate: exact
  match; every produced `S ≤ n/2`.

### 4.2 Property-based testing (fuzz/quick)
Using Go's native fuzzing and a property runner (`testing/quick` or `gopter`) with shrinking, over
**≥10⁵ generated cases** per property and a fixed seed:
- **P1 round-trip:** ∀ field sets and indices, `Fold(LeafForField(f), MTxIDPath(...)) == MTxID`, and
  the composed `VerifyToBlockRoot` accepts a genuine L0–L2 path. (`T1.1`)
- **P2 determinism:** `BuildMTxID(fields)` twice ⇒ identical root and layers. (`T1.4`)
- **P3 reconstruct:** drop `layers`, rebuild from root+fields ⇒ identical root (US 2022/0216997
  [0166]). (`T1.5`)
- **P4 depth bound:** any generated path length ≤ 255; a crafted >255 path is a hard error
  (`ErrDepthOverflow`). (`T1.6`, I-C3)
- **P5 minimal reveal (privacy):** the serialized bundle for a single revealed field contains the
  bytes of *only* that field; no other field's bytes are recoverable (byte-scan assertion). (X-PRIV)
- **P6 subtree cap:** any accepted L1 path has length ≤ 20. (I-TA2)
Go fuzz targets additionally run in CI for a fixed wall-clock budget; any crash/seed is committed.

### 4.3 Differential (oracle) testing
Build a deliberately trivial, independent reference Merkle implementation **in the test package**
(naive recursive, separate author/logic) and assert `commitment.MerkleRoot` agrees with it on
≥10⁵ random leaf-multisets **including odd-cardinality levels** (the odd-node duplication rule is the
historical source of Bitcoin Merkle bugs and must be cross-checked, not assumed). Predicate: roots
identical on every case; any divergence is a blocking defect.

### 4.4 Coverage and mutation testing (test adequacy)
- Report `go test -coverprofile` per package. Coverage is **necessary, not sufficient**, and is
  explicitly subordinated to mutation score.
- Run a Go mutation tester (`gremlins` or `go-mutesting`) on the security-critical packages
  (`commitment`, `bundle`, `crypto`, `accumulator`, `walletbob`). **Pre-registered gate:** overall
  mutation score ≥ 0.85, and **every** mutant that flips a comparison/boolean in `Fold`, `Verify*`,
  `VerifyToBlockRoot`, `Decide`, `VerifyAnchor`, or the low-S/`onCurve` checks **must be killed**
  (a surviving security-critical mutant is a blocking defect — it means a test that should fail does
  not). Report the mutation report alongside coverage.

---

## 5. Security evaluation (EQ2) — every predicate is REJECTION

Each experiment states the adversary, the procedure, and the pass predicate. Adversary is
computationally bounded; cannot break SHA-256 (collision/2nd-preimage) or forge ECDSA; may craft
arbitrary inputs, alternative chains, malformed bundles, and unattested alerts; may corrupt
< majority hash power.

- **S1 — Inclusion soundness (forgery).** *Procedure:* generate `K=10⁶` forged `(leaf, path)` not
  equal to any true sibling set (random siblings; random `Right` bits; random leaf), plus a
  systematic **single-bit flip** of every element of every genuine path in the corpus. *Predicate:*
  **0** accepted by `Verify*`/`VerifyToBlockRoot`; report Clopper–Pearson `p_upper` (§3.3).
  *Note (honest):* this bounds implementation error; the guarantee that a *successful* forgery
  requires a SHA-256d collision is the cryptographic reduction, stated, not measured. (`A1`)
- **S2 — Second-preimage / field reordering.** *Procedure:* take a valid tx, move a field to another
  index (or swap two), keep claimed root. *Predicate:* `VerifyMTxIDPath`/`VerifyToBlockRoot`
  **rejects** (leaf-index binding). 
- **S3 — Merkle duplication (CVE-2012-2459 class).** *Procedure:* construct inputs that exploit the
  odd-node self-duplication rule to attempt a second valid-looking path to the same root for a
  non-member, and attempt the classic duplicate-subtree mutation. *Predicate:* **rejected**; and the
  design records the structural defense (leaf/tx-count is fixed by the Teranode subtree of known
  size; a verifier never accepts a path implying a different leaf count). *Honest note:* if any
  crafted input is accepted, that is a blocking finding to be reported, not hidden. (extends `A1`)
- **S4 — Chain soundness.** *Procedure:* present an alternative header chain not on the
  most-work chain (no majority work). *Predicate:* header **not Contained**, **not anchored**, bundle
  **rejected**. (`A2`)
- **S5 — L4 anchor gating.** *Procedure:* call `VerifyBlockInChain` with an `accRoot` that has **not**
  passed `VerifyAnchor`. *Predicate:* treated as **unverified** (coupling enforced); a test asserts an
  ungated accept is impossible. (I-A2, `T2.2`)
- **S6 — Absent-period gap honesty.** *Procedure:* committed-height set with holes; query a height in
  a hole. *Predicate:* `inGap == true`, **never** a false "in chain"; `CoverageGaps` returns the real
  gaps. (I-A3, `T2.3`) — mandatory; this is the disclosed limitation made executable.
- **S7 — DoS resistance.** (a) *Malformed-bundle flood:* feed N malformed bundles; *predicate:* each
  rejected at the **first failing hash**, **zero network calls**, and measured CPU per rejected bundle
  is `O(depth)` and bounded (report the curve vs depth). (b) *Alert flood without evidence:*
  *predicate:* unattested/evidence-free alerts **dropped** (I-DS1). (`A3`, `A4`)
- **S8 — Inclusion ≠ double-spend.** *Procedure:* a bundle for an output that is then spent.
  *Predicate:* `bundle.Verify` **still true** (inclusion holds) **and** `walletbob.AcceptPayment`
  returns `accepted=false` with `reason="double-spend:utxo-spent"`. The two outcomes coexisting is the
  property. (`T3.5`, `T4.4`, I-BB1)
- **S9 — Signature integrity.** *Procedure:* malleate `S → n−S` (high-S), random signature forgery,
  wrong-key verification. *Predicate:* high-S **rejected** (low-S canonical), forgeries **rejected**;
  Monte-Carlo over `K` random `(msg,sig)` ⇒ 0 accepted with reported `p_upper`.
- **S10 — No keys at till.** *Procedure:* attempt `walletbob.StorePrivateKey`. *Predicate:* always
  errors (`ErrNoKeysAtTill`); static check: the `Wallet` struct has no private-key field. (I-BB2,
  `T4.3`)

---

## 6. Performance and scaling evaluation (EQ3–EQ5)

### 6.1 Microbenchmarks (Measured)
Report, with §3.2 statistics, on the recorded platform:
- **SHA-256d throughput** (hashes/s/core), **software path and SHA-NI path separately**;
- `HashPair` and `Fold` latency as a function of **path depth d = 1…50**;
- `BuildMerkleTree` / `BuildMTxID` build time and allocations vs leaf count, up to the **largest
  feasibly-built tree** on the platform (state it, e.g. 2²⁰–2²⁴ leaves);
- `bundle.Serialize`/`Deserialize` size and time vs depth.

### 6.2 Edge verification throughput (Measured)
Per-payment `bundle.Verify` latency (p50/p99) at representative depths, and **core-parallel scaling**
from 1…N cores (verification is stateless ⇒ expected near-linear). *Predicate:* throughput scales
within a stated fraction of linear; per-payment latency is **independent of r** (depths differ only
by the log term). Report the speedup curve and parallel efficiency.

### 6.3 Depth-law confirmation (Simulated, exact)
A simulator builds **real** SHA-256d trees at feasible sizes and, for the target grid
`r ∈ {1e6,1e7,1e8,1e9,1e10,1e11,1e12}`, checks `depth == CeilLog2(600·r)` by **exact integer
equality** (no statistics — deterministic). It also confirms `proofBytes == 32·depth` (X-R1) and that
the L1/L2 split contributes no extra hashes (`log₂S + log₂(#subtrees) = log₂T`). *Predicate:* exact
equality at every grid point; `⌈6×10¹²/2²⁰⌉ = 5,722,046` (not the floor — this exact cell was a
corrected off-by-one and is a regression guard).

### 6.4 Scaling-law falsification (Measured + statistical) — the load-bearing EQ3 result
Over the feasibly-built sizes, regress measured `Verify` latency on `log₂T` and on `T` and **reject
the linear-in-T model** per §3.3 (F-test, ΔAIC ≥ 10, `R²(log) ≥ 0.98`). *Rationale:* this converts
"verification is logarithmic" from an assertion into a falsified-alternative result — the standard an
ACM reviewer expects. A failure to reject linear-in-T **fails the headline claim**.

### 6.5 Derived projection to 10⁶–10¹⁰ tx/s and the capacity model (Derived, explicitly)
The projection is **closed-form from §6.1 measured primitives**, not a large-scale run, and is
labelled Derived wherever printed:
- per-payment proof size and verify cost at each `r` from `depth(r)` and measured per-hash cost;
- **sealing capacity (X-CAP):** network-wide hash rate `≈ 2·(measured hashes/leaf)·r` per second
  across `⌈T/2²⁰⌉` subtrees/s, expressed in SHA-NI-core-equivalents from the measured SHA-NI rate.
  This is Teranode's horizontal-scale model; `r` is bounded by Teranode validation/propagation, **not**
  by SPV (Result 4.4). The Teranode-scales-horizontally premise is an **inherited assumption**, marked
  as such, not evaluated by this artifact.

### 6.6 Push-vs-pull (Measured) — R4
Instrument the push path and assert **wire bytes obtained by the verifier == 0**; emit, for contrast,
the bytes a pull verifier (legacy SPV / TxChain regime) fetches, and show it grows with depth.
*Predicate:* push == 0 exactly; pull > 0 and monotone in depth.

### 6.7 Header-dataset constancy (Derived) — R2
Compute `80 B · blocks_per_year` and show `∂/∂r = 0`. *Predicate:* identical across all `r`; equals
`80 · 52,560`. The block-interval/calendar inputs are stated BSV parameters (threat: §7).

### 6.8 Comparison framing (Computed, labelled)
Tabulate MF-SPV per-payment proof size vs (a) naive full-tx-Merkle SPV and (b) a FlyClient-style
header-sync cost at matched throughput, using the paper's arithmetic. Every cell labelled
**Computed** (not measured), with its formula. No competitor is re-implemented or benchmarked; claims
are confined to arithmetic each side agrees on.

---

## 7. Threats to validity (explicit, four-class)

- **Construct.** "Verification cost" is measured as single-bundle `Verify` CPU latency; it excludes
  the orthogonal double-spend layer by design (§9). "Header dataset" is the 80-byte-header sum, not
  on-disk index overhead.
- **Internal.** CPU frequency scaling, turbo, co-tenant noise, GC pauses → controlled (§3.1–3.2);
  CV ceiling flags instability. Synthetic-data shape may not match real field/tx distributions →
  property generators cover edge cardinalities; differential test guards the odd-node rule.
- **External (the big one).** Single-machine results are **extrapolated** to 10⁶–10¹⁰ tx/s by a
  *derived* model, not measured end-to-end; this is stated at every projected number. Software vs
  SHA-NI hash paths reported separately. The `teranode` package is a **MockNode** building real
  Merkle/accumulator structures, **not** a pinned production Teranode — wiring to a pinned revision is
  the outstanding integration step (01 §7 dep #2), and at-scale Teranode behaviour is an inherited
  assumption.
- **Conclusion.** Statistics applied **only** to noisy measured quantities; deterministic laws use
  exact equality. Pre-registered thresholds prevent post-hoc tuning. Monte-Carlo soundness bounds
  *implementation* error, not cryptographic strength.

---

## 8. Reproducibility and ACM artifact badges (EQ7)

Target all three ACM badges:
- **Artifacts Available.** Public repository at a citable archive (Zenodo DOI); license stated;
  commit hash recorded in `environment.json`.
- **Artifacts Evaluated — Functional.** `go test ./...` builds and passes with **zero external
  dependencies** (offline), deterministic under `-shuffle=on`; documented structure; the
  functional/adversarial suite (`04_TEST_PLAN` `T*`/`A*`, here §4–§5) runs in a stated wall-clock
  budget on commodity hardware.
- **Results Reproduced.** A single entry point (`make reproduce` / `go run ./cmd/mfspv -bench`)
  regenerates **every table and figure** from raw measurements with the fixed seeds, writes
  `environment.json`, and prints each result tagged M/D/S. Each reproduced figure ships an **expected
  value and a tolerance band** (e.g. latency within the reported CI; all exact/integer and security
  predicates must match exactly). Expected total runtime is stated. A `claims.csv` maps every
  `PAPER.md` claim ID (§2) to the test/figure that establishes it, so a reviewer can audit
  claim-by-claim.

A reviewer's path: clone → `go test ./...` (Functional) → `make reproduce` (Reproduced) → open
`claims.csv` and confirm each green predicate.

---

## 9. Explicitly NOT evaluated (honest scope)

- **End-to-end point-of-sale latency / 0-conf safety.** Bounded by the live double-spend layer, which
  is **orthogonal** to MF-SPV (§4.4 of the paper); not claimed, not measured here.
- **Real Teranode at scale.** MockNode only; see §7 external threat.
- **Side-channel resistance of the signer.** The `crypto` secp256k1 is `math/big` and **not
  constant-time** (disclosed in code). Out of scope; production deployment swaps in the node's audited
  secp256k1. MF-SPV's soundness claims do not rest on the signer.
- **Network / IPv6-multicast alert layer at scale.** The `dsalert` evidence-gating logic is tested
  (S7b); wide-area multicast propagation behaviour is not.
- **Economic calibration of τ.** `RiskPolicy.Tau` is a merchant input; choosing its value is a policy
  question, not an artifact claim.

---

## 10. Acceptance gate ("ACM-worthy" pass)

The evaluation passes iff **all** hold, with no exceptions silently waived:

1. EQ1: all KATs match; P1–P6 pass over ≥10⁵ cases each; differential test agrees on every case;
   mutation score ≥ 0.85 with **zero** surviving security-critical mutants.
2. EQ2: S1–S10 every predicate is REJECTION; S1/S3/S9 report Clopper–Pearson `p_upper` at the
   pre-registered target with 0 accepted; S6 gap-honesty holds.
3. EQ3: X-DL exact at every grid point; **linear-in-T rejected** (F-test + ΔAIC ≥ 10, R²(log) ≥ 0.98).
4. EQ4–EQ5: edge throughput scales near-linearly and is r-independent; X-CAP matches the derived
   formula from measured per-hash cost; push bytes == 0 with a growing pull baseline.
5. EQ6: every disclosed limitation is exercised by a passing test (S6, S8, S10) and the M/D/S label
   is present on every reported number.
6. EQ7: `go test ./...` deterministic and green; `make reproduce` regenerates all results within
   tolerance; `claims.csv` maps every claim to its evidence.

Any failing deterministic/security predicate, any surviving security-critical mutant, or any
unreproducible figure is a **blocking** defect — not a caveat.
