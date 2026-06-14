# Merkle-Forest SPV: Sender-Held Inclusion Proofs for Simplified Payment Verification at 10⁶–10¹⁰ Transactions per Second

**Status:** design + analysis + **reference implementation with a passing test suite**. A complete, zero-dependency Go implementation of the construction now exists (packages `commitment, crypto, accumulator, teranode, bundle, payment, walletalice, walletbob, dsalert, bench`; 61 tests). Every falsifiable scaling prediction in §6 is reproduced by the simulator (`mfspv/bench`), and every security property in §7 is encoded and asserted by a rejection test (`04_TEST_PLAN.md` T1–T7, A1–A5, and the red-team suite RT-1…RT-7 in `SECURITY.md`). What is **not** claimed: production throughput benchmarks — the performance figures are (i) arithmetic derivations and (ii) single-machine reference measurements (per-core hash rate, edge verification rate), used to derive capacity, not a deployed-network measurement. Transaction *ordering* at scale is Teranode's responsibility and is bounded by Teranode, not by this construction (§4.4, §6 R5).

**Scope:** BSV / Teranode only. No Bitcoin-Core (BTC) parameter, code path, or assumption is used; where a quantity is BSV-specific (80-byte header, ~600 s block) it is marked.

---

## Abstract

Simplified Payment Verification (SPV) as described in the Bitcoin white paper is a two-stage pipeline: establish that a header is on the most-work chain, then prove a transaction is inside that header's block. The light-client literature of the last decade has almost entirely optimised the first stage — compressing chain synchronisation from linear to sublinear (FlyClient [L1], the PoPoW family and recursive-SNARK clients surveyed in [L2]). We show by direct arithmetic that for BSV this stage is not the bottleneck: with 80-byte headers and ~10-minute blocks the entire header dataset is ~4.2 MB/year and is **independent of transaction rate**, so the prize those protocols compete for does not grow as throughput scales to 10⁶–10¹⁰ tx/s, and is bought at the price of a stronger trust assumption and a header-format fork.

We instead optimise the second stage and the *delivery model*. We specify **Merkle-Forest SPV (MF-SPV)**: a five-level Merkle commitment hierarchy that already exists inside Teranode (transaction fields → TXID → subtree root → block root → header), extended at the field level by nChain's MTxID construction [P1] and, optionally, by a header accumulator committed off-header in the generation transaction. Inclusion proofs are assembled once by the payer and travel **with the payment** (the "push" model, generalising Utreexo's owner-maintained proofs [L3]), so the per-payment network cost of the proof is zero and the historical portion of every proof is **frozen the moment its block is sealed** — an improvement over accumulators whose state mutates each block.

A derived model (not assumed) gives the headline result: across four orders of magnitude of throughput (10⁶ → 10¹⁰ tx/s) the inclusion proof grows by **13 hashes (416 bytes)**, from 960 to 1376 bytes, while the header dataset stays at 4.2 MB/year. We give a security analysis under the standard BSV minority-hash assumption — weaker than FlyClient's (c,L) assumption, hence a *stronger* guarantee — and we state, rather than hide, the limitation MF-SPV inherits from committing off-header: absent periods for non-participating miners ([P1] [0222]–[0223]).

---

## 1. Introduction

### 1.1 Problem

We want IP-to-IP payments between a payer (Alice) and a payee (Bob) in which Alice hands Bob everything needed to verify the payment — the transaction, its inclusion proofs, the relevant header — and Bob verifies locally and fast, with the construction holding as block contents scale to millions and ultimately ~10 billion transactions per second at an unchanged ~10-minute average block interval. The verification must be secure, robust, and efficient at that scale, and must run natively on Teranode [P5].

### 1.2 The two-stage view of SPV, and which stage matters for BSV

Standard SPV splits into:

- **Stage 1 — chain validity.** Is this header the tip of the most-work chain? Classic SPV downloads and proof-of-work-checks every header (linear in chain length).
- **Stage 2 — inclusion.** Is this transaction inside this header's block? Classic SPV supplies a Merkle path from the whole transaction to the header's Merkle root, forcing the verifier to obtain and hash the entire transaction to recompute its TXID.

The light-client literature optimises Stage 1. FlyClient [L1] replaces linear header sync with a logarithmic sampling proof over a Merkle Mountain Range committed in the header; the PoPoW/recursive-SNARK family surveyed in [L2] pursues the same axis by other means. **This paper's position is that Stage 1 is the wrong target for BSV, and Stage 2 plus the delivery model is the right one.** §2.3 and §5 give the quantitative argument.

### 1.3 Contributions

1. **A quantitative refutation, specific to BSV,** of the premise that sublinear chain sync is the scaling lever (§5, building on the BSV header arithmetic of [P3] and the FlyClient evaluation in [L1]). The header dataset is ~4.2 MB/year and does not grow with throughput; the saving sublinear sync offers is therefore bounded by a constant that is already negligible, and it costs a stronger assumption and a header fork.
2. **MF-SPV, a five-level commitment hierarchy** (§4.1) that requires no consensus change for its core (L0–L3), reusing Teranode's existing subtree→block structure [P5] and nChain's field-level MTxID [P1], with an optional off-header header accumulator (L4) for header-pruned verifiers.
3. **The frozen-proof property** (§4.2): once a block is sealed, the L0–L3 portion of any inclusion proof for a transaction in it never changes. This is the structural improvement over Utreexo [L3], whose accumulator and proofs mutate every block.
4. **A push delivery protocol** (§4.3) in which the payer holds and ships the proof bundle, generalising the author's Merchant→Customer→Merchant→Network flow [P3] and Utreexo's owner-maintained proofs [L3], making the per-payment proof network cost zero and refuting the *pull* premise of TxChain [L4] at the level of paradigm.
5. **A derived scaling model** (§6) with an exact target table the simulator must reproduce, turning every performance claim into a falsifiable prediction rather than an assertion.
6. **A security analysis** (§7) under the standard minority-hash assumption, with every required condition marked tested / demonstrated / asserted, and the absent-periods limitation stated explicitly (§8).
7. **A reference implementation** (zero external dependencies, Go) that realises L0–L4, the push protocol, the offline/PoS wallets, the alert layer, and the simulator, with a passing test suite that reproduces §6's table exactly through 10¹¹ tx/s and asserts §7's rejections.
8. **An adversarial (red-team) audit** (§7.8, `SECURITY.md`) that found and fixed three implementation-level vulnerabilities the prose model had glossed over — an L4 proof-of-work bypass, forgeable double-spend alerts, and signature malleability — each now closed and covered by a rejection test.

### 1.4 What this paper does not claim

It reports no benchmarks. It does not claim end-to-end payment latency in a fraction of a second: inclusion-proof verification is sub-millisecond by the model (§6), but end-to-end acceptance latency is bounded by the live double-spend check, which is **orthogonal to MF-SPV** and a property of Teranode and of merchant policy (§4.4, §8). Conflating the two would be the kind of claim that outruns what is shown.

---

## 2. Background

### 2.1 SPV

SPV lets a verifier holding only block headers confirm that a transaction is in a block, via a Merkle path of `log₂ s` hashes for a block of `s` transactions, without storing the chain. It establishes inclusion, not absence of double-spend; the latter requires either confirmations or a view of the spend set.

### 2.2 The author's prior constructions (primary, fully read)

- **Safe Low-Bandwidth SPV [P3].** The transaction flow is reordered to Merchant→Customer→Merchant→Network. The customer (Alice) is offline and holds her input transactions, keys, optional headers, and **the Merkle paths of her transactions**; the merchant (Bob) is online, holds headers, performs the SPV check locally, and broadcasts. The Merkle proof is explicitly a fail-fast against spam and error, **not** double-spend protection; double-spend is handled by UTXO-seen datasets, PoW-attested IPv6-multicast alerts, and a merchant risk parameter τ. No private keys sit at the till.
- **MTxID [P1].** A Merkle tree whose leaves are the individual *fields* of a transaction (previous-txid, vout, value, scriptSig, sequence, version, input/output counts, locktime, padding; Fig. 6 of [P1]). Its root is a secondary transaction identifier; storing it costs 32 bytes and the tree reconstructs from the fields. The root is committed in the generation transaction ([P1] [0164],[0168]). [P1] also defines an inter-miner root R_M ([0222]–[0223]) to serve trusted identifiers during *absent periods* when some miners do not participate.
- **Multilevel Merkle file validation [P4].** A file is split into 2^d segments transmitted as depth‖position‖segment and verified per segment against the root, with per-segment retransmission; depth is bounded by a one-byte marker (max 255).

### 2.3 Teranode (integration target, fully read)

Teranode [P5] processes transactions into **subtrees** — batches of TXIDs, up to ~2²⁰ each, carrying full Merkle-path connectivity, broadcast roughly every second and pre-validated. The block Merkle root is built **over subtree roots**, so the production system already maintains a two-level tree (transaction → subtree root → block root). The Asset service exposes `GetTransaction(hash)` and stores subtrees and the UTXO set. The testnet has exceeded 1M TPS; mainnet blocks reach 4 GB. The codebase is Go. MF-SPV is designed to read these structures, not to modify consensus.

---

## 3. Threat model and goals

**Assumptions (each marked; see §7 for which are demonstrated vs inherited):**

- **[A1 — chain validity; INHERITED, standard].** A majority of hash power is honest (BSV minority-hash assumption). This is the standard SPV assumption and is *weaker* than FlyClient's (c,L) assumption [L1], i.e. it yields a stronger guarantee. It is not re-proved here; it is the consensus assumption MF-SPV inherits unchanged.
- **[A2 — hash security; INHERITED, standard].** SHA-256d is collision- and preimage-resistant. Inclusion soundness reduces to this.
- **[A3 — header authenticity].** Bob holds, or can obtain, valid block headers (Stage 1). MF-SPV does not weaken Stage 1; for full-header verifiers it is unchanged, and the optional L4 accumulator (§4.1) addresses header-pruned verifiers only.

**Goals.** (G1) inclusion verifiable by Bob locally and in sub-millisecond compute; (G2) per-payment proof network cost zero; (G3) proof size growing logarithmically, not linearly, in block transaction count; (G4) no consensus change for the core; (G5) every limitation stated, none hidden.

**Non-goals.** Double-spend prevention is explicitly out of scope for the proof mechanism (§4.4); it is delegated to the live UTXO check and policy layer. Privacy beyond the field-revelation property of §4.2 is out of scope and flagged as an open dependency (§8).

---

## 4. MF-SPV design

### 4.1 The five-level commitment hierarchy

Each level is a Merkle commitment whose root is the leaf set of the next:

- **L0 — fields → MTxID = TXID.** Per [P1]: the transaction's fields are the leaves; the root is the TXID. A verifier can be shown one field (e.g. an output's value and script) with an `O(log f)` path in `f` fields, **without** the rest of the transaction. This is the property classic SPV lacks and that matters when a BSV transaction is gigabytes.
- **L1 — TXID → subtree root.** Per Teranode [P5]: TXIDs are grouped into subtrees of ≤2²⁰; the path is ≤20 hashes.
- **L2 — subtree root → block Merkle root.** Per Teranode [P5]: the block root is built over subtree roots; the path is `⌈log₂(#subtrees)⌉` hashes.
- **L3 — block Merkle root → 80-byte header.** Standard; PoW-sealed.
- **L4 — header → header-accumulator root (OPTIONAL).** A Merkle Mountain Range over all prior headers, with its root committed **in the generation transaction** (using [P1]'s mechanism), *not* in the header. This gives a header-pruned verifier the ability to prove any past header from a recent commitment, inheriting PoW security through L3 — **without** the header-format fork FlyClient requires [L1]. It is optional and unused by full-header verifiers.

L0–L3 require **no protocol change**; they are a relabelling and composition of structures already present. L4 is the only part touching commitment placement, and it does so in miner-controlled generation-transaction data, not in the header.

### 4.2 The proof bundle and the frozen-proof property

For each spendable output Alice holds, she stores a **proof bundle**:

```
{ output_ref,
  tx_fields            (only the fields to be revealed),
  L0_mtxid_path        (path for the revealed field — privacy: other fields stay hidden),
  L1_subtree_path,
  L2_block_path,
  L3_header,
  L4_anchor            (optional) }
```

**Frozen-proof property (the core improvement).** Once the block containing Alice's transaction is sealed, its L0–L3 structure is immutable: the field set, the TXID, the subtree assignment, the block root, and the header never change. Therefore the L0–L3 portion of Alice's bundle is **valid forever without maintenance**. This is the structural contrast with Utreexo [L3], where the accumulator mutates on every block and owners must update their proofs continually. MF-SPV pushes the maintenance cost to zero for buried transactions because there is nothing to maintain.

**Field-level privacy.** Because L0 is a tree over fields, Alice reveals only the field(s) Bob needs (e.g. the output) and a single path; the remaining fields are not disclosed. FlyClient and classic SPV treat the transaction as an atomic leaf and have no such property [L1].

### 4.3 Push delivery protocol (IP-to-IP)

Generalising [P3] and the owner-maintained model of [L3]:

1. **Bob → Alice:** payment request / template (amount, output script, optional data request per [P2]).
2. **Alice → Bob (offline-capable):** the signed spending transaction plus, for each input, its proof bundle (§4.2).
3. **Bob (local):** verifies each bundle **bottom-up, fail-fast** — recompute TXID from revealed fields (L0), climb L1→L2 to the block root, check the root against the held header (L3, or via L4 if header-pruned), verify Alice's signatures. Any mismatch aborts at the first failing hash, in `O(depth)` work and **zero network calls**.
4. **Bob → Network:** broadcast.
5. **Double-spend check (orthogonal, §4.4).**

Per-payment proof network cost is **zero**: the proof was pushed by Alice, not pulled by Bob. This is the direct refutation of TxChain's premise [L4] that verifying a transaction requires downloading its block — under the push model the relevant path is already in hand.

### 4.4 Double-spend is orthogonal (stated, not assumed away)

The inclusion proof proves *a transaction was in a block*. It does **not** prove *the output is unspent*. MF-SPV delegates double-spend handling to three independent mechanisms, exactly as [P3] does and **without** overloading the Merkle proof to do work it cannot:

- (a) Bob queries the live UTXO set (Teranode `utxoStore` [P5]);
- (b) a PoW-attested IPv6-multicast double-spend alert layer [P3];
- (c) a merchant risk parameter τ governing 0-confirmation acceptance [P3].

End-to-end acceptance latency is set by (a)–(c), not by MF-SPV. We make no claim about it beyond noting the dependency.

---

## 5. Related work and why we diverge

We engage the strongest contrary result in full and decline to delete it.

**FlyClient [L1] — fully read; the principal contrast.** FlyClient is a correct and significant result: it compresses chain synchronisation to `O(log n)` via an in-header MMR and a provably optimal sampling distribution. We do not dispute its mathematics. We dispute its *applicability to BSV*, by arithmetic: FlyClient's evaluated saving is driven by Ethereum's ~508-byte headers and ~15 s blocks; the paper evaluates on Ethereum for exactly this reason [L1]. BSV has 80-byte headers and ~600 s blocks, so the baseline FlyClient improves upon is ~4.2 MB/year and **constant in throughput** (§6, [P3]). Adopting FlyClient would (i) replace the standard minority-hash assumption with the strictly stronger (c,L) assumption — a *weaker* guarantee, by the paper's own statement — and (ii) require a header-format fork. The trade is a stronger assumption plus a consensus change for a saving over a 4.2 MB/year baseline. We decline it on those terms and quantify the decision rather than asserting it. We adopt FlyClient's *idea* of a cross-structure accumulator, but place the commitment off-header (L4, §4.1) using [P1], accepting the absent-periods cost (§8) as the price of not forking.

**Utreexo [L3] — corroborated (PDF robots-blocked).** Utreexo introduces owner-maintained inclusion proofs that travel with spends — the push model we adopt. Its limitation, confirmed across the project's own materials, is that the accumulator mutates each block, so proofs require continual maintenance. MF-SPV improves on this with the frozen-proof property (§4.2): for buried transactions there is no maintenance. We rely on [L3] only for the push-model precedent, which is corroborated; we do not rely on internals of the unread PDF.

**The PoPoW / recursive-SNARK / ZK-light-client family (surveyed in [L2]; representatives [L6], [R5], [R11]).** This family also targets Stage 1, by sublinear or constant-size chain proofs, several requiring trusted setups or imposing heavy prover cost (a property recorded in the survey [L2] and the cross-chain survey [R7]). The Stage-1 argument above applies to the whole family for BSV. The individual papers [L6], [R5], [R11], [R8], [R9], [R10] are cited at the depth stated in `05_REFERENCES.md`; **full-text deep-reads are pending and none is relied upon as evidence here.**

**TxChain [L4] — abstract-level.** TxChain reduces light-client cost by contingent transaction aggregation under a *pull* model. MF-SPV's push model removes the pulled cost at its root. We refute the paradigm, not the paper's internal results, which we have not read in full.

**Vector commitments — KZG [L5], Verkle/VC-updates [R4] — considered and rejected.** Replacing the SHA-256d Merkle tree with a KZG/Verkle vector commitment would shrink an opening from ~1.4 KB to ~48 bytes. We reject it on three demonstrated grounds, not convention: (i) KZG requires a trusted setup, incompatible with BSV's trust model — a definitional property of the scheme, not a claim needing the paper's internals; (ii) prover cost is infeasible at 6×10¹² leaves per 600 s block; (iii) the marginal benefit is ~1.3 KB per proof, which §6 shows is already negligible. SHA-256d Merkle has no setup and reuses the leaf hashing Teranode already performs. (The trusted-setup and prover-cost points are structural; the [L5]/[R4] citations are abstract-level and not load-bearing.)

**Mempool / DoS work — Carbyne [R2], Neonpool [R3] — substantial-depth, context only.** Informs the malformed-bundle DoS surface (§7), not the core design.

---

## 6. Scaling analysis (derived, not assumed)

Parameters (BSV; [P3], [P5]): block interval `t = 600 s`; header `H = 80 B`; blocks/year `≈ 52,560`; subtree capacity `S = 2²⁰`; digest `d = 32 B`.

Derivations: `T(r) = r·t` transactions/block; inclusion path `depth(r) = ⌈log₂ T(r)⌉` (the L1/L2 subtree split adds no hashes, since `log₂ T = log₂ S + log₂(#subtrees)`); core proof size `= d·depth(r)`; header dataset `= H × 52,560 ≈ 4.2 MB/year`, independent of `r`.

| r (tx/s) | T = r·600 | depth = ⌈log₂T⌉ | proof = 32·depth (B) | subtrees = ⌈T/2²⁰⌉ |
|---|---|---|---|---|
| 10⁶  | 6.00×10⁸  | 30 | 960  | 573 |
| 10⁷  | 6.00×10⁹  | 33 | 1056 | 5,723 |
| 10⁸  | 6.00×10¹⁰ | 36 | 1152 | 57,221 |
| 10⁹  | 6.00×10¹¹ | 40 | 1280 | 572,205 |
| 10¹⁰ | 6.00×10¹² | 43 | 1376 | 5,722,046 |
| **10¹¹** | **6.00×10¹³** | **46** | **1472** | **57,220,459** |
| 10¹² | 6.00×10¹⁴ | 50 | 1600 | 572,204,590 |

**Derived results (each a falsifiable prediction the simulator must reproduce; `04_TEST_PLAN.md` T7):**

- **R1.** From 10⁶ to 10¹⁰ tx/s the inclusion proof grows by **13 hashes = 416 bytes** (960 → 1376 B). Logarithmic.
- **R2.** The header dataset is **constant at ~4.2 MB/year** for every `r`. This is the quantity FlyClient-style Stage-1 compression competes to reduce; it does not scale with `r`, so the competition is over a fixed, already-small constant.
- **R3.** Inclusion-verification compute is `≤ depth` hash compressions (≤46 at 10¹¹ tx/s) plus signature checks plus one header lookup — sub-millisecond on commodity hardware; the simulator shows it growing with `log₂ T`, with the linear-in-`T` hypothesis rejected by regression. *Reference measurement:* ~13.7 µs per depth-46 verify on one software core (3.4 M SHA-256d/s), i.e. ~73k verifies/s/core, scaling linearly with cores (`bench.VerifyThroughput`).
- **R4.** Per-payment proof network cost is **0** under the push model; the simulator emits, for contrast, the bytes a pull-model verifier would fetch (the legacy SPV / [L4] regime).
- **R5 (capacity at 100 billion tx/s).** Two costs are kept separate. *Edge:* verification is stateless and embarrassingly parallel, so an N-core fabric sustains `N × ~73k` payment-verifications/s, independent of `r`. *Sealing* (Teranode's job): building the Merkle forest for a block of `T` tx is `T−1` internal hashes (the subtree split adds none), so the network-wide Merkle hash rate to seal at rate `r` is `≈ r` (marginal) to `≈ 2r` (incl. leaf/TXID hashing) SHA-256d/s. At `r = 10¹¹` that is `≈ 2×10¹¹` SHA-256d/s `≈ ~2,000` hardware-accelerated (SHA-NI) cores across `≈ 95,367` subtrees/s of 2²⁰ TXIDs — the horizontal-scale model Teranode already follows. `r` is bounded by Teranode validation/propagation, not by SPV (Result 4.4). Reproduced by `bench.PlanCapacity` from a measured per-core hash rate; asserted by `bench.TestCapacity100BillionTPS`.

These numbers are the empirical core. R1–R2/R4–R5(derivation) are arithmetic from stated BSV parameters; if a benchmark contradicts them the implementation is wrong, not the model. R3 and R5's core-count are single-machine reference measurements scaled by core count, not a deployed-network benchmark (§1 status, §8).

---

## 7. Security analysis

We state each property as a claim, give its reduction (proof sketch), and name the
**executable rejection test** that falsifies it if the implementation deviates. The
adversary model is §3: forge proofs, present an alternative chain, fabricate alerts,
spam malformed bundles, or act as a malicious miner; the adversary cannot break
SHA-256d ([A2]) or forge ECDSA, and the most-work chain is honest under the standard
minority-hash assumption ([A1]). Notation: `H` = SHA-256d; `Fold` = the leaf→root
path collapse; a verifier accepts a path iff `Fold(leaf, path)` equals the committed
root.

**Lemma 1 (Path soundness).** For a fixed committed root `R`, producing any `(leaf',
path')` with `leaf'` not the committed leaf such that `Fold(leaf', path') = R`
requires a SHA-256d collision or second-preimage.
*Proof.* `Fold` is a chain of `H(·‖·)` applications. If two distinct `(leaf,path)`
pairs reach the same `R`, then at the highest level where the intermediate values
differ, two distinct 64-byte inputs hash to the same value — a collision of `H`. ∎
*Test:* `commitment.TestT1_2_ForgeryRejected`, `adversarial.TestA1_ForgeryRejected`
(flipping any sibling, leaf, or root ⇒ reject).

**Theorem 1 (Inclusion soundness).** Under [A2], a `bundle.Verify` that returns
`true` implies the revealed field is committed, via MTxID = TXID and the L1/L2 path,
to `Header`'s Merkle root.
*Proof.* `Verify` recomputes `mtxid = Fold(leaf, MTxIDPath)` and checks `mtxid =
OutputRef.TXID` (L0 is mandatory), then `Fold` through L1, L2 and checks equality
with `HeaderMerkleRoot(Header)`. By Lemma 1 each step is sound under [A2]; a `true`
result therefore exhibits a genuine commitment chain. ∎
*Test:* `bundle.TestT3_1`, `bundle.TestT3_2` (each level corrupted ⇒ fail-fast with
the matching reason).

**Corollary 1.1 (No internal-node-as-leaf / 64-byte-tx attack).** Because L0 is
mandatory, a claimed TXID must be reconstructed from revealed fields. Passing an
*internal* Merkle node off as a leaf TXID would require fields whose field-tree root
equals that node — a second-preimage of `H`. *Test:*
`adversarial.TestRT4_InternalNodeAsLeafRejected`. This is a strict improvement over
classic SPV, which is vulnerable to the 64-byte-transaction confusion.

**Theorem 2 (Chain soundness).** Under [A1], a `true` from `Verify` binds `Header`
to the most-work chain.
*Proof.* Either (5a) `headersView.Contains(Header)` — the verifier holds the header
on its most-work chain; or (5b) the L4 anchor binds it. For (5b), `anchorBindsToChain`
requires (i) the carrying block's full header is on the verifier's chain, (ii) its
committed Merkle root equals `CarryingBlockMerkleRoot`, and (iii) `VerifyAnchor`
shows `AccRoot` is committed in that block's generation transaction; then
`VerifyBlockInChain` proves `Header` ∈ `AccRoot`. Thus `AccRoot` inherits the
carrying block's PoW. Forging either path requires a heavier-work chain, i.e.
majority hash power, excluded by [A1]. ∎
*Tests:* `adversarial.TestA2_AlternativeChainRejected` (off-chain header rejected),
`bundle.TestL4PrunedVerifier` (pruned verifier accepts a sound anchor),
`adversarial.TestRT1_AnchorRequiresTrustedCarrier` (an anchor without a trusted
carrying header is rejected — the RT-1 PoW-bypass fix).

**Theorem 3 (Inclusion ≠ double-spend, kept separate).** A valid inclusion proof
for an output that has since been spent still verifies, and acceptance still
requires the orthogonal liveness checks.
*Proof.* Inclusion is a historical fact about a sealed block; spentness is a
property of the live UTXO set. `bundle.Verify` tests only the former.
`walletbob.AcceptPayment` accepts only if inclusion **and** `IsUnspent` **and**
owner-bound alert-quiet **and** signature/template all hold (I-BB1). ∎
*Tests:* `bundle.TestT3_5_InclusionNotDoubleSpend`,
`walletbob.TestT4_4_AcceptanceSeparation`.

**Theorem 4 (Alert unforgeability).** An admissible double-spend alert can only be
produced by a party holding the outpoint owner's private key.
*Proof.* `VerifyAlert` requires two distinct spends of the same outpoint, each with
a canonical (low-S) ECDSA signature, both valid under one `OwnerPubKey`, over
`H(outpoint‖spendTxID)`. Producing two such signatures without the private key
contradicts ECDSA unforgeability. At the point of sale (`QuietForOwners`) the alert
counts only if `OwnerPubKey` equals the key spending the output in the payment, so a
third party cannot fabricate a conflict for an outpoint they do not own. ∎
*Tests:* `dsalert.TestT5_1_EvidenceGated`, `dsalert.TestFloodIneffective`,
`dsalert.TestRT7_OwnerBoundAlerts`, `adversarial.TestA4_AlertFloodDropped`.

**Theorem 5 (Non-malleable authorisation).** An accepted payment's input signatures
are canonical, so a third party cannot maul the broadcast transaction's id by
flipping `S`.
*Proof.* `payment.VerifyInputSignature` rejects any signature with `S > n/2`; the
malleated form `(r, n−S)` is therefore not accepted even though it verifies under
raw ECDSA. ∎ *Test:* `adversarial.TestRT3_HighSRejected`.

**Proposition 6 (Spam/DoS bounded).** Malformed bundles are rejected in `O(depth)`
work with no network call, and a malicious length prefix cannot force a large
allocation.
*Justification.* `Verify` fails at the first bad hash; the deserializer is bounded
by the input buffer and caps path lengths at the 255 depth ceiling. *Tests:*
`adversarial.TestA3_SpamRejectedFailFast`, `adversarial.TestRT5_SerializationDoS`,
`adversarial.TestRT6_BoundaryPathLengths`, `commitment.TestT1_6_DepthCeiling`.

**Proposition 7 (Reorg safety).** A bundle whose block is orphaned does not verify
until re-anchored; `Reanchor` never mutates the frozen L0 (intra-transaction) data.
*Tests:* `adversarial.TestA5_OrphanedBlockReanchor`, `bundle.TestT3_3_FrozenCore`,
`bundle.TestT3_4_Reanchor`.

**Proposition 8 (Field-level privacy).** Revealing one field discloses only that
field and its L0 path; the rest of the transaction stays hidden (a strict
improvement over atomic-leaf designs [L1]). Unlinkability beyond this is OPEN (§8).
*Test:* `bundle.TestT3_*` (bundles carry only the revealed field, I-B3).

**No causal or security claim rests on an `[ABSTRACT]`-level reference.** [A1] and
[A2] are the standard consensus and hash assumptions; every other claim above is
reduced to them and has an executable falsifying test.

### 7.8 Red-team hardening (adversarial audit)

An adversarial audit of the *implementation* (not just the prose) found and fixed
issues the model had glossed over. Each is now closed and asserted by a rejection
test; full write-up in `SECURITY.md`.

| ID | Severity | Issue | Fix | Test |
|---|---|---|---|---|
| RT-1 | HIGH | L4 anchor trusted an attacker-supplied carrying root ⇒ PoW bypass | bind carrying *header* to the verifier's chain (Thm 2) | `TestRT1_*`, `TestL4PrunedVerifier` |
| RT-2 | HIGH | alert "evidence" was two bare hashes ⇒ forgeable flood | require two owner-**signed** spends (Thm 4) | `TestT5_1`, `TestFloodIneffective` |
| RT-7 | HIGH | owner key not bound to the outpoint ⇒ flood with own key | owner-bound PoS check `QuietForOwners` (Thm 4) | `TestRT7_OwnerBoundAlerts` |
| RT-3 | MED | high-S signatures accepted ⇒ txid malleability | reject non-canonical sigs (Thm 5) | `TestRT3_HighSRejected` |
| RT-4/5/6 | — | internal-node-as-leaf; serialization DoS; path bounds | confirmed safe (Cor 1.1, Prop 6) | `TestRT4/5/6_*` |

---

## 8. Limitations (stated, not hidden)

1. **Absent periods (inherited from off-header commitment).** The optional L4 accumulator is committed in the generation transaction, so it binds only blocks of participating miners; non-participating miners leave gaps — exactly the absent-periods problem [P1] raises and patches with the inter-miner root R_M ([0222]–[0223]). FlyClient's in-header MMR has no such gap because every honest miner maintains it [L1]. This is the price of not forking the header, and it is a real cost. **It affects only header-pruned verifiers using L4; full-header verifiers are unaffected because they do not use L4.** The companion specs require gap-honesty: the accumulator must report its coverage gaps rather than paper over them (`02_MODULE_SPECS.md` `CoverageGaps`; `04_TEST_PLAN.md` T2.3).
2. **Privacy.** MF-SPV provides field-level non-disclosure (§4.2) but no unlinkability guarantee. Treated as an open dependency, not claimed.
3. **Reorg re-anchoring.** Detection and re-anchoring of bundles whose block is orphaned is specified at the interface level (`Reanchor`) but the policy is not fully worked out. Open.
4. **Double-spend latency.** Out of scope for the proof; end-to-end latency depends on the orthogonal layer (§4.4). Not claimed.
5. **Evidence dependency on blocked PDFs.** `eprint.iacr.org` PDFs were robots-blocked; FlyClient [L1] and SoK [L2] were read in full via alternate routes, but Utreexo [L3] and all other ePrint items were not. The related-work claims drawn from `[ABSTRACT]`-level items are positioning, not evidence; before journal submission their full texts must be obtained and re-read (`05_REFERENCES.md`, honest dependency).
6. **Implementation is a reference, not a production benchmark.** A complete zero-dependency Go implementation now exists and its test suite reproduces §6's table and asserts §7's rejections. But the performance figures are arithmetic plus single-machine measurements (per-core hash rate, edge verify rate) used to *derive* capacity — they are **not** a deployed-network throughput benchmark, and §6 R5's core-count is an extrapolation. A production deployment must (a) wire the read-only adapters to a pinned Teranode revision (`01_ARCHITECTURE.md §7` dep #2), (b) replace the `math/big` secp256k1 signer with a constant-time, audited curve (the present signer is correct but not side-channel-hardened), and (c) perform standard full transaction validation (script + value conservation) at the till, which is node-standard and orthogonal to the MF-SPV proof.
7. **Red-team residuals.** The adversarial audit (§7.8, `SECURITY.md`) closed three vulnerabilities; the documented residuals are the constant-time signer and the value-conservation check above, both deployment-layer, not defects in the construction.

---

## 9. Conclusion

For BSV at scale, the scaling lever is not where the light-client literature has put it. Sublinear chain synchronisation optimises a dataset that, at 80-byte headers and 10-minute blocks, is ~4.2 MB/year and does not grow with throughput, and it costs a stronger assumption and a header fork. MF-SPV optimises the inclusion stage and the delivery model instead: a five-level Merkle hierarchy that is already present in Teranode and needs no consensus change for its core, field-level proofs from [P1], sender-pushed bundles whose historical portion is frozen at block-sealing time, and double-spend handling kept orthogonal to the proof. The derived model predicts inclusion proofs growing by 416 bytes across four orders of magnitude of throughput (960→1376 B from 10⁶ to 10¹⁰ tx/s; 1472 B at **10¹¹ tx/s — 100 billion**), with per-payment proof network cost zero. These predictions are now not merely specified but **reproduced** by a reference implementation whose test suite (61 tests) matches the table exactly and asserts every security rejection, and the construction has survived an adversarial audit (§7.8) that hardened the L4 anchor, the alert layer, and signature handling. The limitations — absent periods under the optional off-header accumulator, privacy, reorg re-anchoring, the deployment-layer items of §8, and the outstanding full-text reads — are stated here rather than discovered later.

---

## Appendix A — Build artifacts

Design, build, and audit are in the companion files and the `mfspv` Go module (now implemented): `01_ARCHITECTURE.md` (architecture, namespace `mfspv`, build order), `02_MODULE_SPECS.md` (Go interfaces, invariants, conditions — updated to the hardened protocol), `03_SCALING_MODEL.md` (the simulator's exact target table through 10¹¹/10¹² tx/s), `04_TEST_PLAN.md` (T1–T7 functional and A1–A5 adversarial tests; every security test asserts a **rejection**), `SECURITY.md` (red-team audit), and `README.md` (run instructions). Build order: `commitment → bundle → {wallet_alice, wallet_bob} → teranode_adapter → accumulator → dsalert → bench`. The demonstration runner is `cmd/mfspv`.

## Appendix B — Optional encrypted-delivery path

Where Bob's request carries a data payload, the request/response and ECDH-derived side-secret mechanism of [P2] (US 11,893,074) composes with the payment in step 2 of §4.3. It is optional and outside the core verification path.

## Appendix C — Reference depths

All sources, their verified URLs, read-depths, and tier scores are in `05_REFERENCES.md`. Load-bearing sources: [P1]–[P5] (full primary), [L1] (full), [L2] (full), [L3] (corroborated push-model precedent only). All other references are positioning at the depth stated and are not relied upon as evidence.

## Appendix D — Claim → falsifying test (proof-ready map)

Every load-bearing claim is backed by an executable test; the construction is
"proof-ready" in the sense that each result can be falsified by running one named
test. All 61 pass (`go test ./...`, forced, no cache); `go vet` and `gofmt` clean.

| Claim | Result/Lemma | Test(s) |
|---|---|---|
| Inclusion path is `ceil(log2 T)` | R1 / §6 table | `commitment.TestT1_3_DepthLaw`, `bench.TestT7_TargetTable` |
| Proof +416 B over 10⁶→10¹⁰; 1472 B at 10¹¹ | R1 | `bench.TestR1_ProofGrowth`, `bench.TestScale100BillionTPS` |
| Header dataset constant ~4.2 MB/yr | R2 | `bench.TestT7_3_HeaderConstant` |
| Verify ∝ log T, not linear | R3 | `bench.TestT7_4_LogarithmicVerify`, `bench.TestEdgeThroughputScales` |
| Push proof network cost = 0 | R4 | `bench.TestT7_5_PushVsPull` |
| 100B tx/s sealing capacity derivation | R5 | `bench.TestCapacity100BillionTPS` |
| Path/inclusion soundness | Lem 1 / Thm 1 | `commitment.TestT1_2_*`, `bundle.TestT3_1/2`, `adversarial.TestA1_*` |
| No 64-byte / internal-node attack | Cor 1.1 | `adversarial.TestRT4_InternalNodeAsLeafRejected` |
| Chain soundness + L4 PoW binding | Thm 2 | `adversarial.TestA2_*`, `TestRT1_*`, `bundle.TestL4PrunedVerifier` |
| Inclusion ≠ double-spend | Thm 3 | `bundle.TestT3_5`, `walletbob.TestT4_4` |
| Alert unforgeability + owner-binding | Thm 4 | `dsalert.TestT5_1`, `TestRT7_*`, `adversarial.TestA4_*` |
| Signature non-malleability | Thm 5 | `adversarial.TestRT3_HighSRejected` |
| Spam/DoS bounded | Prop 6 | `adversarial.TestA3_*`, `TestRT5_*`, `TestRT6_*` |
| Reorg safety / frozen core | Prop 7 | `adversarial.TestA5_*`, `bundle.TestT3_3/3_4` |
| Accumulator append-only + gap honesty | §4.1 / §8(1) | `accumulator.TestT2_1`, `TestT2_3_GapHonesty` |
| Offline wallet / no keys at till | I-AL1 / I-BB2 | `walletbob.TestT4_1/4_2/4_3` |

## Appendix E — Security audit

The adversarial (red-team) audit, its findings (RT-1…RT-7), fixes, and confirmed-safe
surfaces are documented in `SECURITY.md`. Three vulnerabilities found in the
implementation were fixed and are now covered by rejection tests (§7.8).
