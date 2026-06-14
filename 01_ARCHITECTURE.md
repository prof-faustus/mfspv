# Layered Merkle-Forest SPV — Architecture Specification

**Working name:** Merkle-Forest SPV (MF-SPV). Rename at will; the code namespace below uses `mfspv`.
**Target chain:** BSV only. No BTC code, parameters, or assumptions appear anywhere in this design. Where "Bitcoin" is used it means the original protocol as defined in Wright (2008), i.e. BSV.
**Target node:** Teranode (BSV Association), microservice architecture, Go.
**Status of this document:** architecture only. It specifies *what* is built and *why*. It does not implement. Claude Code implements against `02_MODULE_SPECS.md` and validates against `03_SCALING_MODEL.md` and `04_TEST_PLAN.md`.

---

## 0. Scope and the one-sentence thesis

**Thesis.** At 10⁶–10¹⁰ transactions per second with a ~10-minute block, the cost that matters for a payment verifier is **not** chain synchronisation (the quantity FlyClient/NIPoPoW/SNACKs/ZK-superlight clients compress) but (i) the per-transaction Merkle path inside an enormous block and (ii) point-of-sale double-spend exposure. The BSV header chain is **constant at ~4.2 MB/year regardless of throughput** (80-byte headers, ~10-min blocks); therefore the chain-sync prize those protocols win is bounded by ~4.2 MB/year and does not grow with throughput. MF-SPV instead (a) makes the per-transaction path logarithmic and pushes it off the network entirely via a sender-held proof bundle (IP-to-IP, Alice→Bob), and (b) handles double-spend at the point of sale with a merchant risk policy plus a network alert layer. It is Teranode-native and requires **no consensus change to the block header**.

This claim is made precise in §4. Each design choice that could be an assumption is marked **[ASSUMPTION]** and is either discharged in §6 or listed as an open dependency in §7. Nothing in §4's arithmetic is an assumption; it is derived.

---

## 1. Inputs this design is built on (all read from primary source)

1. **Safe Low-Bandwidth SPV** (the project's own construction, `Appendix_1_SPV`). Communication flow is changed from `Merchant→Customer→Network→Merchant` to `Merchant→Customer→Merchant→Network`. The customer (Alice) is offline and holds full input-transaction data, private/public keys, all block headers (optional), and **the Merkle paths of her stored transactions**. The merchant (Bob) is online, holds block headers, performs the SPV check **locally**, and broadcasts. The Merkle proof is explicitly a **fail-fast against spam/error, not double-spend protection**. Double-spend handling uses UTXO-seen datasets and IPv6-multicast alerts.

2. **MTxID — field-level Merkle tree** (US 2022/0216997 A1, nChain, "Verification of Data Fields of Blockchain Transactions", pub. 2022-07-07). The leaves of a transaction's own Merkle tree are its **individual fields** (`txid_prev`, `vout`, `value`, `scriptSig`, `sequence`, `version`, `txin/txout counts`, `locktime`, padding). The root `R = MTxID` is the secondary transaction identifier. Storing `R` adds 32 bytes; the tree reconstructs from the fields at any time ([0166]–[0167]). `R` may be committed in the **generation transaction** of a block ([0164], [0168]). **Absent periods** ([0222]–[0223]): a participating miner includes a further 32-byte root `R_M` (root of a third tree `T_M`) in its generation-transaction script so it can serve trusted MTxIDs even when other miners do not participate.

3. **Multilevel file validation** (the project's own construction, `Appendix_2_Merkle`). A file is split into 2^d segments; each segment is transmitted as `[depth ‖ position ‖ segment]`; segments verify individually against the root; only a corrupted segment is re-sent; segments are indexed in a key-value store by component hash. Tree depth is bounded by a one-byte marker, max depth 255.

4. **Data delivery over transactions** (US 11,893,074, nChain, "Sharing data via transactions of a blockchain"; USPTO record https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/11893074). Request/response delivery of document/image content via transactions, with a side ECDH-derived secret, integrity tagging, and hypertext-style linking between transactions.

5. **Teranode** (BSV Association). Microservices observed in the production operator (`bsv-blockchain/teranode-operator`): `propagation`, `subtree-validator`, `block-assembly`, `block-validator`, `block-persister`, `blockchain`, `asset`, `utxo`, `peer`, `miner`. **Subtrees** are batches of **TXIDs with full Merkle-path connectivity**, up to ~2²⁰ (≈1,000,000) TXIDs each, broadcast on the P2P network roughly **every second**, pre-validated before the block is sealed; the block Merkle root is assembled **over subtree roots**. Including only the TXID in a subtree assumes nodes already hold the full transaction data. (Authoritative description: AWS Web3 engineering blog on the million-TPS Teranode node; official docs at docs.bsvblockchain.org and bsv-blockchain.github.io/teranode.)

**Consequence of (5):** Teranode already gives a two-level commitment — `tx → subtree root → block root`. MF-SPV slots one level below it (MTxID) and one optional level above it (cross-block accumulator), giving a single verifiable chain from a data **field** up to the chain tip.

---

## 2. The commitment hierarchy (five levels)

A single datum is committed by a path through five nested Merkle structures. Levels L0–L3 are the **core** and require no protocol change. L4 is **optional** and only matters for a verifier that does not keep the (constant-size) header chain.

```
 L0  field            →  MTxID = TXID          (per US 2022/0216997; leaves = tx fields)
 L1  TXID             →  subtree root          (Teranode subtree, ≤ 2^20 TXIDs)
 L2  subtree root     →  block Merkle root      (standard, but built over subtree roots)
 L3  block Merkle root→  block header          (existing 80-byte header; PoW-sealed)
 ----------------------------------------------- core ends here -----------------
 L4  block header     →  cross-block accumulator root, committed in the
                          generation-transaction script of a later block
                          (per US 2022/0216997 generation-tx mechanism, extended
                           from MTxIDs to headers).  OPTIONAL.
```

- **TXID == MTxID.** The design fixes `TXID := MTxID` so that L0 and L1 compose with no glue: the leaf Teranode already puts in a subtree *is* the root of the field tree. (If a deployment must keep legacy double-SHA256 TXIDs, L0 attaches as a sibling commitment; see `02_MODULE_SPECS.md §commitment`. Default is the unified form.)
- **L1/L2 split is exactly Teranode's.** A block of `T` transactions partitions into `T / 2^20` subtrees. Path length is `20` (within subtree) `+ ⌈log2(T/2^20)⌉` (subtree roots → block root). This equals `⌈log2 T⌉`, i.e. the split does not add hashes; it only matches how Teranode shards the work.
- **L4 is append-only and off-header.** The accumulator is a Merkle Mountain Range (MMR) over sealed block headers, its root written to the generation transaction. Because the generation transaction is itself committed by L3, the accumulator root inherits PoW security **without** a header-format fork. This is the deliberate divergence from FlyClient (which puts the MMR in the header and therefore needs a hard/soft/velvet fork). The cost of staying off-header is **absent periods** (§6.4).

---

## 3. The proof bundle and the IP-to-IP (push) protocol

### 3.1 Bundle (what Alice holds per spendable output)

For each unspent output Alice can spend, she stores a self-contained **bundle**:

```
Bundle {
  output_ref        : (TXID, vout)
  tx_fields         : the fields needed to (a) reconstruct MTxID and (b) let Bob form the spending input
  mtxid_path        : L0 path  field → MTxID            (only the revealed field(s) — privacy, §6.6)
  subtree_path      : L1 path  TXID  → subtree root
  block_path        : L2 path  subtree root → block Merkle root
  header            : L3        the 80-byte header whose merkle_root closes block_path
  anchor (optional) : L4 path  header → accumulator root + the carrying generation tx’s own
                                L0–L2 path to a recent block, PLUS that carrying block’s full
                                80-byte header, for header-pruned verifiers
}
```

> **Security (RT-1).** The anchor carries the carrying block’s **full header**, and a
> header-pruned verifier MUST check that header is on its most-work chain and that its
> committed Merkle root equals the anchor’s `CarryingBlockMerkleRoot` before trusting the
> accumulator. Otherwise `CarryingBlockMerkleRoot` is attacker-chosen and the accumulator
> inherits no PoW. See `SECURITY.md` RT-1.

The L0–L3 portion of a bundle is **frozen forever** once the block is sealed: a buried transaction's path to its block root never changes. This is the central maintenance result and the key improvement over Utreexo (§5.3).

### 3.2 Protocol (generalises the project's Safe Low-Bandwidth SPV)

Flow stays `Bob → Alice → Bob → Network`.

```
[1] Bob → Alice   : payment template Tx3 (Bob output + amount), and a request for
                    {tx_fields, mtxid_path, subtree_path, block_path, header[, anchor]} per input.
[2] Alice → Bob   : the requested bundle(s) + the filled, signed Tx3.       (Alice may be OFFLINE.)
[3] Bob (LOCAL)   : verify each input bundle bottom-up:
                    field → MTxID(=TXID) → subtree root → block root → header.merkle_root,
                    then header ∈ Bob’s most-work header chain (L3),
                    or (if Bob is header-pruned) header ∈ chain via anchor (L4);
                    then verify Alice’s signature(s) and that Tx3 matches the template.
                    The Merkle verification is FAIL-FAST (spam/error rejection), not
                    double-spend protection.
[4] Bob → Network : broadcast Tx3 (only if [3] passed).
[5] (optional)    : Bob’s post-broadcast SPV check, identical to legacy SPV; not required.
```

Double-spend protection is **orthogonal** to [1]–[5] and is provided by:
- **(a)** Bob querying the live UTXO set for each `output_ref` (Teranode `utxo`/`asset` service). Confirms the output is still unspent at acceptance time.
- **(b)** the **double-spend alert layer** (`mfspv/dsalert`): IPv6-multicast alerts carrying **cryptographically verifiable** evidence of a conflicting spend — two distinct spends of the same outpoint, each signed by the outpoint owner's key (RT-2) — attested with prior proof-of-work. Bob counts an alert only when its signing key matches the key spending the output in the payment (owner-bound, RT-7), so third parties cannot fabricate conflicts. This lets Bob reject within the propagation window.
- **(c)** a **merchant risk parameter τ**: Bob's policy for accepting 0-confirmation against value at risk and elapsed alert-quiet time. τ is set by Bob, not the protocol.

### 3.3 Why this is "give everything to Bob, fast"

Alice transmits a bundle whose verification payload is ~`32 × depth` bytes (§4) plus the fields. Bob verifies with `depth` hash operations and one header lookup — microseconds. No proof is fetched from the network; the round-trip the legacy SPV check needs (network supplies the Merkle path) is eliminated because Alice already holds the path. This is the literal realisation of the project's stated inversion of the message flow, now generalised to the full forest and to arbitrary block size.

---

## 4. Scaling analysis (derived, not assumed)

Let `r` = transactions/second, block interval `t = 600 s`, transactions per block `T = r·t`.

| `r` (tx/s) | `T = r·600` (tx/block) | `depth = ⌈log2 T⌉` | core proof `= 32·depth` bytes |
|---|---|---|---|
| 10⁶ | 6.0×10⁸ | 30 | 960 B |
| 10⁷ | 6.0×10⁹ | 33 | 1,056 B |
| 10⁸ | 6.0×10¹⁰ | 36 | 1,152 B |
| 10⁹ | 6.0×10¹¹ | 40 | 1,280 B |
| 10¹⁰ | 6.0×10¹² | 43 | 1,376 B |

**Result 4.1 (logarithmic path).** A complete L0–L2 inclusion path for one transaction is `⌈log2 T⌉` hashes. From 10⁶ to 10¹⁰ tx/s the path grows from 30 to 43 hashes — i.e. the proof for a payment grows by **13 hashes (416 bytes) across four orders of magnitude of throughput.** Depth 43 ≪ 255, so the one-byte depth marker from `Appendix_2_Merkle` never overflows.

**Result 4.2 (header constancy).** Headers are 80 bytes at ~144 blocks/day = 80·144·365 ≈ **4.2 MB/year, independent of `r`.** Bob's entire chain-validity dataset is constant in throughput.

**Result 4.3 (FlyClient prize is bounded and non-growing).** A chain-sync compressor's saving is at most (full headers) − (compressed headers) ≤ full headers = 4.2 MB/year, and this does **not** scale with `r`. MF-SPV's per-payment cost (≈1 KB, Result 4.1) also does not scale with `r`. Therefore at any throughput the chain-sync prize is dominated by, and orthogonal to, the per-payment path that MF-SPV addresses. *(This is the rigorous form of "FlyClient is marginal-to-irrelevant for BSV." It is a corollary of 4.1–4.2, not an opinion.)*

**Result 4.4 (network decoupling).** The network's per-second obligations are: emit subtree roots (Teranode: 2²⁰-TXID subtrees ≈ every second), seal blocks (per 600 s), and append one header to L4 (one 32-byte write to a generation transaction, per block). None is per-payment. Hence verification cost at the edge is decoupled from `r`; throughput is bounded by Teranode's validation/propagation, not by SPV.

---

## 5. What is taken from the literature, what is rejected, and why

`STATE · CLASSIFY · DONE.` Full-text adversarial reads are pending for ePrint-hosted items (robots-blocked fetch); claims below are confined to each work's own stated contribution and are depth-tagged in `05_REFERENCES.md`.

### 5.1 Take: the push model (Utreexo, ePrint 2019/611)
Utreexo represents the UTXO set as a logarithmic hash accumulator; **nodes attach and propagate inclusion proofs with transaction inputs**, pushing proof maintenance to the fund owner ("an exchange creating millions of transactions maintains millions of proofs; a personal account maintains a few kilobytes"). MF-SPV adopts this push model — it *is* the project's "Alice holds her Merkle paths." **Improvement (5.3).**

### 5.2 Take, but off-header: the cross-block accumulator (FlyClient, ePrint 2019/226, S&P 2020)
FlyClient commits all prior blocks via an MMR root **in the header**, enabling a single recent header to prove any past block; it then samples headers under an optimal distribution. MF-SPV takes the MMR idea for the **optional L4** but commits it in the **generation transaction** (US 2022/0216997 mechanism), avoiding the header fork FlyClient needs. **Reject FlyClient wholesale:** its `(c,L)` adversary assumption is, by its own statement, stronger than the SPV assumption, and it requires a header change — paid for a saving bounded by Result 4.3. Not worth it for BSV.

### 5.3 Improvement over Utreexo: frozen historical paths
Utreexo's accumulator **mutates every block** as outputs are spent/created, so a holder's proof must be updated each block. MF-SPV's L0–L3 path is to a **sealed block** and is therefore **immutable forever**; only the optional L4 anchor to a *recent* tip grows, by `O(log Δ)` in blocks-since. Maintenance is thus lighter than Utreexo for already-confirmed funds. (This is a design property of committing to historical blocks rather than to a live set; demonstrated, not assumed.)

### 5.4 Reject the premise: TxChain (ePrint 2020/580)
TxChain reduces, via contingent transaction aggregation, the number of blocks a **pull** light client must download to verify a set of transactions — its cost model assumes "to verify a transaction the corresponding block must be downloaded." MF-SPV is a **push** model: Alice already holds the path, so blocks downloaded = 0. We do not delete TxChain; we show its optimisation targets a paradigm we replace. *(Engagement of a contradicting design, per the project standard.)*

### 5.5 Reject for BSV: the chain-sync compression family
NIPoPoW (FC 2020), SNACKs (ASIACRYPT 2022), Plumo (FC 2022), ZeroSync (STARK proofs for Bitcoin, 2024), and SNARK query-verification for superlight clients (arXiv 2503.08359, 2025) all compress **chain synchronisation** (the linear-header problem) via succinct proofs or sampling. By Result 4.2 BSV has no linear-header problem; by Result 4.3 their prize does not scale with throughput. They also add proving cost and, in several cases, trusted setup or stronger assumptions. Classify: solving a non-problem for BSV; not adopted. They remain the right tool for high-header-rate chains (e.g. Ethereum), which is exactly the regime FlyClient itself chose to evaluate.

### 5.6 Considered and rejected: replacing Merkle with a vector/polynomial commitment
KZG (ASIACRYPT 2010, doi 10.1007/978-3-642-17373-8_11) gives **O(1)-size** openings (one group element, ≈48 B) versus Merkle's `O(log T)` (≈1.4 KB at 10¹⁰ tx/s). Aggregatable subvector commitments (SCN 2020) and Verkle trees (arXiv 2307.04085, 2023) extend/optimise this. **Rejected for this design**, on three demonstrated grounds, not convention:
1. **Trusted setup.** KZG/Verkle need a structured reference string (powers-of-tau ceremony). This is incompatible with BSV's trust model and with a node that must not depend on a setup ceremony.
2. **Prover cost at scale.** Committing/opening a KZG vector of `T = 6×10¹²` leaves per 600 s in real time is infeasible (super-linear field arithmetic per block) where SHA-256d Merkle is `O(T)` hashing that Teranode already performs to build subtrees.
3. **Marginal benefit.** The saving is ≈1.3 KB per payment (Result 4.1). Against a payment payload that already carries transaction fields and signatures, and given Teranode produces the Merkle structure for free, the saving does not justify (1)–(2).
Decision: **SHA-256d Merkle**, no trusted setup, leaf hashing reused from Teranode subtree construction.

### 5.7 Adjacent, relevant, retained for the DoS surface (recent)
Carbyne (arXiv 2504.16089, 2025) and Neonpool (arXiv 2412.16217, 2024) treat DoS-resilient / lightweight mempools. They inform `mfspv/dsalert` and the spam fail-fast (§3.2, §6.5) rather than the commitment hierarchy.

---

## 6. Security model

**Threat model.** Adversary may: present forged inclusion proofs; present an alternative header chain; attempt a double-spend at the point of sale; spam Bob with malformed bundles; collude as a miner who commits a false L4 root. Adversary cannot break SHA-256 (collision/second-preimage) or forge ECDSA.

**[ASSUMPTION — chain validity]** Most-work chain is honest under BSV's standard **minority-hash** assumption (honest majority of hash power). This is the *standard* SPV assumption and is **weaker** (hence a stronger guarantee) than FlyClient's `(c,L)` assumption. Discharged by adoption of the standard model; not strengthened anywhere in this design.

### 6.1 Inclusion soundness
Forging any L0–L2 path requires a SHA-256 collision. Bob recomputes the path bottom-up and compares to `header.merkle_root`; mismatch ⇒ reject. **DONE.**

### 6.2 Chain soundness
`header.merkle_root` is bound to the most-work chain either directly (Bob holds the constant-size header chain, L3) or via the L4 accumulator anchored in a PoW-sealed generation transaction — where the carrying block's header must itself be on the verifier's chain with a matching Merkle root (RT-1), so the anchor genuinely inherits PoW. A false chain requires majority hash power (the assumption). **DONE.**

### 6.3 Merkle proof is fail-fast, not double-spend protection — stated explicitly
Per the project's own construction, a valid inclusion proof shows the *input* transaction was mined; it does **not** show the output is still unspent. Double-spend exposure is closed by §3.2(a) live UTXO query, §3.2(b) alert layer, §3.2(c) τ. Conflating the Merkle proof with double-spend protection is a **defect**; the design keeps them separate. **DONE.**

### 6.4 Absent periods — stated, not hidden (the real cost of staying off-header)
L4 binds only blocks whose miners committed the accumulator. Non-participating miners leave **gaps**: a header-pruned verifier cannot anchor a block that lies in a gap and must fall back to the nearest participating block ≤ N, or to fetching the missing header. The `R_M`/`R_M^Inter` third-tree mechanism ([0222]–[0223]) lets participating miners cover intervals, but cannot cover a block no participant committed. FlyClient's in-header MMR has no gaps because every honest miner maintains it; that gaplessness is exactly what the header fork buys, and what MF-SPV trades away to avoid the fork. **This limitation is intrinsic to L4 and is the price of not forking.** A verifier that keeps the full (4.2 MB/year) header chain is unaffected, since L4 is then unused. **CLASSIFY: limitation, bounded, disclosed.**

### 6.5 Spam / DoS
Malformed bundles are rejected by the first failing hash in the fail-fast check — `O(1)` to `O(depth)` work, no network call. Alert-layer flooding and mempool DoS are handled at the node tier (informed by Carbyne/Neonpool). **DONE.**

### 6.6 Privacy
Field-level MTxID lets Alice reveal **only the spent output's fields and their L0 path**, not the whole input transaction — a strict improvement over FlyClient's atomic-transaction leaf, which forces revealing/handling the entire transaction. The bundle still reveals the specific outpoint and its block to Bob; further unlinkability is out of scope and flagged in §7. **CLASSIFY: partial; improvement over atomic-leaf designs; residual leakage disclosed.**

### 6.7 Red-team hardening (adversarial audit; `SECURITY.md`)
An adversarial review of the implementation found and fixed issues that the prose
model glossed over. Each is now closed in code and asserted by a rejection test:
- **RT-1 (L4 PoW binding).** The accumulator anchor must bind its `CarryingBlockMerkleRoot`
  to a header on the verifier's chain (carry the full header; check containment + root
  match), else PoW is bypassed. §3.1, §6.2.
- **RT-2 (alert evidence).** Conflict evidence is two owner-**signed** spends of the same
  outpoint, not two bare hashes; forging requires the owner key. §3.2(b), §6.5.
- **RT-7 (owner-bound alerts).** The merchant counts a conflict only when its signing key
  equals the key spending the output, so third parties cannot fabricate conflicts. §3.2(b).
- **RT-3 (malleability).** Non-canonical (high-S) signatures are rejected at the till.
- **Confirmed safe:** internal-node-as-leaf / 64-byte-preimage (blocked by mandatory L0),
  serialization DoS (bounded reader), boundary path lengths. **DONE.**

---

## 7. Open dependencies and explicit assumptions (nothing swept under the rug)

1. **[ASSUMPTION — chain validity]** §6 minority-hash. Standard; stated.
2. **[DEPENDENCY — Teranode interfaces]** The exact Go interfaces of the `asset`/`utxo`/`subtree`/`blockchain` services must be read from the pinned Teranode source revision before `mfspv/teranode_adapter` is implemented. The operator pod set and the Asset Service `Repository` signatures are confirmed; field-level subtree path accessors must be confirmed against source. Listed, not assumed.
3. **[DEPENDENCY — generation-tx commitment standardisation]** L4 requires a convention for where in the generation-transaction script the accumulator root sits and how multiple miners' roots reconcile. US 2022/0216997 gives the mechanism; the network convention is a deployment decision.
4. **[OPEN — reorg re-anchoring]** A bundle anchored to a block that is later orphaned is invalid until re-anchored to the winning chain. Maintenance cost and detection are specified in `02_MODULE_SPECS.md §bundle.reanchor`; the economic/UX policy is open.
5. **[OPEN — unlinkability]** §6.6 residual leakage; not addressed here.
6. **[OPEN — full-text literature read]** §5 claims are abstract-/contribution-level pending full-text reads of ePrint-hosted works (robots-blocked fetch). Required input: the PDFs, or arXiv mirrors, before any §5 claim is promoted to load-bearing evidence in the paper.

---

## 8. Mapping to build artifacts

| Concern | Module (`02_MODULE_SPECS.md`) | Validated by |
|---|---|---|
| L0 MTxID build/verify | `mfspv/commitment` | `04_TEST_PLAN.md §T1` |
| L1/L2 subtree & block path | `mfspv/commitment` | `§T1` |
| L4 accumulator + absent periods | `mfspv/accumulator` | `§T2` |
| Bundle build/serialize/verify/reanchor | `mfspv/bundle` | `§T3` |
| Alice offline wallet | `mfspv/wallet_alice` | `§T4` |
| Bob PoS wallet (verify, UTXO query, τ, broadcast) | `mfspv/wallet_bob` | `§T4,§T5` |
| Teranode read adapters | `mfspv/teranode_adapter` | `§T6` |
| Double-spend alert (IPv6 multicast) | `mfspv/dsalert` | `§T5` |
| Scaling simulator (10⁶→10¹⁰ tx/s) | `mfspv/bench` | `03_SCALING_MODEL.md` |

Build order: `commitment → bundle → {wallet_alice, wallet_bob} → teranode_adapter → accumulator → dsalert → bench`.
