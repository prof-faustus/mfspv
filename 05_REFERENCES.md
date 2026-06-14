# 05 — References (verified URLs, read-depth, tier scoring)

This file governs what the paper (`PAPER.md`) is permitted to treat as **evidence**.

## Reading conventions (enforced)

**Depth tags** — what was actually read, stated plainly:
- `[FULL]` — full primary text read (this session or a prior session via an uploaded PDF). Load-bearing permitted.
- `[CORROBORATED]` — primary paper PDF was **robots-blocked** from the fetcher; the *claim attributed to it* is confirmed across ≥2 independent primary/authoritative sources (e.g. the authors' own project page and official code repository). Load-bearing **only** for the specifically corroborated claim, not for paper internals.
- `[SUBSTANTIAL]` — significant body text (beyond the abstract) was returned and read, but not the whole paper. Usable for positioning; **not** load-bearing for any quantitative or security claim.
- `[ABSTRACT]` — only the abstract / landing page / a third-party bibliography entry was seen. **Not analysed in full.** Per the governing standard, relying on this as evidence is fraud; therefore these contribute **0** to the evidence tally and the paper does **not** rest any claim on them. They are listed for completeness and to position the work.

**Tier scoring** (user rubric): Tier 1/2 venue = 1.0 (full citation); Tier 3/4 = 0.5; Tier 5 = 0.2; textbook = 0.1; non-peer-reviewed (preprint, patent, docs, repo, blog) = 0.01. **A work scores its points only if the full work was analysed.** An `[ABSTRACT]`-only or `[CORROBORATED]`-only item scores 0 on the evidence tally regardless of venue, because the full work was not analysed.

**Venue-tier mapping is my classification, not gospel** — stated so the author can re-tier. Mapping used: IEEE S&P / ACM CCS / CRYPTO = Tier 1 conference; Financial Cryptography (FC) / ASIACRYPT / ESORICS = Tier 2; arXiv / IACR ePrint preprints = non-peer-reviewed (0.01) until the venue of record is confirmed; granted patents and vendor documentation = non-peer-reviewed (0.01).

---

## A. Primary design sources — `[FULL]` (the basis of our own construction)

These are fully read from primary source. They are the foundation of MF-SPV. On the citation rubric they are non-peer-reviewed (0.01 each); their value is as primary design inputs, not as peer-reviewed evidence. Both facts are stated.

- **[P1]** nChain Holdings Ltd. *Verification of Data Fields of Blockchain Transactions.* US 2022/0216997 A1 (publ. 2022-07-07). `[FULL]` (OCR + figures read from source). https://patents.google.com/patent/US20220216997A1/en — Tier: patent, 0.01. **Load-bearing for:** MTxID = Merkle tree over transaction *fields* (Fig. 6); root committed in the generation transaction ([0164],[0168]); the absent-periods limitation and the R_M inter-miner patch ([0222]–[0223]).
- **[P2]** nChain. *Sharing data via transactions of a blockchain.* US 11,893,074 (granted 2024-02-06; PCT/IB2020/057799; UK priority 1913144.0). `[FULL]`. https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/11893074 — Tier: patent, 0.01. **Load-bearing for:** request/response data delivery over transactions, ECDH-derived side secret, integrity tagging (the optional encrypted-delivery path, App. C of the paper).
- **[P3]** Author appendix. *Safe Low-Bandwidth SPV* (Appendix 1 / Chapter 4, supplied document). `[FULL]`. Local: `/mnt/project/Appendix_1_SPV_-_Copy.docx`. Tier: unpublished, 0.01. **Load-bearing for:** the Merchant→Customer→Merchant→Network flow; offline customer holding her own Merkle paths; Merkle proof as fail-fast not double-spend; UTXO-seen + IPv6-multicast alerts + merchant risk parameter τ; 80-byte headers, 4.2 MB/yr constant.
- **[P4]** Author appendix. *Multilevel Merkle file validation* (Appendix 2, supplied document). `[FULL]`. Local: `/mnt/project/Appendix_2_Merkle_-_Copy.docx`. Tier: unpublished, 0.01. **Load-bearing for:** depth‖position‖segment leaf encoding; per-segment retransmission; one-byte depth marker (max depth 255).
- **[P5]** BSV Association. *Teranode* (architecture, subtree data model, services). `[FULL]` across four independent primary sources. Tier: vendor docs/engineering, 0.01. **Load-bearing for:** subtrees as batches of TXIDs with full Merkle-path connectivity (≤ ~2²⁰), broadcast ~per second; block root built over subtree roots (the native two-level tree); Asset service `GetTransaction`, `subtreeStore`, `utxoStore`; >1M TPS testnet, 4 GB mainnet blocks; Go codebase.
  - AWS Web3 engineering blog: https://aws.amazon.com/blogs/web3/how-the-bsv-association-built-a-million-tps-blockchain-node-using-aws
  - Docs: https://docs.bsvblockchain.org/network-topology/nodes/teranode
  - Asset service reference: https://bsv-blockchain.github.io/teranode/references/services/asset_reference/
  - Operator repo: https://github.com/bsv-blockchain/teranode-operator

---

## B. Literature relied upon — `[FULL]` / `[CORROBORATED]`

- **[L1]** B. Bünz, L. Kiffer, L. Luu, M. Zamani. *FlyClient: Super-Light Clients for Cryptocurrencies.* IEEE S&P 2020. `[FULL]` (uploaded PDF, prior session — verbatim engagement with the (c,L) assumption, the optimal sampling distribution g(x), and the "regular SPV proof" inclusion step). DOI https://doi.org/10.1109/SP40000.2020.00049 ; ePrint https://eprint.iacr.org/2019/226 — **Tier 1 conference, full-analysed → 1.0 (COUNTS).** Used as the principal point of contrast (header-sync axis; stronger (c,L) assumption; header fork).
- **[L2]** P. Chatzigiannis, F. Baldimtsi, K. Chalkias. *SoK: Blockchain Light Clients.* Financial Cryptography 2022. `[FULL]` (FC22 preproceedings text + complete bibliography read). DOI https://doi.org/10.1007/978-3-031-18283-9_31 ; ePrint https://eprint.iacr.org/2021/1657 ; preproceedings https://fc22.ifca.ai/preproceedings/176.pdf — **Tier 2 conference, full-analysed → 1.0 (COUNTS).** Used as the authoritative taxonomy and as the umbrella citation for the PoPoW/recursive-SNARK compression family we decline to adopt.
- **[L3]** T. Dryja. *Utreexo: A dynamic hash-based accumulator optimized for the Bitcoin UTXO set.* IACR ePrint 2019/611. `[CORROBORATED]` — ePrint PDF robots-blocked; the load-bearing claim (the fund owner maintains and supplies the inclusion proof at spend time = the "push" model) is confirmed by the authors' MIT DCI project page and the official repository. ePrint https://eprint.iacr.org/2019/611 ; MIT DCI https://dci.mit.edu/projects/utreexo ; repo https://github.com/mit-dci/utreexo — Tier: preprint, **0 counted** (full paper not analysed). Used only for the push-model precedent, which MF-SPV improves by freezing historical paths.

**Evidence tally meeting the "full work analysed" bar: [L1] + [L2] = 2.0 points (two Tier 1/2, full-analysed).** No other listed work clears that bar; see §C.

---

## C. Positioning references — `[SUBSTANTIAL]` / `[ABSTRACT]` (verified URL, **0 evidence points**, not load-bearing)

Listed because they are real, relevant, and locate MF-SPV in the field. Each has a verified URL. None is analysed in full; **the paper relies on none of them for any claim.** Where the paper mentions them it says "full-text deep-read pending."

Recent (within three years of June 2026):
- **[R1]** *SNARK-based superlight-client query verification.* arXiv 2503.08359 (2025). `[SUBSTANTIAL]`. https://arxiv.org/abs/2503.08359 — preprint, 0.
- **[R2]** *Carbyne* (mempool design). arXiv 2504.16089 (2025). `[SUBSTANTIAL]`. https://arxiv.org/abs/2504.16089 — preprint, 0. (DoS-surface context.)
- **[R3]** *Neonpool: Reimagining cryptocurrency transaction pools for lightweight clients and IoT.* arXiv 2412.16217 (2024). `[SUBSTANTIAL]`. https://arxiv.org/abs/2412.16217 — preprint, 0.
- **[R4]** *Verkle trees / vector commitments with updates.* arXiv 2307.04085 (2023). `[ABSTRACT]`. https://arxiv.org/abs/2307.04085 — preprint, 0. (VC-vs-Merkle context.)
- **[R5]** Y. Ozmiş. *Applications of Zero-Knowledge Proofs on Bitcoin* (includes a STARK ZK light client for the PoW header chain). arXiv 2507.21085 (2025) = IACR ePrint 2025/1271. `[SUBSTANTIAL]` (abstract + preliminaries read). https://arxiv.org/abs/2507.21085 ; https://eprint.iacr.org/2025/1271 — preprint, 0.
- **[R6]** M. Xu et al. *EC-Chain: Cost-Effective Storage Solution for Permissionless Blockchains.* arXiv 2412.05502 (2024). `[ABSTRACT]`. https://arxiv.org/abs/2412.05502 — preprint, 0.
- **[R7]** *Enhancing Blockchain Cross-Chain Interoperability: A Comprehensive Survey.* arXiv 2505.04934 (2025). `[SUBSTANTIAL]` (light-client section read). https://arxiv.org/abs/2505.04934 — preprint, 0. (Umbrella for light-client taxonomy alongside [L2].)
- **[R8]** *Unconditionally Safe Light Client.* arXiv 2405.01459 (2024). `[SUBSTANTIAL]` (related-work section read). https://arxiv.org/abs/2405.01459 — preprint, 0. (PoS-economic-security framing, contrasted with our PoW design.)
- **[R9]** *TeleBTC: Trustless Wrapped Bitcoin.* arXiv 2307.13848 (2023). `[SUBSTANTIAL]` (light-client-bridge section read). https://arxiv.org/abs/2307.13848 — preprint, 0.
- **[R10]** F. Armknecht et al. *Practical Light Clients for Committee-Based Blockchains.* arXiv 2410.03347 (2024). `[ABSTRACT]`. https://arxiv.org/abs/2410.03347 — preprint, 0.
- **[R11]** ZeroSync. *STARK proofs for the Bitcoin header chain* (project + code). 2024. `[SUBSTANTIAL]` (project description + repo). https://github.com/ZeroSync/header_chain — non-peer-reviewed, 0.

Older positioning:
- **[L4]** *TxChain: Efficient Cryptocurrency Light Clients via Contingent Transaction Aggregation.* IACR ePrint 2020/580. `[ABSTRACT]`. https://eprint.iacr.org/2020/580 — preprint, 0. The paper refutes its *pull* premise ("to verify a transaction the corresponding block must be downloaded") at the level of paradigm, not by relitigating its internals.
- **[L5]** A. Kate, G. Zaverucha, I. Goldberg. *Constant-Size Commitments to Polynomials (KZG).* ASIACRYPT 2010. `[ABSTRACT]`. DOI https://doi.org/10.1007/978-3-642-17373-8_11 — Tier 1 conference **but abstract-only → 0 counted.** Cited only to record why KZG/Verkle is *rejected* (trusted setup; prover cost at 6×10¹² leaves); the rejection rests on the definitional trusted-setup property, not on this paper's internals.
- **[L6]** J. Bonneau, I. Meckler, V. Rao, E. Shapiro. *Coda/Mina: decentralized cryptocurrency at scale.* IACR ePrint 2020/352. `[ABSTRACT]`. https://eprint.iacr.org/2020/352 — preprint, 0. Recursive-SNARK constant-size-chain representative.
- **[L7]** K. Chalkias, F. Garillot, Y. Kondi, V. Nikolaenko. *Mithril: stake-based threshold multisignatures.* IACR ePrint 2021/916. `[ABSTRACT]`. https://ia.cr/2021/916 — preprint, 0.
- **[L8]** A. Kattis, J. Bonneau. *Proof of Necessary Work.* IACR ePrint 2020/190. `[ABSTRACT]`. https://eprint.iacr.org/2020/190 — preprint, 0.

---

## Tallies

- **Total distinct references:** 24 ([P1–P5], [L1–L8], [R1–R11]).
- **Requirement ≥ 20:** met (24).
- **Within three years (≥ June 2023):** [P2] 2024, [P5] 2025, [R1]–[R11] (11) = **13**. Excluding the two undated author appendices from the denominator: 13 / 22 = **59%**. Including them: 13 / 24 = 54%. **Requirement ≥ half:** met either way.
- **Peer-reviewed works analysed in full (counting on the evidence rubric):** [L1] 1.0 + [L2] 1.0 = **2.0**.
- **Everything else:** primary non-peer-reviewed sources we fully read ([P1–P5]; 0.01 each on the rubric but foundational to the design), one corroborated-but-PDF-blocked precedent ([L3]), and 18 positioning references at abstract/substantial depth contributing **0** to the evidence tally.

## Honest dependency (stated, not hidden)

`eprint.iacr.org` PDFs are robots-blocked from the fetcher. FlyClient ([L1], via prior uploaded PDF) and SoK ([L2], via FC22 preproceedings) were read in full through alternate routes; Utreexo ([L3]) and every other ePrint item were **not**. Before any §C claim is promoted to load-bearing in a journal submission, the corresponding full text must be obtained (author-supplied PDF or an open mirror) and re-read. Until then the paper's evidentiary weight rests on [P1]–[P5], [L1], [L2], and the corroborated push-model precedent [L3].
