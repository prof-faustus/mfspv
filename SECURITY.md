# MF-SPV — Security audit (red-team pass)

This records an adversarial review of the security-critical code and the fixes
applied. Standard set by the project: **"SECURITY is 100% perfect or fail."**

Threat model (from `01_ARCHITECTURE.md §6` / `PAPER.md §3`): the adversary may
present forged inclusion proofs, an alternative header chain, fabricated alerts,
malformed bundles, or a malicious miner's false L4 root. The adversary cannot
break SHA-256 (collision/second-preimage) or forge ECDSA.

## Findings and fixes

### RT-1 (HIGH, FIXED) — L4 anchor PoW bypass
**Was:** `bundle.Verify`'s L4 branch trusted `Anchor.CarryingBlockMerkleRoot`, an
attacker-supplied value, and never bound it to a header on the verifier's chain.
An attacker could therefore fabricate an accumulator root, commit it in a fake
generation transaction folding to a fake carrying-block root, and prove any header
"in chain" — defeating proof-of-work for header-pruned verifiers.
**Fix:** `AnchorProof` now carries the full `CarryingHeader`. The verifier requires
`headersView.Contains(CarryingHeader)` **and**
`HeaderMerkleRoot(CarryingHeader) == CarryingBlockMerkleRoot` before trusting the
anchor (`bundle.anchorBindsToChain`). The accRoot now provably inherits PoW through
a header the verifier actually holds. Regression: `adversarial.TestRT1_*`,
positive path: `bundle.TestL4PrunedVerifier` (a pruned `StaticHeaderChain` holding
only the recent carrying header).

### RT-2 (HIGH, FIXED) — forgeable double-spend evidence
**Was:** `dsalert.VerifyAlert` accepted any two distinct 32-byte hashes as a
"conflict." Anyone could fabricate *verified* alerts for any outpoint, flooding the
alert layer to censor/deny legitimate 0-conf payments (the very DoS the layer is
meant to gate against, I-DS1).
**Fix:** `ConflictEvidence` now carries the owner's compressed public key and **two
ECDSA signatures** over `H(outpoint ‖ spendTxID)` for two distinct spends.
`VerifyAlert` parses the key, checks both signatures are valid and canonical
(low-S), and only then accepts. Forging an alert now requires the outpoint owner's
private key — i.e. it can only be produced by an actual double-spender. Tests:
`dsalert.TestT5_1_EvidenceGated`, `TestFloodIneffective`, `adversarial.TestA4_*`.

### RT-7 (HIGH, FIXED) — alert owner-key not bound to the outpoint (RT-2 was incomplete)
**Was:** after RT-2, `VerifyAlert` proved "the holder of `OwnerPubKey` signed two
spends of outpoint O" — but never checked that `OwnerPubKey` is authorised to spend
O. An attacker could generate their OWN key, sign two messages naming a victim's
outpoint, and produce a "valid" alert, reopening the flood/censorship vector with a
different key.
**Fix:** the point-of-sale check is now owner-bound. `Bus.QuietForOwners` matches a
verified alert only when its signing key equals the key actually spending the output
in the payment under evaluation; `walletbob.AcceptPayment` passes each input's
pubkey. A third party signing a bogus conflict with their own key is ignored; only
the real spender's double-spend flips acceptance. Tests:
`dsalert.TestRT7_OwnerBoundAlerts`, `walletbob.TestTauAndAlertBehaviour`
(non-owner alert does not flip; owner-signed alert does). The owner-agnostic
`QuietFor` is retained for advisory use only.

### RT-3 (MEDIUM, FIXED) — ECDSA signature malleability
**Was:** raw `crypto.Verify` accepts both `(r, s)` and `(r, n−s)`; the payment
verifier did not enforce canonical form, so a third party could malleate an
in-flight transaction's id.
**Fix:** `crypto.Signature.IsLowS()` added; `payment.VerifyInputSignature` rejects
non-canonical (high-S) signatures. Signing already produced low-S. Test:
`adversarial.TestRT3_HighSRejected` (confirms the malleated sig still verifies under
raw ECDSA but is rejected by the payment layer).

## Confirmed-safe (tested, no change needed)

- **RT-4 — Merkle internal-node-as-leaf / 64-byte-preimage attack.** Classic SPV is
  vulnerable to passing an internal node off as a leaf. MF-SPV is not: L0 is
  mandatory, so a claimed TXID must be reconstructed from revealed fields
  (`mtxid == OutputRef.TXID`). Matching an internal node would require a SHA-256
  preimage. `adversarial.TestRT4_InternalNodeAsLeafRejected` (shortened path +
  internal node ⇒ rejected at L0; bare-TXID bundle ⇒ rejected at L0).
- **RT-5 — serialization DoS.** Length-prefixed reader is bounded by the input
  buffer and caps path lengths at the depth ceiling; oversized prefixes fail fast
  with no large allocation. `adversarial.TestRT5_SerializationDoS`.
- **RT-6 — boundary path lengths.** Subtree paths > 20 and composed depth > 255 are
  hard-rejected (`depth-overflow`). `adversarial.TestRT6_BoundaryPathLengths`,
  `commitment.TestT1_6_DepthCeiling`, `TestSubtreePathCap`.
- **Inclusion soundness / forgery (A1), alternative chain (A2), spam (A3), orphan
  re-anchor (A5).** All assert rejection; see `adversarial/adversarial_test.go`.

## Residual, documented (not code defects)

- **secp256k1 signer is `math/big`-based, not constant-time.** Correct and
  dependency-free; constant-time hardening / swapping for the node's audited curve
  is a deployment task. Inclusion soundness does not depend on it.
- **Live Teranode wiring.** Interfaces are read-only by construction (I-TA1); the
  `MockNode` builds real trees and a real accumulator. Binding to a pinned Teranode
  revision is the remaining integration step (01 §7 dependency #2).
- **Alert-to-owner binding.** RT-7 binds an accepted alert to the *pubkey spending
  the output in the payment* (`QuietForOwners`), closing third-party forgery. The
  remaining nuance — proving that pubkey is the UTXO's rightful owner per its locking
  script — is part of script-level validation (the deployment residual above), not
  the alert layer.
- **Value conservation.** Now enforced at the till via `ValueOracle` (Σ inputs ≥
  Σ outputs; I-BB6, `walletbob.TestValueConservation`). Full *script* validation
  remains node-standard and orthogonal to the MF-SPV proof.

## Test posture

74 tests pass (forced, no cache; order-independent under `-shuffle=on`): T1–T7 and
A1–A5; the red-team suite RT-1..7; and the publication-grade evaluation of
`06_EVALUATION_DESIGN.md` — known-answer tests (double-SHA256, secp256k1 2G, RFC 6979
nonce), a differential Merkle oracle over odd cardinalities, property tests at 10⁵
cases, Monte-Carlo inclusion-forgery (10⁶ trials, 0 accepted, Clopper–Pearson
`p_upper ≤ 4.6×10⁻⁶`), and a scaling-law regression rejecting linear-in-T
(R²(log)=0.999 vs R²(T)=0.40); plus scale/capacity/throughput at 10¹¹ tx/s.
`go vet` and `gofmt` clean. Every adversarial test asserts a **rejection**.
