# MF-SPV — Test Plan

Tests are grouped by module. Each test states the property and the pass condition.
Security tests assert that forgeries are REJECTED; correctness tests assert valid inputs PASS;
performance tests assert the scaling laws of `03_SCALING_MODEL.md`. BSV only.

## T1 — commitment (L0–L2)
- T1.1 **Round-trip:** BuildMTxID then MTxIDPath/VerifyMTxIDPath passes for every field index.
- T1.2 **Forgery rejected:** flip one byte of any sibling ⇒ Verify*Path == false. (I-C1)
- T1.3 **Depth law:** for synthetic blocks at r ∈ {1e6…1e10}, VerifyToBlockRoot reports
  depth == ceil(log2 T). (Result 4.1 / I-BE1)
- T1.4 **Determinism:** BuildMTxID twice on identical fields ⇒ identical root + layers. (I-C1)
- T1.5 **Reconstruct-from-root+fields:** drop `layers`, rebuild from fields, root matches. (US 2022/0216997 [0166])
- T1.6 **Depth ceiling:** a crafted >255 path is a hard error. (I-C3)

## T2 — accumulator (L4) and absent periods
- T2.1 **Append-only provability:** append K headers; every previously proven height stays provable. (I-A1)
- T2.2 **PoW binding:** VerifyBlockInChain on an accRoot that has NOT passed VerifyAnchor is treated
  as unverified (test asserts the coupling is enforced). (I-A2)
- T2.3 **Gap honesty:** with a committed-height set containing holes, a height in a hole returns
  inGap==true and NO false "in chain". (I-A3 / §6.4) — this test is mandatory; it encodes the
  disclosed limitation.
- T2.4 **Fork buys gaplessness (negative control):** document/test that a full-header verifier (L4
  unused) is unaffected by gaps.

## T3 — bundle
- T3.1 **End-to-end valid:** a bundle from a real (simulated) sealed block passes Verify with a
  HeaderChain that Contains the header.
- T3.2 **Fail-fast reasons:** corrupt each level in turn ⇒ Verify returns the matching reason
  (L0/L1/L2/L3-bind/L3-L4-chain) and stops at first failure.
- T3.3 **Frozen core (anti-Utreexo):** after a reorg + Reanchor, MTxIDPath/SubtreePath/BlockPath/
  Header are byte-identical to before; only Anchor/chain selection changed. (I-B1 / §5.3)
- T3.4 **Reanchor:** NeedsReanchor true iff header off best chain; Reanchor restores Verify==true
  on the new best chain.
- T3.5 **Inclusion ≠ double-spend (negative):** a bundle for an output that has since been spent
  STILL passes Verify (inclusion holds); the test asserts Verify alone does not imply spendable.
  (§6.3 / I-BB1)

## T4 — wallets
- T4.1 **Alice offline:** Sign/FillTemplate/Export run with network disabled. (I-AL1)
- T4.2 **TXID-only rejected:** Export omitting MTxID fields is rejected. (I-AL2)
- T4.3 **No keys at till:** wallet_bob holds no private keys; attempt to store one is rejected. (I-BB2)
- T4.4 **Acceptance separation:** AcceptPayment returns "accepted" only when inclusion AND unspent
  AND alert-quiet AND signature/template checks pass under RiskPolicy. (I-BB1)

## T5 — dsalert + double-spend at PoS
- T5.1 **Evidence-gated:** an alert with no verifiable conflict is dropped. (I-DS1)
- T5.2 **Conflict detected:** a genuine conflicting spend produces an alert that flips QuietFor false
  within the window, causing AcceptPayment to reject under a strict τ.
- T5.3 **τ behaviour:** sweep τ; show accept/reject boundary moves with value-at-risk and elapsed
  alert-quiet time; τ is read from RiskPolicy, never hard-coded. (I-BB3)

## T6 — teranode_adapter
- T6.1 **Read-only:** adapter exposes no mutation of header/block format; compile-time/interface check. (I-TA1)
- T6.2 **Subtree fidelity:** SubtreePathFor matches Teranode's actual subtree membership on a fixture
  block (path ≤20). (I-TA2)
- T6.3 **Pinned revision:** adapter builds against the pinned Teranode commit; signature drift fails CI.

## T7 — bench / scaling (falsifiable paper claims)
- T7.1 depth == ceil(log2 T) for all r. (I-BE1)
- T7.2 proofBytes == 32·depth. (I-BE2)
- T7.3 HeaderGrowthBytesPerYear constant ≈ 4.2e6 across all r. (I-BE3 / Result 4.2)
- T7.4 verifyMS grows ∝ depth (log), confirmed by regression of verifyMS on log2(T) (slope finite,
  linear-in-T hypothesis rejected). (I-BE4 / Result 4.3)
- T7.5 push-model proof network bytes == 0; pull-model comparison row > 0 and grows with depth. (Result 4.4)

## Adversarial / red-team (must all be REJECTIONS)
- A1 collision-free forgery of any path ⇒ reject.
- A2 alternative header chain without majority work ⇒ not Contained, not anchored ⇒ reject.
- A3 spam of malformed bundles ⇒ rejected at first failing hash, O(depth), no network call.
- A4 alert flooding without evidence ⇒ dropped.
- A5 a bundle anchored to an orphaned block ⇒ NeedsReanchor true; Verify false until reanchored.
