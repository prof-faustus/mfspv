# MF-SPV — Module Specifications (for implementation by Claude Code)

This file defines interfaces, data structures, invariants, and the exact conditions each
function must satisfy. It is a contract, not an implementation. Language: Go (Teranode-native).
Hash: SHA-256d (double SHA-256), 32-byte digests. Endianness: follow Teranode's `chainhash.Hash`.
**BSV only. No BTC parameters, no BTC code paths.**

Conventions:
- `Hash = [32]byte`.
- A "path" is `[]PathElem` ordered leaf→root; `PathElem{Sibling Hash; Right bool}` where `Right`
  means the sibling is the right child (so `parent = H(node ‖ sibling)`), else `H(sibling ‖ node)`.
- All `Verify*` functions are pure, allocation-light, and return `(ok bool)` plus the recomputed
  root where useful. They MUST NOT call the network.

---

## `mfspv/commitment`

Builds and verifies levels L0–L2. Leaf hashing is reused from Teranode subtree construction
where possible (do not re-hash transactions Teranode already hashed).

### Types
```
type FieldLeaf struct { Index uint8; Bytes []byte }      // a transaction field (L0 leaf)
type TxFields  []FieldLeaf                                // ordered per US 2022/0216997 Fig.6 layout
```

### Functions
```
// L0: build the field tree of a transaction; root == MTxID == TXID (unified form).
BuildMTxID(fields TxFields) (mtxid Hash, layers [][]Hash, err error)
    INVARIANT: re-running on the same fields yields the identical root (determinism).
    INVARIANT: storing only `mtxid` + fields suffices to rebuild `layers` (US 2022/0216997 [0166]).

// L0 path for a single revealed field (privacy: reveal one field, not the whole tx).
MTxIDPath(fields TxFields, fieldIndex uint8) (leaf Hash, path []PathElem, mtxid Hash, err error)
VerifyMTxIDPath(leaf Hash, path []PathElem, mtxid Hash) (ok bool)
    CONDITION: ok ⇔ folding `leaf` along `path` equals `mtxid`.

// L1: TXID → subtree root (Teranode subtree). Path provided by teranode_adapter.
VerifySubtreePath(txid Hash, path []PathElem, subtreeRoot Hash) (ok bool)
    CONDITION: |path| ≤ 20 for a ≤2^20-leaf subtree; ok ⇔ fold(txid,path)==subtreeRoot.

// L2: subtree root → block Merkle root.
VerifyBlockPath(subtreeRoot Hash, path []PathElem, blockMerkleRoot Hash) (ok bool)

// Composed core verification L0→L2 in one call (the hot path Bob runs).
VerifyToBlockRoot(leaf Hash, l0,l1,l2 []PathElem, blockMerkleRoot Hash) (ok bool, depth int)
    CONDITION: depth == |l0|+|l1|+|l2|; for a block of T txs over 2^20-subtrees,
               depth == ceil(log2 T)  (this is asserted by 04_TEST_PLAN §T1.3).
```

### Invariants for the whole module
- I-C1 **Soundness:** no input other than the true sibling set folds to the correct root, except
  on a SHA-256 collision (assumed infeasible).
- I-C2 **No network:** the module imports no client/transport package.
- I-C3 **Depth bound:** any path length ≤ 255 (one-byte depth marker, `Appendix_2_Merkle`); a longer
  path is a hard error (cannot occur below 2^255 leaves).

---

## `mfspv/accumulator` (OPTIONAL L4; only for header-pruned verifiers)

Append-only MMR over sealed block headers; root committed in a generation transaction.

### Functions
```
type MMR struct { /* peaks []Hash; size uint64 */ }
(m *MMR) Append(header80 [80]byte) (root Hash)         // O(log n) amortised
(m *MMR) ProveBlock(height uint64) (path []PathElem, root Hash, err error)
VerifyBlockInChain(header80 [80]byte, path []PathElem, accRoot Hash) (ok bool)

// Bind accRoot to PoW: accRoot lives in a generation tx whose own L0–L2 path closes to a
// sealed block. This composes with commitment.VerifyToBlockRoot.
VerifyAnchor(accRoot Hash, genTxFields TxFields, l0,l1,l2 []PathElem,
             carryingBlockMerkleRoot Hash) (ok bool)

// Absent-periods coverage (US 2022/0216997 [0222]-[0223]).
type ParticipationGap struct { FromHeight, ToHeight uint64 }
CoverageGaps(committedHeights []uint64, tipHeight uint64) []ParticipationGap
NearestCommitted(height uint64, committedHeights []uint64) (h uint64, inGap bool)
```

### Invariants
- I-A1 **Append-only:** `Append` never rewrites historical peaks; a proven block stays provable.
- I-A2 **PoW binding:** `VerifyBlockInChain` is meaningful only when `accRoot` passed `VerifyAnchor`
  (i.e. it is committed in a PoW-sealed generation tx). Document this coupling; tests enforce it.
- I-A3 **Gap honesty:** `CoverageGaps` MUST return real gaps; a verifier in a gap MUST get
  `inGap==true` and fall back (never a false "in chain"). This is the §6.4 limitation made explicit
  in code, not hidden.

---

## `mfspv/bundle`

The sender-held proof object (§3.1) and its lifecycle.

### Types
```
type Bundle struct {
  OutputRef    struct{ TXID Hash; Vout uint32 }
  Fields       commitment.TxFields
  MTxIDPath    []PathElem      // L0 (revealed field only)
  SubtreePath  []PathElem      // L1
  BlockPath    []PathElem      // L2
  Header       [80]byte        // L3
  Anchor       *AnchorProof    // L4, optional (nil when verifier keeps full headers)
}
type AnchorProof struct {
  AccRoot Hash; AccPath []PathElem
  GenTxFields commitment.TxFields; GenL0,GenL1,GenL2 []PathElem; CarryingBlockMerkleRoot Hash
  CarryingHeader [80]byte   // SECURITY (RT-1): the carrying block's full header.
}
// RT-1 (red-team fix): the L4 branch MUST bind CarryingBlockMerkleRoot to a header
// the verifier actually trusts, else accRoot inherits no PoW (an attacker could
// supply any CarryingBlockMerkleRoot). The verifier requires:
//   headersView.Contains(CarryingHeader) AND
//   HeaderMerkleRoot(CarryingHeader) == CarryingBlockMerkleRoot
// before trusting VerifyAnchor/VerifyBlockInChain. See bundle.anchorBindsToChain.
```

### Functions
```
Build(out OutputRef, fields TxFields, src ProofSource) (Bundle, error)   // src = teranode_adapter
Serialize(b Bundle) ([]byte, error)                                      // compact, length-prefixed
Deserialize([]byte) (Bundle, error)

// The verification Bob runs locally (NO network). headersView answers "is this header in my chain?"
Verify(b Bundle, headersView HeaderChain) (ok bool, depth int, reason string)
   STEPS (all must pass; first failure returns its reason — fail-fast):
     1. fold revealed field along MTxIDPath  → mtxid(=TXID)            ; else reason="L0"
     2. VerifySubtreePath(TXID, SubtreePath) → subtreeRoot             ; else reason="L1"
     3. VerifyBlockPath(subtreeRoot, BlockPath) → blockMerkleRoot      ; else reason="L2"
     4. blockMerkleRoot == Header.merkleRoot                           ; else reason="L3-bind"
     5a. headersView.Contains(Header)                                  ; else go to 5b
     5b. if Anchor!=nil AND anchorBindsToChain(Anchor,headersView):
            (i.e. headersView.Contains(Anchor.CarryingHeader)
             AND HeaderMerkleRoot(CarryingHeader)==CarryingBlockMerkleRoot
             AND accumulator.VerifyAnchor(...))                        // RT-1 PoW binding
         then VerifyBlockInChain(Header, Anchor.AccPath, Anchor.AccRoot); else reason="L3/L4-chain"
   NOTE: Verify proves INCLUSION only. It is FAIL-FAST against spam/error, NOT double-spend
         protection (see wallet_bob for double-spend).

// Maintenance.
NeedsReanchor(b Bundle, headersView HeaderChain) bool   // true iff Header no longer on best chain
Reanchor(b *Bundle, src ProofSource) error              // refresh after a reorg; L0–L2 unchanged
```

### Invariants
- I-B1 **Frozen core:** for a buried, non-orphaned block, `MTxIDPath/SubtreePath/BlockPath/Header`
  are immutable; `Reanchor` MUST NOT alter them (it only updates `Anchor` / re-selects chain).
  (This is the §5.3 improvement over Utreexo; a test asserts byte-equality across calls.)
- I-B2 **Self-contained:** `Verify` needs only the bundle + a `HeaderChain` view; no other I/O.
- I-B3 **Minimal reveal:** `Build` includes only the revealed field(s)' L0 path, never the whole
  field set's paths (privacy, §6.6).

---

## `mfspv/wallet_alice` (offline customer wallet)

Mirrors the project's off-line SPV wallet spec.

### Responsibilities / functions
```
Store: spendable outputs' Bundles, private/public keys, (optional) headers.
Sign(tx Tx, inputIdx int, key PrivKey) (sig []byte, err error)   // ECDSA; works offline
FillTemplate(template Tx3, inputs []Bundle, change PubKey) (signedTx Tx3, err error)
Export(inputs []Bundle, signedTx Tx3) ([]byte, error)            // the message [2] payload to Bob
```
### Invariants
- I-AL1 **Offline-complete:** every function is computable with no network access (smart-card capable).
- I-AL2 **TXID sufficiency:** providing only a TXID is INSUFFICIENT; the wallet always exports the
  fields needed to reconstruct MTxID (project requirement). Enforce in `Export`.

---

## `mfspv/wallet_bob` (point-of-sale merchant wallet)

### Responsibilities / functions
```
HeaderChain view: keeps the constant ~4.2 MB/year header chain (or pruned + Anchor fallback).
AcceptPayment(msg []byte, policy RiskPolicy) (Decision, error)
   1. Deserialize bundles + Tx3.
   2. For each input: bundle.Verify(...)            → inclusion (fail-fast).   [LOCAL]
   3. For each input.OutputRef: utxoClient.IsUnspent(outpoint).               [NETWORK: Teranode utxo]
   4. dsalert.QuietForOwners({outpoint→input.PubKey}, policy.Window)  → no owner-bound
      conflicting-spend alert seen (RT-7).                            [NETWORK: alert bus]
   5. Verify Alice's signatures (canonical low-S only, RT-3); verify Tx3 matches template.
   5b. Value conservation: if the UTXOClient implements ValueOracle, require
       Σ input values ≥ Σ output values, else reason="value:underfunded" (I-BB6). [NETWORK]
   6. Decision = policy.Decide(valueAtRisk, allInclusionOK, allUnspent, alertQuiet, elapsed).
Broadcast(tx Tx3) error                                                      [NETWORK]
type RiskPolicy struct { Tau float64; Window time.Duration; /* merchant-set */ }
```
### Invariants
- I-BB1 **Separation:** inclusion (step 2) and double-spend (steps 3–4) are distinct; a passing
  step 2 NEVER alone yields "accepted". (Encodes §6.3.)
- I-BB2 **No keys at till:** wallet stores only receiving public keys, never private keys.
- I-BB3 **τ is policy:** the protocol provides signals; the accept/reject threshold is `RiskPolicy`,
  owned by the merchant, never hard-coded in the protocol.
- I-BB4 **Canonical signatures (RT-3):** non-canonical (high-S) input signatures are rejected
  (malleability defence), via `payment.VerifyInputSignature` / `crypto.Signature.IsLowS`.
- I-BB5 **Owner-bound alerts (RT-7):** the alert check is keyed to the spending input's pubkey
  (`QuietForOwners`); alerts signed by any other key are ignored.
- I-BB6 **Value conservation:** an underfunded payment (Σ inputs < Σ outputs) is rejected when a
  `ValueOracle` is available; without one, value validation is delegated to the node at broadcast.

---

## `mfspv/teranode_adapter`

Read-only adapter over a pinned Teranode revision. Provides `ProofSource` and `HeaderChain`.

### Interfaces to satisfy (confirm exact signatures against pinned source — see 01 §7 dep #2)
```
type ProofSource interface {
  SubtreePathFor(txid Hash) (path []PathElem, subtreeRoot Hash, err error)   // from subtree store
  BlockPathFor(subtreeRoot Hash, blockHash Hash) (path []PathElem, root Hash, err error)
  HeaderFor(blockHash Hash) ([80]byte, error)
  GenTxAccumulator(blockHash Hash) (accRoot Hash, fields TxFields, l0,l1,l2 []PathElem, err error) // L4
}
type HeaderChain interface { Contains(h [80]byte) bool; BestTipHeight() uint64 }
type UTXOClient interface { IsUnspent(outpoint Outpoint) (bool, error) }   // Teranode utxo/asset
type ValueOracle interface { OutputValue(outpoint Outpoint) (value uint64, unspent bool, err error) } // value conservation (I-BB6)
```
### Invariants
- I-TA1 **No consensus mutation:** adapter is read-only; it never proposes header or block format change.
- I-TA2 **Subtree fidelity:** `SubtreePathFor` returns Teranode's actual subtree membership path
  (≤20 elems), not a recomputed alternative.

---

## `mfspv/dsalert` (double-spend alert layer)

IPv6-multicast alerts; project's reputation/PoW-attested alert mechanism.

```
Subscribe(group IPv6Group) (<-chan Alert, error)
type ConflictEvidence struct {                 // RT-2: cryptographically verifiable
  OwnerPubKey []byte                           // 33-byte compressed key
  SpendA Hash; SigA []byte                     // owner sig over H(outpoint‖SpendA)
  SpendB Hash; SigB []byte                     // owner sig over H(outpoint‖SpendB)
}
type Alert struct { Outpoint Outpoint; Evidence ConflictEvidence; AttesterPoW []byte }
SignSpend(key, out, spendTx) ([]byte,error)            // owner authorisation of a spend
BuildEvidence(key, out, spendA, spendB) (ConflictEvidence,error)
Attest(out, ev) Alert                                  // mines PoWBits over the whole alert
VerifyAlert(a Alert) (ok bool)                         // see I-DS1
QuietFor(outpoints, window) (quiet bool)                   // owner-AGNOSTIC, advisory only
QuietForOwners(map[Outpoint][]byte, window) (quiet bool)   // owner-BOUND (RT-7), PoS use
```
### Invariants
- I-DS1 **Evidence-gated (RT-2):** an admissible alert MUST carry two DISTINCT spends
  of the same outpoint, BOTH signed (canonical low-S) by the SAME `OwnerPubKey`, plus a
  valid PoW attestation. Two bare hashes are NOT evidence; forging an alert requires the
  owner's private key. Prevents alert-flooding as a censorship/DoS vector.
- I-DS3 **Owner-bound at PoS (RT-7):** the merchant counts a conflict only when the
  alert's `OwnerPubKey` equals the key spending the output in the payment under
  evaluation (`QuietForOwners`); a third party cannot manufacture a conflict for an
  outpoint they do not own.
- I-DS2 **Advisory:** alerts feed `RiskPolicy`; they are not consensus.

---

## `mfspv/bench` (scaling simulator — see 03_SCALING_MODEL.md)

```
SimulateBlock(r_tx_per_s float64) (T uint64, depth int, proofBytes int, buildMS, verifyMS float64)
SweepThroughput(rs []float64) (rows []BenchRow)   // r ∈ {1e6,1e7,1e8,1e9,1e10}
HeaderGrowthBytesPerYear() int                     // must return ~4.2e6 independent of r
```
### Invariants (these are the falsifiable claims of the paper)
- I-BE1 `depth == ceil(log2 T)` for every row (Result 4.1).
- I-BE2 `proofBytes == 32*depth`.
- I-BE3 `HeaderGrowthBytesPerYear()` is constant across all `r` (Result 4.2).
- I-BE4 `verifyMS` grows logarithmically (∝ depth), not linearly, in `T`.
