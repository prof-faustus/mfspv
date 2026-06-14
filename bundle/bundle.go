// Package bundle is the sender-held proof object of MF-SPV (01_ARCHITECTURE.md
// §3.1, 02_MODULE_SPECS.md §bundle) and its lifecycle.
//
// A Bundle is what Alice holds per spendable output and ships to Bob with the
// payment. Bob runs Verify LOCALLY with no network call. Verify proves INCLUSION
// only; it is FAIL-FAST against spam/error, NOT double-spend protection (§6.3).
//
// Frozen-proof property (I-B1, §5.3, the improvement over Utreexo): once a block
// is sealed, MTxIDPath/SubtreePath/BlockPath/Header are immutable for a buried,
// non-orphaned block. Reanchor never alters them in that case.
//
// BSV only.
package bundle

import (
	"mfspv/accumulator"
	"mfspv/commitment"
	"mfspv/teranode"
)

type Hash = commitment.Hash
type PathElem = commitment.PathElem
type TxFields = commitment.TxFields

// OutputRef references a spendable output.
type OutputRef struct {
	TXID Hash
	Vout uint32
}

// AnchorProof is the OPTIONAL L4 material for a header-pruned verifier.
//
//	AccRoot                 : the accumulator root committed in a carrying gen tx
//	AccPath                 : MMR path proving Header's block is in AccRoot
//	GenTxFields/GenL0/L1/L2 : the carrying gen tx's commitment of AccRoot into a block
//	CarryingBlockMerkleRoot : that carrying block's PoW-sealed Merkle root
type AnchorProof struct {
	AccRoot                 Hash
	AccPath                 []PathElem
	GenTxFields             TxFields
	GenL0, GenL1, GenL2     []PathElem
	CarryingBlockMerkleRoot Hash
	// CarryingHeader is the FULL 80-byte header of the carrying block. The verifier
	// MUST confirm this header is on its (pruned) most-work chain and that its
	// committed Merkle root equals CarryingBlockMerkleRoot — otherwise accRoot does
	// not inherit PoW and an attacker could supply any CarryingBlockMerkleRoot. (RT-1)
	CarryingHeader [80]byte
}

// Bundle is the self-contained inclusion proof for one output.
type Bundle struct {
	OutputRef   OutputRef
	Fields      TxFields     // revealed field(s) only (minimal reveal, I-B3)
	MTxIDPath   []PathElem   // L0: revealed field -> MTxID(=TXID)
	SubtreePath []PathElem   // L1: TXID -> subtree root
	BlockPath   []PathElem   // L2: subtree root -> block Merkle root
	Header      [80]byte     // L3
	Anchor      *AnchorProof // L4 (nil when the verifier keeps full headers)
}

// HeaderMerkleRoot extracts the block Merkle root committed in an 80-byte header.
// Layout: version(4) ‖ prevhash(32) ‖ merkleroot(32) ‖ time(4) ‖ bits(4) ‖ nonce(4).
func HeaderMerkleRoot(h [80]byte) Hash {
	var r Hash
	copy(r[:], h[36:68])
	return r
}

// Build assembles a Bundle for out, revealing the field at revealIndex. fields is
// the FULL field set of the transaction (Alice holds it); only the revealed field
// and its L0 path are placed in the bundle (I-B3 / §6.6). src supplies L1/L2/header.
//
// (Signature note: revealIndex is added to the 02_MODULE_SPECS contract so Build
// knows which single field to disclose; without it minimal reveal is undefined.)
func Build(out OutputRef, fields TxFields, revealIndex uint8, src teranode.ProofSource) (Bundle, error) {
	leaf, l0, mtxid, err := commitment.MTxIDPath(fields, revealIndex)
	if err != nil {
		return Bundle{}, err
	}
	if mtxid != out.TXID {
		return Bundle{}, ErrTXIDMismatch
	}
	_ = leaf
	l1, subtreeRoot, err := src.SubtreePathFor(out.TXID)
	if err != nil {
		return Bundle{}, err
	}
	blockHash, err := src.LocateTx(out.TXID)
	if err != nil {
		return Bundle{}, err
	}
	l2, _, err := src.BlockPathFor(subtreeRoot, blockHash)
	if err != nil {
		return Bundle{}, err
	}
	hdr, err := src.HeaderFor(blockHash)
	if err != nil {
		return Bundle{}, err
	}
	b := Bundle{
		OutputRef:   out,
		Fields:      TxFields{fields[revealIndex]},
		MTxIDPath:   l0,
		SubtreePath: l1,
		BlockPath:   l2,
		Header:      hdr,
	}
	return b, nil
}

// Verify runs the local, network-free, fail-fast inclusion check Bob performs.
// It returns (ok, depth, reason). depth is the inclusion path length |L1|+|L2|.
// On the first failing step it returns ok=false and the matching reason.
//
// Verify proves INCLUSION only. It is NOT double-spend protection (see wallet_bob).
func Verify(b Bundle, headersView teranode.HeaderChain) (ok bool, depth int, reason string) {
	depth = len(b.SubtreePath) + len(b.BlockPath)
	if len(b.MTxIDPath)+depth > commitment.MaxDepth || len(b.SubtreePath) > 20 {
		return false, depth, "depth-overflow"
	}
	if len(b.Fields) == 0 {
		return false, depth, "L0" // nothing revealed; cannot reconstruct MTxID
	}
	// 1. L0: fold the revealed field along MTxIDPath -> mtxid(=TXID).
	leaf := commitment.LeafForField(b.Fields[0])
	mtxid := commitment.Fold(leaf, b.MTxIDPath)
	if mtxid != b.OutputRef.TXID {
		return false, depth, "L0"
	}
	// 2. L1: TXID -> subtree root.
	subtreeRoot := commitment.Fold(b.OutputRef.TXID, b.SubtreePath)
	// 3. L2: subtree root -> block Merkle root.
	blockRoot := commitment.Fold(subtreeRoot, b.BlockPath)
	// 4. L3-bind: computed block root must equal the header's committed root.
	if blockRoot != HeaderMerkleRoot(b.Header) {
		return false, depth, "L3-bind"
	}
	// 5a. header on Bob's most-work chain?
	if headersView != nil && headersView.Contains(b.Header) {
		return true, depth, ""
	}
	// 5b. else fall back to the L4 anchor (header-pruned verifier).
	if b.Anchor != nil && headersView != nil && anchorBindsToChain(b.Anchor, headersView) {
		a := b.Anchor
		// I-A2: VerifyBlockInChain is trusted ONLY when accRoot is PoW-anchored AND
		// the carrying block is itself on the verifier's most-work chain (RT-1).
		inChain := accumulator.VerifyBlockInChain(b.Header, a.AccPath, a.AccRoot)
		if inChain {
			return true, depth, ""
		}
	}
	return false, depth, "L3/L4-chain"
}

// anchorBindsToChain reports whether an L4 anchor is genuinely PoW-bound: the
// accRoot is committed in the carrying block's gen tx (VerifyAnchor) AND the
// carrying block's header is on the verifier's most-work chain with the matching
// Merkle root. Without the header check, CarryingBlockMerkleRoot is attacker-chosen
// and the accumulator inherits no PoW (RT-1).
func anchorBindsToChain(a *AnchorProof, headersView teranode.HeaderChain) bool {
	if headersView == nil {
		return false
	}
	if !headersView.Contains(a.CarryingHeader) {
		return false
	}
	if HeaderMerkleRoot(a.CarryingHeader) != a.CarryingBlockMerkleRoot {
		return false
	}
	return accumulator.VerifyAnchor(a.AccRoot, a.GenTxFields, a.GenL0, a.GenL1, a.GenL2, a.CarryingBlockMerkleRoot)
}

// Errors.
var (
	ErrTXIDMismatch = errString("bundle: revealed fields do not reconstruct OutputRef.TXID")
)

type errString string

func (e errString) Error() string { return string(e) }

// ---------------------------------------------------------------------------
// Maintenance.
// ---------------------------------------------------------------------------

// NeedsReanchor reports whether the bundle's header is no longer on the best
// chain (orphaned) — the only condition under which the frozen core may legitimately
// change (the block was reorged out).
func NeedsReanchor(b Bundle, headersView teranode.HeaderChain) bool {
	if headersView == nil {
		return false
	}
	if headersView.Contains(b.Header) {
		return false
	}
	// If a valid, PoW-bound L4 anchor still binds the header, no reanchor is needed.
	if b.Anchor != nil && anchorBindsToChain(b.Anchor, headersView) &&
		accumulator.VerifyBlockInChain(b.Header, b.Anchor.AccPath, b.Anchor.AccRoot) {
		return false
	}
	return true
}

// Reanchor refreshes the bundle from the current best chain. It re-fetches L1/L2/
// header from src for the bundle's TXID.
//
//   - Non-orphaned block (I-B1): src returns identical L1/L2/header, so
//     MTxIDPath/SubtreePath/BlockPath/Header are byte-unchanged; only a stale L4
//     anchor would be refreshed. (T3.3)
//   - Orphaned block (A5): the tx is now in a different block on the best chain;
//     SubtreePath/BlockPath/Header are updated to that block. MTxIDPath/Fields are
//     intra-transaction and NEVER change.
func Reanchor(b *Bundle, src teranode.ProofSource) error {
	l1, subtreeRoot, err := src.SubtreePathFor(b.OutputRef.TXID)
	if err != nil {
		return err
	}
	blockHash, err := src.LocateTx(b.OutputRef.TXID)
	if err != nil {
		return err
	}
	l2, _, err := src.BlockPathFor(subtreeRoot, blockHash)
	if err != nil {
		return err
	}
	hdr, err := src.HeaderFor(blockHash)
	if err != nil {
		return err
	}
	b.SubtreePath = l1
	b.BlockPath = l2
	b.Header = hdr
	// L0 (MTxIDPath, Fields) is intra-tx and frozen; never touched here.
	return nil
}
