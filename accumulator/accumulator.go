// Package accumulator implements the OPTIONAL L4 of MF-SPV (01_ARCHITECTURE.md
// §2, 02_MODULE_SPECS.md §accumulator): an append-only Merkle Mountain Range over
// sealed block headers, whose root is committed OFF-HEADER in the generation
// transaction (US 2022/0216997 mechanism). This gives a header-pruned verifier a
// way to prove any past header from a recent commitment, inheriting PoW security
// through L3 — WITHOUT the header-format fork FlyClient requires.
//
// The price of staying off-header is ABSENT PERIODS (§6.4): L4 binds only blocks
// whose miners committed the accumulator. That limitation is made explicit in code
// here (CoverageGaps / NearestCommitted, I-A3), never hidden.
//
// BSV only.
package accumulator

import (
	"bytes"

	"mfspv/commitment"
)

type Hash = commitment.Hash
type PathElem = commitment.PathElem
type TxFields = commitment.TxFields

// MMR is an append-only Merkle Mountain Range over 80-byte block headers.
//
// We retain the leaf digests (header SHA-256d) and derive peaks/proofs on demand.
// Because leaves are never rewritten, any height proven once stays provable
// forever (I-A1), even as the MMR grows.
type MMR struct {
	leaves []Hash
}

// NewMMR returns an empty accumulator.
func NewMMR() *MMR { return &MMR{} }

// Size returns the number of appended headers.
func (m *MMR) Size() uint64 { return uint64(len(m.leaves)) }

// Append adds a header and returns the new root. O(log n) work to recompute peaks.
// I-A1: Append never rewrites historical leaves.
func (m *MMR) Append(header80 [80]byte) Hash {
	m.leaves = append(m.leaves, commitment.DoubleSHA256(header80[:]))
	return m.Root()
}

// mountainSizes returns the perfect-subtree sizes that partition n leaves,
// largest (left, earliest leaves) first.
func mountainSizes(n uint64) []uint64 {
	var sizes []uint64
	for b := 63; b >= 0; b-- {
		if n&(uint64(1)<<uint(b)) != 0 {
			sizes = append(sizes, uint64(1)<<uint(b))
		}
	}
	return sizes
}

// peaks returns the peak hashes left->right (largest mountain first).
func (m *MMR) peaks() []Hash {
	var pk []Hash
	start := uint64(0)
	for _, sz := range mountainSizes(uint64(len(m.leaves))) {
		root, _ := commitment.MerkleRoot(m.leaves[start : start+sz])
		pk = append(pk, root)
		start += sz
	}
	return pk
}

// bagPeaks combines peaks right-to-left: root = H(p0, H(p1, ... H(p_{m-2}, p_{m-1}))).
func bagPeaks(pk []Hash) Hash {
	if len(pk) == 0 {
		return Hash{}
	}
	acc := pk[len(pk)-1]
	for i := len(pk) - 2; i >= 0; i-- {
		acc = commitment.HashPair(pk[i], acc)
	}
	return acc
}

// Root returns the current MMR root (bagged peaks). Empty MMR -> zero hash.
func (m *MMR) Root() Hash {
	if len(m.leaves) == 0 {
		return Hash{}
	}
	return bagPeaks(m.peaks())
}

// ProveBlock returns a leaf->root path for the header at the given height (0-based
// leaf index) together with the current root. The path covers (a) the in-mountain
// climb to the containing peak and (b) the peak-bagging combination to the root.
func (m *MMR) ProveBlock(height uint64) (path []PathElem, root Hash, err error) {
	if height >= uint64(len(m.leaves)) {
		return nil, Hash{}, commitment.ErrEmpty
	}
	sizes := mountainSizes(uint64(len(m.leaves)))
	// locate the mountain containing `height`
	start := uint64(0)
	mIdx := -1
	var mStart, mSize uint64
	for i, sz := range sizes {
		if height < start+sz {
			mIdx = i
			mStart = start
			mSize = sz
			break
		}
		start += sz
	}
	// in-mountain path
	_, layers, err := commitment.BuildMerkleTree(m.leaves[mStart : mStart+mSize])
	if err != nil {
		return nil, Hash{}, err
	}
	inPath, err := commitment.MerklePath(layers, int(height-mStart))
	if err != nil {
		return nil, Hash{}, err
	}
	path = append(path, inPath...)

	// peak-bagging combination
	pk := m.peaks()
	k := mIdx
	mp := len(pk)
	if k < mp-1 {
		// fold with the bag of all peaks to the right (sibling on the right)
		right := bagPeaks(pk[k+1:])
		path = append(path, PathElem{Sibling: right, Right: true})
	}
	for i := k - 1; i >= 0; i-- {
		// fold with each peak to the left (sibling on the left)
		path = append(path, PathElem{Sibling: pk[i], Right: false})
	}
	return path, m.Root(), nil
}

// VerifyBlockInChain reports whether header80 folds along path to accRoot.
//
// I-A2 (PoW binding): this is meaningful ONLY when accRoot has separately passed
// VerifyAnchor — i.e. it is committed in a PoW-sealed generation tx. Membership in
// the MMR alone does not establish chain validity; the caller (bundle.Verify)
// MUST gate this with VerifyAnchor.
func VerifyBlockInChain(header80 [80]byte, path []PathElem, accRoot Hash) (ok bool) {
	if len(path) > commitment.MaxDepth {
		return false
	}
	leaf := commitment.DoubleSHA256(header80[:])
	return commitment.Fold(leaf, path) == accRoot
}

// VerifyAnchor binds accRoot to PoW: it confirms accRoot is committed as a field of
// a generation transaction whose own L0–L2 path closes to carryingBlockMerkleRoot
// (a PoW-sealed block). Composes with commitment.VerifyToBlockRoot.
//
//	l0 : accRoot field -> gen-tx MTxID
//	l1 : gen-tx MTxID  -> subtree root
//	l2 : subtree root  -> carrying block Merkle root
func VerifyAnchor(accRoot Hash, genTxFields TxFields, l0, l1, l2 []PathElem, carryingBlockMerkleRoot Hash) (ok bool) {
	if len(l0)+len(l1)+len(l2) > commitment.MaxDepth {
		return false
	}
	// The accRoot must actually appear as a committed field of the gen tx.
	var leaf Hash
	found := false
	for _, f := range genTxFields {
		if bytes.Equal(f.Bytes, accRoot[:]) {
			leaf = commitment.LeafForField(f)
			found = true
			break
		}
	}
	if !found {
		return false
	}
	mtxid := commitment.Fold(leaf, l0)
	sub := commitment.Fold(mtxid, l1)
	root := commitment.Fold(sub, l2)
	return root == carryingBlockMerkleRoot
}

// ---------------------------------------------------------------------------
// Absent periods (§6.4) — stated, not hidden.
// ---------------------------------------------------------------------------

// ParticipationGap is a [FromHeight, ToHeight] inclusive run of heights for which
// NO miner committed the accumulator.
type ParticipationGap struct {
	FromHeight, ToHeight uint64
}

// CoverageGaps returns every gap in [0, tipHeight] not covered by committedHeights.
// I-A3: gaps are reported honestly; the caller must fall back inside a gap rather
// than treat a header as "in chain".
func CoverageGaps(committedHeights []uint64, tipHeight uint64) []ParticipationGap {
	present := make(map[uint64]bool, len(committedHeights))
	for _, h := range committedHeights {
		present[h] = true
	}
	var gaps []ParticipationGap
	inGap := false
	var from uint64
	for h := uint64(0); h <= tipHeight; h++ {
		if present[h] {
			if inGap {
				gaps = append(gaps, ParticipationGap{FromHeight: from, ToHeight: h - 1})
				inGap = false
			}
			continue
		}
		if !inGap {
			from = h
			inGap = true
		}
	}
	if inGap {
		gaps = append(gaps, ParticipationGap{FromHeight: from, ToHeight: tipHeight})
	}
	return gaps
}

// NearestCommitted returns the largest committed height <= height. inGap is true
// whenever `height` itself was not committed (so a header-pruned verifier knows it
// must fall back and never gets a false "in chain"). If no committed height <=
// height exists, h is returned as 0 with inGap true.
func NearestCommitted(height uint64, committedHeights []uint64) (h uint64, inGap bool) {
	best := int64(-1)
	exact := false
	for _, c := range committedHeights {
		if c == height {
			exact = true
		}
		if c <= height && int64(c) > best {
			best = int64(c)
		}
	}
	if best < 0 {
		return 0, true
	}
	return uint64(best), !exact
}
