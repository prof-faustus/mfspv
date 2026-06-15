// Package fabric is the verifier-side throughput architecture of 07_VERIFICATION_FABRIC.md.
// It targets >= 1.5e7 inclusion-verifications/s (A >= 1.5, where verif/s = A*1e7)
// WITHOUT any BSV consensus change — every lever is local to the verifier (Bob):
//
//   - Lever A: a pluggable SHA-256d backend (Hasher). The software backend uses
//     Go's crypto/sha256 (which itself uses SHA-NI when the CPU exposes it). An
//     AVX2/AVX-512 multi-buffer backend is a future assembly/cgo plug-in behind the
//     same interface; output is identical SHA-256d across backends.
//   - Lever B: BatchVerify amortises shared Merkle nodes across proofs that land in
//     the same block/subtree — header/PoW once per block, subtree->block path once
//     per subtree, and (the key win) shared INTERNAL subtree nodes computed once via
//     memoisation. Dense workloads collapse per-proof cost toward a small constant.
//   - Lever C: Capacity() gives the cores/nodes needed for a target rate.
//
// §5 correctness: the inclusion leaf is the CONSENSUS TXID (= reverse(double-SHA256
// (serialized tx))). The L0 field tree (MTxID) is NOT on the inclusion path; it is
// an optional secondary commitment for selective field disclosure. A Proof here
// folds TXID -> subtree root -> block root, i.e. commitment.VerifyToBlockRoot with
// leaf = txid, l0 = nil.
//
// BSV only.
package fabric

import (
	"mfspv/commitment"
	"mfspv/teranode"
)

type Hash = commitment.Hash
type PathElem = commitment.PathElem

// Hasher is the pluggable SHA-256d backend (Lever A). Every backend MUST produce
// identical SHA-256d output (asserted by KAT in the tests).
type Hasher interface {
	HashPair(left, right Hash) Hash
	Name() string
}

// Software is the dependency-free backend (Go crypto/sha256; SHA-NI auto-engaged
// by the runtime when present).
type Software struct{}

func (Software) HashPair(l, r Hash) Hash { return commitment.HashPair(l, r) }
func (Software) Name() string            { return "software(crypto/sha256d)" }

// DefaultHasher returns the backend selected for this build.
func DefaultHasher() Hasher { return Software{} }

// Proof is one inclusion proof on the consensus path (§5: Leaf is the TXID).
type Proof struct {
	Leaf        Hash       // consensus TXID
	L1          []PathElem // TXID -> subtree root
	SubtreeRoot Hash
	L2          []PathElem // subtree root -> block Merkle root
	Header      [80]byte
}

// HeaderMerkleRoot extracts the block Merkle root from an 80-byte header.
func HeaderMerkleRoot(h [80]byte) Hash {
	var r Hash
	copy(r[:], h[36:68])
	return r
}

// foldCount folds leaf along path and returns the root plus the hash count.
func foldCount(h Hasher, leaf Hash, path []PathElem) (Hash, int) {
	node := leaf
	for _, e := range path {
		if e.Right {
			node = h.HashPair(node, e.Sibling)
		} else {
			node = h.HashPair(e.Sibling, node)
		}
	}
	return node, len(path)
}

// VerifyOne verifies a single proof against the header view. ok iff the TXID folds
// to the block root committed in a header on the chain.
func VerifyOne(h Hasher, p Proof, chain teranode.HeaderChain) (ok bool, hashes int) {
	sub, n1 := foldCount(h, p.Leaf, p.L1)
	if sub != p.SubtreeRoot {
		return false, n1
	}
	br, n2 := foldCount(h, p.SubtreeRoot, p.L2)
	if br != HeaderMerkleRoot(p.Header) {
		return false, n1 + n2
	}
	if chain != nil && !chain.Contains(p.Header) {
		return false, n1 + n2
	}
	return true, n1 + n2
}

// nodeKey identifies an internal Merkle node for cross-proof memoisation.
type nodeKey struct {
	subtree Hash
	level   int
	index   uint64
}

// leafIndex reconstructs a leaf's index within its subtree from the path's
// Right bits (Right==true means the sibling is the right child, i.e. this node is
// the left child -> bit 0; Right==false -> bit 1).
func leafIndex(path []PathElem) uint64 {
	var idx uint64
	for j := 0; j < len(path); j++ {
		if !path[j].Right {
			idx |= uint64(1) << uint(j)
		}
	}
	return idx
}

// BatchVerify verifies a batch with shared-node amortisation (Lever B). It returns
// whether ALL proofs are valid and the TOTAL number of HashPair operations actually
// performed (the amortised work); amortised depth = hashes / len(proofs).
//
// Sharing: the header/PoW is checked once per block; the subtree->block path once
// per subtree; and internal subtree nodes are memoised so proofs that share upper
// paths do not recompute them. The first proof of each subtree folds fully to the
// subtree root; later proofs merge into the verified structure.
func BatchVerify(h Hasher, proofs []Proof, chain teranode.HeaderChain) (ok bool, hashes int) {
	memo := make(map[nodeKey]Hash, len(proofs)*4)
	subtreeOK := make(map[Hash]bool)
	headerOK := make(map[Hash]bool)

	for i := range proofs {
		p := &proofs[i]

		// L1: fold TXID -> subtree root with memoisation across proofs.
		cur := p.Leaf
		idx := leafIndex(p.L1)
		merged := false
		for j := 0; j < len(p.L1); j++ {
			var parent Hash
			if p.L1[j].Right {
				parent = h.HashPair(cur, p.L1[j].Sibling)
			} else {
				parent = h.HashPair(p.L1[j].Sibling, cur)
			}
			hashes++
			pidx := idx >> 1
			k := nodeKey{p.SubtreeRoot, j + 1, pidx}
			if existing, ok := memo[k]; ok {
				if existing != parent {
					return false, hashes // inconsistent sibling set
				}
				merged = true
				break // upper path already verified by an earlier proof
			}
			memo[k] = parent
			cur = parent
			idx = pidx
		}
		if !merged && cur != p.SubtreeRoot {
			return false, hashes
		}

		// L2: subtree root -> block root, once per subtree.
		if !subtreeOK[p.SubtreeRoot] {
			br, n := foldCount(h, p.SubtreeRoot, p.L2)
			hashes += n
			if br != HeaderMerkleRoot(p.Header) {
				return false, hashes
			}
			subtreeOK[p.SubtreeRoot] = true
		}

		// L3: header on the most-work chain, once per block.
		hk := commitment.DoubleSHA256(p.Header[:])
		if !headerOK[hk] {
			if chain != nil && !chain.Contains(p.Header) {
				return false, hashes
			}
			headerOK[hk] = true
		}
	}
	return true, hashes
}

// ---------------------------------------------------------------------------
// Lever C — capacity equation.
// ---------------------------------------------------------------------------

// RequiredCores returns the number of cores needed to sustain targetVerifPerSec at
// the given amortised depth and measured per-core SHA-256d rate (06/07 §4 Lever C).
func RequiredCores(targetVerifPerSec, amortizedDepth, perCoreHashRate float64) float64 {
	if perCoreHashRate <= 0 {
		return 0
	}
	return targetVerifPerSec * amortizedDepth / perCoreHashRate
}

// VerifPerSec returns the aggregate verifications/s for a measured aggregate
// SHA-256d rate and an amortised depth.
func VerifPerSec(aggregateHashRate, amortizedDepth float64) float64 {
	if amortizedDepth <= 0 {
		return 0
	}
	return aggregateHashRate / amortizedDepth
}
