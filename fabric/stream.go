package fabric

import (
	"mfspv/commitment"
	"mfspv/teranode"
)

// Verifier is a reusable, allocation-light batch verifier that folds proofs
// DIRECTLY from their wire bytes (no per-proof Proof/PathElem heap allocation) with
// cross-proof shared-node memoisation. This is the optimised REAL path: the only
// per-call heap is the reused memo maps (cleared, not reallocated). Siblings are
// read into fixed stack arrays. (07 Lever B + the deserialisation optimisation.)
type Verifier struct {
	memo  map[uint64]Hash // (subID<<40 | level<<32 | index) -> node hash
	subID map[Hash]uint32 // subtree root -> small id (cheap memo keys)
	subOK map[uint32]bool // subtree id -> L2 verified
	hdrOK map[Hash]bool   // header dsha -> on-chain
}

// NewVerifier allocates the reusable maps.
func NewVerifier() *Verifier {
	return &Verifier{
		memo:  make(map[uint64]Hash, 1<<16),
		subID: make(map[Hash]uint32, 1024),
		subOK: make(map[uint32]bool, 1024),
		hdrOK: make(map[Hash]bool, 16),
	}
}

func (v *Verifier) reset() {
	clear(v.memo)
	clear(v.subID)
	clear(v.subOK)
	clear(v.hdrOK)
}

// VerifyWire decodes-and-verifies a batch produced by EncodeBatch in a single pass
// with no per-proof allocation. Returns ok, hashes performed, and proof count.
func (v *Verifier) VerifyWire(h Hasher, wire []byte, chain teranode.HeaderChain) (ok bool, hashes int, nproofs int) {
	v.reset()
	if len(wire) < 4 {
		return false, 0, 0
	}
	n := int(u32(wire[0:]))
	off := 4
	var nextID uint32

	var sibs [64][32]byte
	var rights [64]bool
	var lastSub Hash
	var lastID uint32
	haveLast := false

	for p := 0; p < n; p++ {
		if off+4 > len(wire) {
			return false, hashes, p
		}
		plen := int(u32(wire[off:]))
		off += 4
		if off+plen > len(wire) {
			return false, hashes, p
		}
		b := wire[off : off+plen]
		off += plen
		o := 0

		// Leaf
		if o+32 > len(b) {
			return false, hashes, p
		}
		var cur Hash
		copy(cur[:], b[o:o+32])
		o += 32

		// L1 into stack arrays
		if o+1 > len(b) {
			return false, hashes, p
		}
		n1 := int(b[o])
		o++
		if n1 > len(sibs) {
			return false, hashes, p
		}
		var idx uint64
		for j := 0; j < n1; j++ {
			if o+33 > len(b) {
				return false, hashes, p
			}
			rights[j] = b[o] == 1
			copy(sibs[j][:], b[o+1:o+33])
			o += 33
			if !rights[j] {
				idx |= uint64(1) << uint(j)
			}
		}

		// SubtreeRoot
		if o+32 > len(b) {
			return false, hashes, p
		}
		var subRoot Hash
		copy(subRoot[:], b[o:o+32])
		o += 32

		// Fast path: real batches arrive grouped by subtree, so avoid the 32-byte-key
		// map lookup when the subtree root is unchanged from the previous proof.
		var id uint32
		if haveLast && subRoot == lastSub {
			id = lastID
		} else {
			var seen bool
			id, seen = v.subID[subRoot]
			if !seen {
				id = nextID
				nextID++
				v.subID[subRoot] = id
			}
			lastSub = subRoot
			lastID = id
			haveLast = true
		}

		// Fold L1 with memo.
		merged := false
		for j := 0; j < n1; j++ {
			var parent Hash
			if rights[j] {
				parent = h.HashPair(cur, sibs[j])
			} else {
				parent = h.HashPair(sibs[j], cur)
			}
			hashes++
			pidx := idx >> 1
			key := uint64(id)<<40 | uint64(j+1)<<32 | pidx
			if e, ok := v.memo[key]; ok {
				if e != parent {
					return false, hashes, p
				}
				merged = true
				break
			}
			v.memo[key] = parent
			cur = parent
			idx = pidx
		}
		if !merged && cur != subRoot {
			return false, hashes, p
		}

		// L2 once per subtree.
		if o+1 > len(b) {
			return false, hashes, p
		}
		n2 := int(b[o])
		o++
		// header is after L2; we need its merkle root for the L2 check.
		l2start := o
		o += n2 * 33
		if o+80 > len(b) {
			return false, hashes, p
		}
		var hdr [80]byte
		copy(hdr[:], b[o:o+80])
		o += 80

		if !v.subOK[id] {
			node := subRoot
			for j := 0; j < n2; j++ {
				base := l2start + j*33
				right := b[base] == 1
				var sib Hash
				copy(sib[:], b[base+1:base+33])
				if right {
					node = h.HashPair(node, sib)
				} else {
					node = h.HashPair(sib, node)
				}
				hashes++
			}
			var mr Hash
			copy(mr[:], hdr[36:68])
			if node != mr {
				return false, hashes, p
			}
			v.subOK[id] = true
		}

		// Header once per block.
		hk := commitment.DoubleSHA256(hdr[:])
		if !v.hdrOK[hk] {
			if chain != nil && !chain.Contains(hdr) {
				return false, hashes, p
			}
			v.hdrOK[hk] = true
		}
	}
	return true, hashes, n
}

func u32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
