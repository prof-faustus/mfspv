package fabric

import (
	"sync"
	"sync/atomic"
	"time"

	"mfspv/commitment"
	"mfspv/internal/sha256mb"
	"mfspv/teranode"
)

// BuildServedBlock seals a REAL block of numSub subtrees of subCap txs on a MockNode
// and returns the node (a ProofSource + HeaderChain) and the list of txids it can
// serve Merkle proofs for. Models the node side of SPV proof acquisition. txids are
// subtree-major (subtree 0's leaves, then subtree 1's, ...).
func BuildServedBlock(subCap, numSub int) (*teranode.MockNode, []commitment.Hash, error) {
	n := teranode.NewMockNode(subCap)
	txids := make([]commitment.Hash, 0, subCap*numSub)
	for s := 0; s < numSub; s++ {
		for i := 0; i < subCap; i++ {
			txids = append(txids, commitment.DoubleSHA256([]byte{byte(s), byte(s >> 8), byte(i), byte(i >> 8), 0x7c}))
		}
	}
	if _, err := n.SealBlock(txids, false); err != nil {
		return nil, nil, err
	}
	return n, txids, nil
}

// MeasurePullThroughput measures the PULL half of SPV at scale: a high-throughput
// verifier pulls many proofs and verifies them. Each worker owns a contiguous slice
// of txids; per group of 16 it (1) serves the proofs from the node into reusable
// buffers (allocation-free on-demand path construction, lock-free) and (2) folds the
// 16 L1 paths in LOCKSTEP on the AVX-512 16-lane kernel (Lever A) — the same SIMD
// verification the push path uses. L2 (subtree->block->header) is verified once per
// subtree outside the hot loop. Returns aggregate proofs/s. Scalar fallback if no
// AVX-512.
func MeasurePullThroughput(node *teranode.MockNode, txids []commitment.Hash, cores int, dur time.Duration) float64 {
	if cores < 1 {
		cores = 1
	}
	h := DefaultHasher()

	// Pre-verify each distinct subtree's L2 path -> block root -> header, once.
	// (Serve one proof per subtree; check it folds to the header's committed root.)
	valid := map[commitment.Hash]bool{}
	var l1tmp, l2tmp []commitment.PathElem
	for _, txid := range txids {
		l1, l2, sub, hdr, ok := node.ServeInto(txid, l1tmp[:0], l2tmp[:0])
		if !ok {
			continue
		}
		l1tmp, l2tmp = l1, l2
		if _, done := valid[sub]; done {
			continue
		}
		valid[sub] = commitment.Fold(sub, l2) == HeaderMerkleRoot(hdr) && node.Contains(hdr)
	}

	per := len(txids) / cores
	if per < 16 {
		per = len(txids)
	}
	var count uint64
	var wg sync.WaitGroup
	deadline := time.Now().Add(dur)
	wg.Add(cores)
	for w := 0; w < cores; w++ {
		go func(start int) {
			defer wg.Done()
			end := start + per
			if end > len(txids) {
				end = len(txids)
			}
			mine := txids[start:end]
			n16 := (len(mine) / 16) * 16
			hasher := sha256mb.NewHasher()
			var l1 [16][]commitment.PathElem
			for k := range l1 {
				l1[k] = make([]commitment.PathElem, 0, 40)
			}
			var node16, sub16 [16]commitment.Hash
			var msgs [16][64]byte
			var out [16][32]byte
			var local uint64
			for {
				for base := 0; base < n16; base += 16 {
					// (1) serve 16 proofs (allocation-free).
					for k := 0; k < 16; k++ {
						p1, _, sub, _, ok := node.ServeInto(mine[base+k], l1[k][:0], nil)
						if ok {
							l1[k] = p1
							sub16[k] = sub
							node16[k] = mine[base+k] // leaf = txid
						} else {
							sub16[k] = commitment.Hash{}
						}
					}
					// (2) lockstep 16-lane fold of the L1 paths (uniform length).
					levels := len(l1[0])
					for j := 0; j < levels; j++ {
						for k := 0; k < 16; k++ {
							e := l1[k][j]
							if e.Right {
								copy(msgs[k][:32], node16[k][:])
								copy(msgs[k][32:], e.Sibling[:])
							} else {
								copy(msgs[k][:32], e.Sibling[:])
								copy(msgs[k][32:], node16[k][:])
							}
						}
						hasher.DoubleSHA256x16(&msgs, &out)
						for k := 0; k < 16; k++ {
							node16[k] = commitment.Hash(out[k])
						}
					}
					for k := 0; k < 16; k++ {
						if node16[k] == sub16[k] && valid[sub16[k]] {
							local++
						}
					}
				}
				if time.Now().After(deadline) {
					break
				}
			}
			atomic.AddUint64(&count, local)
		}(w * per)
	}
	wg.Wait()
	_ = h
	secs := dur.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return float64(count) / secs
}
