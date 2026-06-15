package fabric

import (
	"sync"
	"sync/atomic"
	"time"

	"mfspv/commitment"
	"mfspv/teranode"
)

// BuildServedBlock seals a REAL block of numSub subtrees of subCap txs on a MockNode
// and returns the node (a ProofSource + HeaderChain) and the list of txids it can
// serve Merkle proofs for. Models the node side of SPV proof acquisition.
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

// MeasurePullThroughput measures the PULL half of SPV at scale: each worker repeatedly
// picks a txid, Fetches its Merkle path + block from the node (proof acquisition), and
// verifies inclusion against the node's header chain. Returns aggregate proofs/s.
// This includes the node's per-proof path-construction cost (the real serving cost),
// not just the fold.
func MeasurePullThroughput(node *teranode.MockNode, txids []commitment.Hash, cores int, dur time.Duration) float64 {
	if cores < 1 {
		cores = 1
	}
	h := DefaultHasher()
	var count uint64
	var wg sync.WaitGroup
	deadline := time.Now().Add(dur)
	wg.Add(cores)
	for w := 0; w < cores; w++ {
		go func(start int) {
			defer wg.Done()
			var local uint64
			i := start
			for {
				for k := 0; k < 256; k++ {
					txid := txids[i%len(txids)]
					i++
					p, err := Fetch(txid, node) // proof acquisition: get path + block
					if err != nil {
						continue
					}
					if ok, _ := VerifyOne(h, p, node); ok {
						local++
					}
				}
				if time.Now().After(deadline) {
					break
				}
			}
			atomic.AddUint64(&count, local)
		}(w * (len(txids) / cores))
	}
	wg.Wait()
	secs := dur.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return float64(count) / secs
}
