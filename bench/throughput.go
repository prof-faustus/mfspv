package bench

import (
	"sync"
	"sync/atomic"
	"time"

	"mfspv/commitment"
)

// VerifyThroughput measures SUSTAINED inclusion-verification throughput: `workers`
// goroutines each fold a depth-length inclusion path in a tight loop for `dur`, and
// the function returns total verifications and verifications/second.
//
// This is the concrete "runs at that level" evidence for the EDGE: MF-SPV inclusion
// verification is stateless and embarrassingly parallel (no shared mutable state, no
// network, no locks on the hot path), so aggregate capacity scales linearly with
// cores. A verifier fabric absorbs any payment rate by adding cores; per-payment
// cost stays at depth hash compressions regardless of chain throughput T.
func VerifyThroughput(depth, workers int, dur time.Duration) (totalOps uint64, opsPerSec float64) {
	if workers < 1 {
		workers = 1
	}
	// One representative valid inclusion of the requested depth, shared read-only.
	leaf := commitment.DoubleSHA256([]byte("tp-leaf"))
	path := make([]commitment.PathElem, depth)
	for i := range path {
		path[i] = commitment.PathElem{
			Sibling: commitment.DoubleSHA256([]byte{byte(i), byte(i >> 8)}),
			Right:   i%2 == 0,
		}
	}
	root := commitment.Fold(leaf, path)

	var count uint64
	var wg sync.WaitGroup
	deadline := time.Now().Add(dur)
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			var local uint64
			// Check the clock every 4096 iterations to keep the hot loop tight.
			for {
				for i := 0; i < 4096; i++ {
					if commitment.Fold(leaf, path) != root {
						panic("throughput: fold mismatch")
					}
				}
				local += 4096
				if time.Now().After(deadline) {
					break
				}
			}
			atomic.AddUint64(&count, local)
		}()
	}
	wg.Wait()
	secs := dur.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return count, float64(count) / secs
}

// EdgeProfile summarises edge verification capacity at a target rate.
type EdgeProfile struct {
	R               float64
	Depth           int
	ProofBytes      int
	PerVerifyNanos  float64 // measured time for one inclusion verify
	VerifiesPerSec1 float64 // single-core sustained
	VerifiesPerSecN float64 // workers-core sustained
	Workers         int
}

// ProfileEdge measures the edge at the depth implied by rate r, single-core and
// across `workers` cores, over `dur` each.
func ProfileEdge(r float64, workers int, dur time.Duration) EdgeProfile {
	T := uint64(r) * BlockIntervalSec
	depth := ceilLog2(T)
	ops1, ps1 := VerifyThroughput(depth, 1, dur)
	_, psN := VerifyThroughput(depth, workers, dur)
	per := 0.0
	if ops1 > 0 {
		per = dur.Seconds() / float64(ops1) * 1e9
	}
	return EdgeProfile{
		R:               r,
		Depth:           depth,
		ProofBytes:      DigestBytes * depth,
		PerVerifyNanos:  per,
		VerifiesPerSec1: ps1,
		VerifiesPerSecN: psN,
		Workers:         workers,
	}
}
