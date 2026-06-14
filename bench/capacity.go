package bench

import (
	"time"

	"mfspv/commitment"
)

// Capacity planning for SEALING blocks at a target rate.
//
// Important separation of concerns (PAPER.md §4.4, Result 4.4):
//   - The SPV/proof EDGE cost is logarithmic and decoupled from throughput. A
//     verifier never processes every transaction; it verifies one ~1.5 KB proof in
//     microseconds (see throughput.go). 100 billion tx/s does not raise edge cost.
//   - ORDERING/validating the transactions themselves is Teranode's job, bounded by
//     Teranode, not by SPV. What MF-SPV adds to that job is the Merkle commitment
//     work: building subtree trees and the block tree. This file quantifies exactly
//     that, so "100 billion tx/s" becomes a derived capacity number, not a slogan.
//
// The Merkle work to seal a block of T transactions is the number of INTERNAL node
// hashes in the forest: across all 2^20-leaf subtrees plus the block tree over
// subtree roots, that is T-1 SHA-256d compressions (a binary tree over n leaves has
// n-1 internal nodes; the subtree split does not change the total). Leaf hashing
// (computing each TXID) is another ~T and is normally amortised into transaction
// validation; we report both the marginal (internal-only) and the inclusive (2T)
// figures so nothing is hidden.

// ShaNiRatePerCore is a representative SHA-256d rate for a core WITH the SHA hardware
// extensions (SHA-NI / ARMv8 crypto). Commodity server cores reach this range; it is
// ~30x the pure-software Go path measured by HashRatePerSec on machines lacking the
// intrinsic. Used only to bracket the core-count estimate.
const ShaNiRatePerCore = 100_000_000.0 // 100 M SHA-256d/s/core (hardware-accelerated)

// Capacity is the derived sealing cost for a throughput r.
type Capacity struct {
	R                 float64 // tx/s
	T                 uint64  // tx/block
	Subtrees          uint64  // ceil(T / 2^20)
	SubtreesPerSec    float64 // subtree roots the network emits per second
	InternalHashes    uint64  // Merkle internal-node hashes to seal one block (= T-1)
	MarginalHashRate  float64 // internal hashes/sec network-wide (= (T-1)/600)
	InclusiveHashRate float64 // including leaf hashing (~2T/600)
	CoresMeasured     float64 // cores needed at the measured (software) hash rate
	CoresShaNi        float64 // cores needed at hardware-accelerated rate
	ProofBytes        int     // per-payment proof size (edge), unchanged by r beyond +log
	MeasuredHashRate  float64 // the per-core software rate this estimate used
}

// HashRatePerSec measures this machine's single-core SHA-256d throughput (HashPair).
// It runs ~n compressions; pass 0 for a default sample size.
func HashRatePerSec(n int) float64 {
	if n <= 0 {
		n = 2_000_000
	}
	h := commitment.DoubleSHA256([]byte("capacity-seed"))
	start := time.Now()
	for i := 0; i < n; i++ {
		h = commitment.HashPair(h, h)
	}
	el := time.Since(start)
	_ = h
	if el <= 0 {
		return 0
	}
	return float64(n) / el.Seconds()
}

// PlanCapacity derives the sealing capacity for rate r using a given per-core
// software hash rate (pass HashRatePerSec(0) to measure it).
func PlanCapacity(r float64, perCoreHashRate float64) Capacity {
	T := uint64(r) * BlockIntervalSec
	internal := uint64(0)
	if T > 0 {
		internal = T - 1
	}
	c := Capacity{
		R:                 r,
		T:                 T,
		Subtrees:          ceilDiv(T, SubtreeCap),
		SubtreesPerSec:    float64(ceilDiv(T, SubtreeCap)) / float64(BlockIntervalSec),
		InternalHashes:    internal,
		MarginalHashRate:  float64(internal) / float64(BlockIntervalSec),
		InclusiveHashRate: float64(2*T) / float64(BlockIntervalSec),
		ProofBytes:        DigestBytes * ceilLog2(T),
		MeasuredHashRate:  perCoreHashRate,
	}
	if perCoreHashRate > 0 {
		c.CoresMeasured = c.InclusiveHashRate / perCoreHashRate
	}
	c.CoresShaNi = c.InclusiveHashRate / ShaNiRatePerCore
	return c
}
