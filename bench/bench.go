// Package bench is the scaling simulator (02_MODULE_SPECS.md §bench,
// 03_SCALING_MODEL.md). Every number it emits is DERIVED from BSV parameters, not
// tuned: deviations from 03_SCALING_MODEL's target table are bugs, not noise.
//
// The headline claims it makes falsifiable:
//   - I-BE1 depth == ceil(log2 T)
//   - I-BE2 proofBytes == 32*depth
//   - I-BE3 HeaderGrowthBytesPerYear() constant across r (~4.2e6)
//   - I-BE4 verifyMS grows logarithmically (∝ depth), not linearly in T
//
// BSV only.
package bench

import (
	"time"

	"mfspv/commitment"
)

// BSV parameters (03_SCALING_MODEL.md). None is changed by this design.
const (
	BlockIntervalSec = 600             // ~10-minute block
	HeaderBytes      = 80              // BSV header
	BlocksPerYear    = 144 * 365       // 52,560
	SubtreeCap       = uint64(1) << 20 // 2^20 TXIDs per Teranode subtree
	DigestBytes      = 32              // SHA-256d
)

// BenchRow is one throughput point.
type BenchRow struct {
	R              float64 // tx/s
	T              uint64  // tx/block = r * 600
	Depth          int     // ceil(log2 T) — inclusion path length (L1+L2)
	ProofBytes     int     // 32 * depth (core L0–L2 path)
	Subtrees       uint64  // ceil(T / 2^20)
	L1Len          int     // ceil(log2(min(T, 2^20)))
	L2Len          int     // depth - L1Len
	BuildMS        float64 // time to fold/build a representative path (measured)
	VerifyMS       float64 // measured fold time of a depth-length path
	PushNetBytes   int     // per-payment proof bytes on the network under the push model (0)
	PullNetBytes   int     // bytes a pull-model verifier would fetch (legacy SPV / TxChain)
	FlyClientCeilB int     // FlyClient-style saving ceiling = full header dataset (does NOT scale with r)
}

// ceilLog2 over integers (no float rounding).
func ceilLog2(n uint64) int { return commitment.CeilLog2(n) }

func min64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func ceilDiv(a, b uint64) uint64 { return (a + b - 1) / b }

// SimulateBlock returns the derived figures for a throughput r, measuring verify
// (and a representative build) by actually folding a synthetic path of the correct
// length. The fold work is real, so VerifyMS genuinely scales with depth.
func SimulateBlock(rTxPerS float64) (T uint64, depth int, proofBytes int, buildMS, verifyMS float64) {
	T = uint64(rTxPerS) * BlockIntervalSec
	depth = ceilLog2(T)
	proofBytes = DigestBytes * depth

	// Build a synthetic valid inclusion of length `depth` and measure folding it.
	leaf := commitment.DoubleSHA256([]byte("bench-leaf"))
	path := make([]commitment.PathElem, depth)
	for i := range path {
		path[i] = commitment.PathElem{
			Sibling: commitment.DoubleSHA256([]byte{byte(i), byte(i >> 8)}),
			Right:   i%2 == 0,
		}
	}
	root := commitment.Fold(leaf, path)

	const iters = 2000
	startV := time.Now()
	for i := 0; i < iters; i++ {
		if commitment.Fold(leaf, path) != root {
			panic("bench: fold mismatch")
		}
	}
	verifyMS = float64(time.Since(startV).Nanoseconds()) / float64(iters) / 1e6

	// "Build" here is the prover-side cost of assembling the path (hashing `depth`
	// pairs), measured the same way for a representative figure.
	startB := time.Now()
	for i := 0; i < iters; i++ {
		node := leaf
		for j := range path {
			node = commitment.HashPair(node, path[j].Sibling)
		}
		_ = node
	}
	buildMS = float64(time.Since(startB).Nanoseconds()) / float64(iters) / 1e6
	return
}

// Row computes a full BenchRow for r.
func Row(rTxPerS float64) BenchRow {
	T, depth, proofBytes, buildMS, verifyMS := SimulateBlock(rTxPerS)
	l1 := ceilLog2(min64(T, SubtreeCap))
	return BenchRow{
		R:              rTxPerS,
		T:              T,
		Depth:          depth,
		ProofBytes:     proofBytes,
		Subtrees:       ceilDiv(T, SubtreeCap),
		L1Len:          l1,
		L2Len:          depth - l1,
		BuildMS:        buildMS,
		VerifyMS:       verifyMS,
		PushNetBytes:   0,                          // R4: proof is sender-pushed
		PullNetBytes:   proofBytes,                 // bytes a pull verifier would fetch
		FlyClientCeilB: HeaderGrowthBytesPerYear(), // R2/Result 4.3: constant ceiling
	}
}

// SweepThroughput returns rows for each r (defaults to {1e6..1e11} if rs is nil).
// 1e11 is 100 billion tx/s — the target operating point; 1e12 is included by
// SweepThroughputExtended for headroom.
func SweepThroughput(rs []float64) []BenchRow {
	if rs == nil {
		rs = []float64{1e6, 1e7, 1e8, 1e9, 1e10, 1e11}
	}
	rows := make([]BenchRow, 0, len(rs))
	for _, r := range rs {
		rows = append(rows, Row(r))
	}
	return rows
}

// SweepThroughputExtended sweeps {1e6 .. 1e12} to show headroom beyond the 100
// billion tx/s (1e11) operating point.
func SweepThroughputExtended() []BenchRow {
	return SweepThroughput([]float64{1e6, 1e7, 1e8, 1e9, 1e10, 1e11, 1e12})
}

// HeaderGrowthBytesPerYear returns the BSV header dataset growth: 80 B * 52,560
// blocks/year ≈ 4.2 MB/year, INDEPENDENT of throughput r (Result 4.2 / I-BE3).
func HeaderGrowthBytesPerYear() int { return HeaderBytes * BlocksPerYear }
