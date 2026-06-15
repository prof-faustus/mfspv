package bench

// Verification fabric — Levers B (batch amortization) and C (capacity), plus the
// measured throughput vs the >=1.5e7 verifications/s bar (07_VERIFICATION_FABRIC.md
// §4, §6, §7). All folds are REAL SHA-256d over real Merkle paths; nothing simulated.
//
// Lever B (batch): in IP-to-IP commerce a verifier processes MANY proofs at once.
// Proofs in the same block share the header/PoW (L3, once per block); proofs in the
// same subtree share the subtree-root -> block-root path (L2, once per subtree). Only
// the TXID -> subtree-root path (L1, <=20) is per-proof and non-amortizable. So for a
// batch of P proofs spanning S distinct subtrees in B blocks the amortized cost is
//   per_proof_hashes ~= L1 + (S/P)*L2 + (B/P)*L3check
// and per-proof cost decouples from the L2 growth between 1e6 and 1e11 tx/s.
//
// Lever C (capacity): bench.PlanCapacity already emits cores needed for a target rate
// from a measured per-core rate; FabricCapacityForBar() inverts it for the edge bar.
//
// Inclusion-leaf correction (§5): the inclusion leaf is the consensus TXID; L0 (the
// field/MTxID tree) is OFF the inclusion path. Here leaf == txid and we fold L1->L2.

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"

	"mfspv/commitment"
)

// VerifBar is the throughput pass threshold: verifications per second.
const VerifBar = 1.5e7

// BatchProof is one inclusion proof in a batch. Leaf is the consensus TXID (§5).
// L1 folds TXID->subtreeRoot (<=20); L2 folds subtreeRoot->blockRoot; both BlockHash
// and SubtreeRoot key the shared-work caches.
type BatchProof struct {
	Leaf        commitment.Hash // consensus TXID
	L1          []commitment.PathElem
	L2          []commitment.PathElem
	SubtreeRoot commitment.Hash
	BlockRoot   commitment.Hash
	BlockHash   commitment.Hash
}

func txidFromIndex(block uint64, i uint64) commitment.Hash {
	var b [16]byte
	binary.LittleEndian.PutUint64(b[:8], block)
	binary.LittleEndian.PutUint64(b[8:], i)
	return commitment.DoubleSHA256(b[:])
}

// BuildBatch constructs a REAL batch of P inclusion proofs spanning S distinct
// subtrees within one block whose inclusion depth is `depth` (L1len + L2len), with
// L1len = min(depth,20). Each of the S subtrees has ONE shared, self-consistent
// inclusion (leaf, L1 -> subtreeRoot, L2 -> blockRoot); the P proofs replicate those
// S subtrees round-robin, so proofs in the same subtree share the subtree root and L2
// path. Density P/S then controls L2 sharing: dense (P>>S) -> L2 amortized to ~0;
// sparse (P==S) -> every proof pays its own L2. All folds are real SHA-256d.
func BuildBatch(depth, P, S int) []BatchProof {
	if S < 1 {
		S = 1
	}
	if S > P {
		S = P
	}
	l1len := depth
	if l1len > 20 {
		l1len = 20
	}
	l2len := depth - l1len

	blockHash := commitment.DoubleSHA256([]byte("block-0"))
	// One real, self-consistent subtree inclusion per distinct subtree.
	sub := make([]BatchProof, S)
	for s := 0; s < S; s++ {
		leaf := txidFromIndex(0, uint64(s)) // consensus TXID (inclusion leaf, §5)
		l1 := make([]commitment.PathElem, l1len)
		for i := range l1 {
			l1[i] = commitment.PathElem{
				Sibling: commitment.DoubleSHA256([]byte{byte(s), byte(s >> 8), byte(i), 0xA1}),
				Right:   i%2 == 0,
			}
		}
		sr := commitment.Fold(leaf, l1) // TXID -> subtree root (real fold)
		l2 := make([]commitment.PathElem, l2len)
		for i := range l2 {
			l2[i] = commitment.PathElem{
				Sibling: commitment.DoubleSHA256([]byte{byte(s), byte(i), 0xA2}),
				Right:   i%2 == 0,
			}
		}
		sub[s] = BatchProof{
			Leaf: leaf, L1: l1, L2: l2,
			SubtreeRoot: sr,
			BlockRoot:   commitment.Fold(sr, l2), // subtree root -> block root (real)
			BlockHash:   blockHash,
		}
	}

	proofs := make([]BatchProof, P)
	for p := 0; p < P; p++ {
		proofs[p] = sub[p%S] // proofs in the same subtree share root + L2 path
	}
	return proofs
}

// foldWith folds a leaf up a path using a specific backend's HashPair.
func foldWith(be Backend, leaf commitment.Hash, path []commitment.PathElem) commitment.Hash {
	node := leaf
	for _, e := range path {
		if e.Right {
			node = be.HashPair(node, e.Sibling)
		} else {
			node = be.HashPair(e.Sibling, node)
		}
	}
	return node
}

// FabricRow is one measured (depth, density, backend) throughput point.
type FabricRow struct {
	Depth     int
	P, S      int
	Density   float64 // P/S
	Backend   string
	VerifPerS float64 // amortized verifications/sec across workers
	A         float64 // VerifPerS / 1.5e7
	Pass      bool
}

// FabricThroughput measures AMORTIZED batch-verification throughput on a realistic
// sharded, cold batch. Each worker owns whole subtrees (so no shared cache, no locks)
// and repeatedly verifies its sub-batch from a COLD local verified-roots set: the
// first proof of each subtree pays the L2 fold (subtreeRoot->blockRoot) once, every
// later proof of that subtree pays only its L1 fold. Total work per pass over P proofs
// across S subtrees is P*L1 + S*L2, so throughput rises with density P/S — this is the
// real Lever-B amortization, measured, not assumed.
func FabricThroughput(proofs []BatchProof, be Backend, workers int, dur time.Duration) float64 {
	if workers < 1 {
		workers = 1
	}
	// Each worker verifies the WHOLE batch with its own LOCAL verified-roots memo, so
	// per-worker density == batch density (no shared cache, no locks). Aggregate
	// verif/s = sum over workers; the fabric is shares-nothing, so this is the real
	// scale-out (Lever C) of the amortized (Lever B) per-proof cost.
	var count uint64
	var wg sync.WaitGroup
	deadline := time.Now().Add(dur)
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			var local uint64
			seen := make(map[commitment.Hash]commitment.Hash, 2048) // subtreeRoot -> blockRoot
			for {
				for k := range seen { // cold per pass: L2 paid once per subtree per pass
					delete(seen, k)
				}
				for i := range proofs {
					p := &proofs[i]
					if foldWith(be, p.Leaf, p.L1) != p.SubtreeRoot { // L1 always (per proof)
						continue
					}
					br, ok := seen[p.SubtreeRoot]
					if !ok { // first proof of this subtree pays the L2 fold once
						br = foldWith(be, p.SubtreeRoot, p.L2)
						seen[p.SubtreeRoot] = br
					}
					if br == p.BlockRoot {
						local++
					}
				}
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
	return float64(count) / secs
}

// MeasureFabric runs the fabric benchmark at the depth implied by rate r, across the
// given densities and backends, and returns PASS/FAIL rows vs the 1.5e7 bar.
func MeasureFabric(r float64, densities []float64, backends []Backend, workers int, dur time.Duration) []FabricRow {
	T := uint64(r) * BlockIntervalSec
	depth := ceilLog2(T)
	var rows []FabricRow
	for _, be := range backends {
		for _, d := range densities {
			P := 4096
			S := int(float64(P) / d)
			if S < 1 {
				S = 1
			}
			proofs := BuildBatch(depth, P, S)
			vps := FabricThroughput(proofs, be, workers, dur)
			rows = append(rows, FabricRow{
				Depth: depth, P: P, S: S, Density: float64(P) / float64(S),
				Backend: be.Name, VerifPerS: vps, A: vps / VerifBar, Pass: vps >= VerifBar,
			})
		}
	}
	return rows
}

// FabricCapacityForBar (Lever C) returns the software cores needed to reach the edge
// bar at depth(r), given the measured per-core SHA-256d rate: cores = bar*depth/rate.
func FabricCapacityForBar(r, perCoreHashRate float64) (depth int, coresSoftware, coresShaNi float64) {
	T := uint64(r) * BlockIntervalSec
	depth = ceilLog2(T)
	if perCoreHashRate > 0 {
		coresSoftware = VerifBar * float64(depth) / perCoreHashRate
	}
	coresShaNi = VerifBar * float64(depth) / ShaNiRatePerCore
	return
}
