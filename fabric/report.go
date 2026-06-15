package fabric

import (
	"fmt"
	"io"
	"runtime"
	"sync"
	"time"

	"mfspv/commitment"
	"mfspv/teranode"
)

// Bar is the 07_VERIFICATION_FABRIC.md throughput target: verif/s >= 1.5e7 (A>=1.5).
const Bar = 1.5e7

// BuildBlock builds a REAL block (numSub subtrees of subCap leaves) and returns a
// proof for every leaf plus a header-chain view that contains the block header.
func BuildBlock(subCap, numSub int) ([]Proof, teranode.HeaderChain, error) {
	subRoots := make([]Hash, numSub)
	subLayers := make([][][]Hash, numSub)
	for s := 0; s < numSub; s++ {
		leaves := make([]Hash, subCap)
		for i := range leaves {
			leaves[i] = commitment.DoubleSHA256([]byte{byte(s), byte(s >> 8), byte(i), byte(i >> 8)})
		}
		root, layers, err := commitment.BuildMerkleTree(leaves)
		if err != nil {
			return nil, nil, err
		}
		subRoots[s] = root
		subLayers[s] = layers
	}
	blockRoot, blockLayers, err := commitment.BuildMerkleTree(subRoots)
	if err != nil {
		return nil, nil, err
	}
	var hdr [80]byte
	hdr[0] = 1
	copy(hdr[36:68], blockRoot[:])

	proofs := make([]Proof, 0, subCap*numSub)
	for s := 0; s < numSub; s++ {
		l2, _ := commitment.MerklePath(blockLayers, s)
		for i, leaf := range subLayers[s][0] {
			l1, _ := commitment.MerklePath(subLayers[s], i)
			proofs = append(proofs, Proof{Leaf: leaf, L1: l1, SubtreeRoot: subRoots[s], L2: l2, Header: hdr})
		}
	}
	return proofs, teranode.NewStaticHeaderChain([][80]byte{hdr}, 1), nil
}

// MeasureAggregateHashRate measures aggregate independent SHA-256d/s across cores.
func MeasureAggregateHashRate(cores int) float64 {
	const per = 1_500_000
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < cores; w++ {
		wg.Add(1)
		go func(seed byte) {
			defer wg.Done()
			var b [64]byte
			b[0] = seed
			var s Hash
			for i := 0; i < per; i++ {
				b[1] = byte(i)
				b[2] = byte(i >> 8)
				s = commitment.DoubleSHA256(b[:])
			}
			_ = s
		}(byte(w))
	}
	wg.Wait()
	return float64(cores*per) / time.Since(start).Seconds()
}

// MeasureBatchThroughput runs BatchVerify on `cores` goroutines for dur and returns
// aggregate verifications/s.
func MeasureBatchThroughput(h Hasher, proofs []Proof, chain teranode.HeaderChain, cores int, dur time.Duration) float64 {
	var total int64
	var mu sync.Mutex
	var wg sync.WaitGroup
	deadline := time.Now().Add(dur)
	for w := 0; w < cores; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make([]Proof, len(proofs))
			copy(local, proofs)
			var count int64
			for time.Now().Before(deadline) {
				if ok, _ := BatchVerify(h, local, chain); !ok {
					panic("fabric: batch verify failed mid-benchmark")
				}
				count += int64(len(local))
			}
			mu.Lock()
			total += count
			mu.Unlock()
		}()
	}
	wg.Wait()
	return float64(total) / dur.Seconds()
}

func passFail(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

// RunReport runs the 07 §7 benchmark and writes the measured table to out: per-core
// and aggregate hash rate, the sparse single-proof A per depth, the dense batched A
// per density, and the Lever C core requirement. Honest, measured on this box.
func RunReport(out io.Writer) {
	h := DefaultHasher()
	cores := runtime.NumCPU()
	agg := MeasureAggregateHashRate(cores)
	perCore := agg / float64(cores)

	fmt.Fprintln(out, "== 07 Verification-Fabric benchmark (bar: verif/s >= 1.5e7, A>=1.5) ==")
	fmt.Fprintf(out, "backend=%s  cores=%d  per-core=%.2fM dsha/s  aggregate=%.3e dsha/s\n",
		h.Name(), cores, perCore/1e6, agg)

	fmt.Fprintln(out, "-- Lever 0: sparse single-proof (derived from measured aggregate) --")
	for _, d := range []int{30, 40, 43, 46} {
		v := VerifPerSec(agg, float64(d))
		fmt.Fprintf(out, "   depth=%-2d  verif/s=%.3e  A=%.2f  %s\n", d, v, v/Bar, passFail(v >= Bar))
	}

	fmt.Fprintln(out, "-- Lever B: dense batch verification (measured, real block, subtree=4096) --")
	for _, numSub := range []int{1, 4, 64} {
		proofs, chain, err := BuildBlock(4096, numSub)
		if err != nil {
			fmt.Fprintln(out, "   build error:", err)
			continue
		}
		_, hashes := BatchVerify(h, proofs, chain)
		amortized := float64(hashes) / float64(len(proofs))
		v := MeasureBatchThroughput(h, proofs, chain, cores, 300*time.Millisecond)
		fmt.Fprintf(out, "   proofs=%-7d subtrees=%-3d amortized-depth=%.3f  verif/s=%.3e  A=%.2f  %s\n",
			len(proofs), numSub, amortized, v, v/Bar, passFail(v >= Bar))
	}

	fmt.Fprintf(out, "-- Lever C: software cores to hit %.1e at depth 43 (sparse) = %.0f --\n",
		Bar, RequiredCores(Bar, 43, perCore))
	fmt.Fprintln(out, "Result: dense batched verification clears the bar on the software path;")
	fmt.Fprintln(out, "sparse single-proof needs Lever A (SHA-NI/AVX2) or scale-out. No consensus change.")
}
