package bench

// Whole-block verification at the hash-bound ceiling. A node/verifier validating an
// entire block (or a dense set covering it) reconstructs the Merkle forest from the
// leaves and checks the root against the PoW-sealed header. The marginal cost is ~1
// SHA-256d per transaction, so this runs at the box's hash rate — the physical ceiling
// for inclusion verification. Built on the AVX-512 16-lane kernel (internal/sha256mb),
// scalar fallback otherwise. BSV only.

import (
	"sync"
	"sync/atomic"
	"time"

	"mfspv/commitment"
	"mfspv/internal/sha256mb"
)

// buildLevel16 hashes adjacent pairs of cur into next (len = ceil(len(cur)/2)) using
// the 16-lane kernel; an odd tail is duplicated (Bitcoin/Teranode rule).
func buildLevel16(h *sha256mb.Hasher, cur, next []commitment.Hash, msgs *[16][64]byte, out *[16][32]byte) {
	n := len(cur)
	m := len(next)
	for base := 0; base < m; base += 16 {
		cnt := m - base
		if cnt > 16 {
			cnt = 16
		}
		for k := 0; k < cnt; k++ {
			i := (base + k) * 2
			l := cur[i]
			r := l
			if i+1 < n {
				r = cur[i+1]
			}
			copy(msgs[k][:32], l[:])
			copy(msgs[k][32:], r[:])
		}
		h.DoubleSHA256x16(msgs, out)
		for k := 0; k < cnt; k++ {
			next[base+k] = commitment.Hash(out[k])
		}
	}
}

// buildTree16 reduces leaves to a root using the 16-lane kernel, ping-ponging between
// two preallocated scratch buffers (no per-level allocation).
func buildTree16(h *sha256mb.Hasher, leaves, a, b []commitment.Hash, msgs *[16][64]byte, out *[16][32]byte) commitment.Hash {
	if len(leaves) == 1 {
		return leaves[0]
	}
	cur := leaves
	dst := a
	for len(cur) > 1 {
		m := (len(cur) + 1) / 2
		buildLevel16(h, cur, dst[:m], msgs, out)
		cur = dst[:m]
		if &dst[0] == &a[0] {
			dst = b
		} else {
			dst = a
		}
	}
	return cur[0]
}

// VerifyWholeBlockThroughput measures whole-block verification throughput (txs/s) at
// the hash-bound ceiling: each worker repeatedly rebuilds a real `subCap`-leaf subtree
// with the 16-lane kernel and checks the root, reusing scratch (no per-build alloc).
// Returns aggregate transactions-verified/s — the single-box inclusion-verify ceiling.
func VerifyWholeBlockThroughput(subCap, cores int, dur time.Duration) (txPerSec float64, ok bool) {
	if cores < 1 {
		cores = 1
	}
	// reference leaves + expected root (correctness anchor).
	leaves := make([]commitment.Hash, subCap)
	for i := range leaves {
		leaves[i] = commitment.DoubleSHA256([]byte{byte(i), byte(i >> 8), byte(i >> 16), 0x9b})
	}
	wantRoot, _ := commitment.MerkleRoot(leaves)

	var total uint64
	var allOK int32 = 1
	var wg sync.WaitGroup
	deadline := time.Now().Add(dur)
	wg.Add(cores)
	for w := 0; w < cores; w++ {
		go func() {
			defer wg.Done()
			h := sha256mb.NewHasher()
			a := make([]commitment.Hash, (subCap+1)/2)
			b := make([]commitment.Hash, (subCap+1)/2)
			var msgs [16][64]byte
			var out [16][32]byte
			var n uint64
			for time.Now().Before(deadline) {
				root := buildTree16(h, leaves, a, b, &msgs, &out)
				if root != wantRoot {
					atomic.StoreInt32(&allOK, 0)
				}
				n += uint64(subCap)
			}
			atomic.AddUint64(&total, n)
		}()
	}
	wg.Wait()
	secs := dur.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return float64(total) / secs, atomic.LoadInt32(&allOK) == 1
}
