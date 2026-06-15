package bench

import (
	"math/rand"
	"testing"

	"mfspv/commitment"
)

// The minio backend MUST produce byte-identical SHA-256d to the reference, else a
// verifier using it would disagree with consensus. Cross-check over random inputs.
func TestMinioBackendMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	be := MinioBackend()
	for i := 0; i < 100000; i++ {
		var l, r commitment.Hash
		rng.Read(l[:])
		rng.Read(r[:])
		if be.HashPair(l, r) != commitment.HashPair(l, r) {
			t.Fatalf("minio backend disagrees with reference at i=%d", i)
		}
	}
	// batch path agrees too
	const k = 64
	ls := make([]commitment.Hash, k)
	rs := make([]commitment.Hash, k)
	out := make([]commitment.Hash, k)
	for i := 0; i < k; i++ {
		rng.Read(ls[i][:])
		rng.Read(rs[i][:])
	}
	be.HashPairBatch(ls, rs, out)
	for i := 0; i < k; i++ {
		if out[i] != commitment.HashPair(ls[i], rs[i]) {
			t.Fatalf("minio batch disagrees at %d", i)
		}
	}
}
