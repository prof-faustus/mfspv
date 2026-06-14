package adversarial

import (
	"math"
	"math/rand"
	"testing"

	"mfspv/commitment"
)

// 06_EVALUATION_DESIGN.md §5 — Monte-Carlo soundness (S1), second-preimage/field
// reordering (S2), and Merkle duplication / CVE-2012-2459 class (S3).
//
// HONEST NOTE: these bound the *implementation* false-accept rate; the guarantee
// that a successful forgery requires a SHA-256d collision is the cryptographic
// reduction (PAPER §7 Lemma 1), not a measured quantity.

// clopperPearsonUpper returns the one-sided upper confidence bound on the true
// false-accept probability given 0 accepts in K trials at confidence 1-alpha:
//
//	p_upper = 1 - alpha^(1/K)
func clopperPearsonUpper(K int, alpha float64) float64 {
	return 1 - math.Pow(alpha, 1/float64(K))
}

// S1: Monte-Carlo inclusion-forgery. K random (leaf, path) forgeries against a
// fixed genuine root must ALL be rejected; report the Clopper-Pearson p_upper.
func TestS1_MonteCarloForgery(t *testing.T) {
	K := 1_000_000
	if testing.Short() {
		K = 50_000
	}
	// A genuine root from a real path.
	leaf := commitment.DoubleSHA256([]byte("genuine-leaf"))
	genuine := make([]commitment.PathElem, 30)
	rng := rand.New(rand.NewSource(0xC0FFEE))
	for i := range genuine {
		var b [8]byte
		rng.Read(b[:])
		genuine[i] = commitment.PathElem{Sibling: commitment.DoubleSHA256(b[:]), Right: rng.Intn(2) == 0}
	}
	root := commitment.Fold(leaf, genuine)

	accepted := 0
	for i := 0; i < K; i++ {
		// random forged leaf + random siblings + random Right bits
		var lb [8]byte
		rng.Read(lb[:])
		fLeaf := commitment.DoubleSHA256(lb[:])
		fp := make([]commitment.PathElem, 1+rng.Intn(43))
		for j := range fp {
			var sb [8]byte
			rng.Read(sb[:])
			fp[j] = commitment.PathElem{Sibling: commitment.DoubleSHA256(sb[:]), Right: rng.Intn(2) == 0}
		}
		if commitment.Fold(fLeaf, fp) == root {
			accepted++ // would be a SHA-256d collision — astronomically unlikely
		}
	}
	if accepted != 0 {
		t.Fatalf("S1: %d/%d random forgeries accepted (collision or bug)", accepted, K)
	}
	pUpper := clopperPearsonUpper(K, 0.01)
	t.Logf("S1: 0/%d forgeries accepted; implementation false-accept p_upper <= %.3e (99%% CI)", K, pUpper)
}

// S1b: systematic single-bit-flip of every element of a genuine path must break it.
func TestS1b_SingleBitFlip(t *testing.T) {
	leaf := commitment.DoubleSHA256([]byte("leaf"))
	path := make([]commitment.PathElem, 24)
	rng := rand.New(rand.NewSource(7))
	for i := range path {
		var b [8]byte
		rng.Read(b[:])
		path[i] = commitment.PathElem{Sibling: commitment.DoubleSHA256(b[:]), Right: i%2 == 0}
	}
	root := commitment.Fold(leaf, path)
	for i := range path {
		for bit := 0; bit < 256; bit++ {
			tampered := make([]commitment.PathElem, len(path))
			copy(tampered, path)
			s := tampered[i].Sibling
			s[bit/8] ^= 1 << uint(bit%8)
			tampered[i].Sibling = s
			if commitment.Fold(leaf, tampered) == root {
				t.Fatalf("single-bit flip at elem %d bit %d preserved the root", i, bit)
			}
		}
	}
}

// S2: second-preimage / field reordering. Moving a field to a different index must
// change the MTxID (leaf-index binding), so an old path no longer verifies.
func TestS2_FieldReordering(t *testing.T) {
	fields := commitment.TxFields{
		{Index: 0, Bytes: []byte("alpha")},
		{Index: 1, Bytes: []byte("beta")},
		{Index: 2, Bytes: []byte("gamma")},
		{Index: 3, Bytes: []byte("delta")},
	}
	_, _, root, err := commitment.MTxIDPath(fields, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Swap the positions (and thus indices) of fields 1 and 2.
	swapped := commitment.TxFields{
		{Index: 0, Bytes: []byte("alpha")},
		{Index: 1, Bytes: []byte("gamma")},
		{Index: 2, Bytes: []byte("beta")},
		{Index: 3, Bytes: []byte("delta")},
	}
	root2, _, _ := commitment.BuildMTxID(swapped)
	if root2 == root {
		t.Fatal("S2: field reordering did not change the MTxID (index not bound)")
	}
	// The original "beta" leaf, now at index 2, must not verify against the old root.
	leafBetaAt2 := commitment.LeafForField(commitment.FieldLeaf{Index: 2, Bytes: []byte("beta")})
	_, p, _, _ := commitment.MTxIDPath(swapped, 2)
	if commitment.VerifyMTxIDPath(leafBetaAt2, p, root) {
		t.Fatal("S2: reordered field verified against the original root")
	}
}

// S3: Merkle duplication ambiguity (CVE-2012-2459 class). We DOCUMENT the known
// property (an odd tail duplicates, so [a,b,c] and [a,b,c,c] share a root) and
// assert it does NOT grant inclusion of a non-member. Block-level rejection of a
// duplicate-tx block is the node's job (Teranode), orthogonal to SPV inclusion.
func TestS3_DuplicationAmbiguity(t *testing.T) {
	a := commitment.DoubleSHA256([]byte("a"))
	b := commitment.DoubleSHA256([]byte("b"))
	c := commitment.DoubleSHA256([]byte("c"))
	r3, _, _ := commitment.BuildMerkleTree([]commitment.Hash{a, b, c})
	r4, _, _ := commitment.BuildMerkleTree([]commitment.Hash{a, b, c, c})
	if r3 != r4 {
		t.Fatal("expected the documented odd-duplication ambiguity (roots should match)")
	}
	// A non-member d cannot be proven against r3 by any short path (would need a
	// SHA-256d preimage). Try the duplication trick and assert rejection.
	d := commitment.DoubleSHA256([]byte("d-not-a-member"))
	_, layers, _ := commitment.BuildMerkleTree([]commitment.Hash{a, b, c})
	// attempt: claim d sits where c is, reusing c's path
	if p, err := commitment.MerklePath(layers, 2); err == nil {
		if commitment.Fold(d, p) == r3 {
			t.Fatal("S3: non-member d proven via duplication (BLOCKING)")
		}
	}
}
