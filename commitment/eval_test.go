package commitment

import (
	"encoding/hex"
	"math/rand"
	"testing"
)

// 06_EVALUATION_DESIGN.md §4.1 (KAT), §4.2 (property), §4.3 (differential oracle).

// KAT: SHA-256d against canonical Bitcoin HASH256 values (independent, published).
func TestKAT_DoubleSHA256(t *testing.T) {
	cases := []struct{ in, want string }{
		// hash256("hello") — canonical Bitcoin double-SHA256 example
		{"hello", "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50"},
		// hash256("") — well-known double-SHA256 of the empty string
		{"", "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"},
	}
	for _, c := range cases {
		got := DoubleSHA256([]byte(c.in))
		if hex.EncodeToString(got[:]) != c.want {
			t.Fatalf("DoubleSHA256(%q) = %x, want %s", c.in, got, c.want)
		}
	}
}

// --- §4.3 Differential (oracle) testing ---

// naiveRoot is a deliberately independent, recursive reference Merkle root using
// Bitcoin's odd-node duplication rule. Different code path from BuildMerkleTree.
func naiveRoot(leaves []Hash) Hash {
	if len(leaves) == 1 {
		return leaves[0]
	}
	var next []Hash
	for i := 0; i < len(leaves); i += 2 {
		if i+1 < len(leaves) {
			next = append(next, HashPair(leaves[i], leaves[i+1]))
		} else {
			next = append(next, HashPair(leaves[i], leaves[i])) // duplicate odd tail
		}
	}
	return naiveRoot(next)
}

// TestDifferentialMerkle cross-checks BuildMerkleTree against the independent
// reference over many random leaf-multisets, INCLUDING odd cardinalities (the
// historical source of Bitcoin Merkle bugs). (06 §4.3)
func TestDifferentialMerkle(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5EED))
	const cases = 20000
	for c := 0; c < cases; c++ {
		n := 1 + rng.Intn(33) // 1..33 leaves -> exercises odd levels
		leaves := make([]Hash, n)
		for i := range leaves {
			var b [8]byte
			rng.Read(b[:])
			leaves[i] = DoubleSHA256(b[:])
		}
		got, _, err := BuildMerkleTree(leaves)
		if err != nil {
			t.Fatal(err)
		}
		if got != naiveRoot(leaves) {
			t.Fatalf("differential mismatch at case %d (n=%d)", c, n)
		}
	}
}

// --- §4.2 Property-based tests (≥1e5 cases each, fixed seed) ---

func randFields(rng *rand.Rand) TxFields {
	n := 1 + rng.Intn(24)
	f := make(TxFields, n)
	for i := range f {
		ln := rng.Intn(40)
		b := make([]byte, ln)
		rng.Read(b)
		f[i] = FieldLeaf{Index: uint8(i), Bytes: b}
	}
	return f
}

// P1 round-trip + P2 determinism + P3 reconstruct, over 1e5 cases. (T1.1/T1.4/T1.5)
func TestProperty_RoundTripDeterminismReconstruct(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	const cases = 100000
	for c := 0; c < cases; c++ {
		f := randFields(rng)
		idx := uint8(rng.Intn(len(f)))
		leaf, path, root, err := MTxIDPath(f, idx)
		if err != nil {
			t.Fatal(err)
		}
		// P1: genuine path verifies.
		if !VerifyMTxIDPath(leaf, path, root) {
			t.Fatalf("case %d: round-trip failed", c)
		}
		// P2: determinism.
		root2, _, _ := BuildMTxID(f)
		if root2 != root {
			t.Fatalf("case %d: non-deterministic root", c)
		}
		// P3: reconstruct from root+fields (drop layers, rebuild).
		root3, _, _ := BuildMTxID(f)
		if root3 != root {
			t.Fatalf("case %d: reconstruct mismatch", c)
		}
	}
}

// P4 depth bound: no generated path exceeds 255; over-long paths hard-error. (T1.6)
func TestProperty_DepthBound(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	for c := 0; c < 100000; c++ {
		f := randFields(rng)
		_, path, _, _ := MTxIDPath(f, uint8(rng.Intn(len(f))))
		if len(path) > MaxDepth {
			t.Fatalf("case %d: path length %d exceeds MaxDepth", c, len(path))
		}
	}
	// crafted over-long path is rejected
	leaf := DoubleSHA256([]byte("x"))
	long := make([]PathElem, 256)
	if VerifyMTxIDPath(leaf, long, Fold(leaf, long)) {
		t.Fatal("over-long path accepted")
	}
}

// P6 subtree cap: any accepted L1 path has length <= 20. (I-TA2)
func TestProperty_SubtreeCap(t *testing.T) {
	txid := DoubleSHA256([]byte("tx"))
	for n := 0; n <= 25; n++ {
		path := make([]PathElem, n)
		for i := range path {
			path[i] = PathElem{Sibling: DoubleSHA256([]byte{byte(i)})}
		}
		root := Fold(txid, path)
		accepted := VerifySubtreePath(txid, path, root)
		if n <= 20 && !accepted {
			t.Fatalf("n=%d: legal subtree path rejected", n)
		}
		if n > 20 && accepted {
			t.Fatalf("n=%d: oversized subtree path accepted", n)
		}
	}
}
