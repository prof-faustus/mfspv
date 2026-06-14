package commitment

import (
	"bytes"
	"fmt"
	"testing"
)

// helper: a synthetic field set of n fields.
func synthFields(n int) TxFields {
	f := make(TxFields, n)
	for i := range f {
		f[i] = FieldLeaf{Index: uint8(i), Bytes: []byte(fmt.Sprintf("field-%d-payload", i))}
	}
	return f
}

// T1.1 Round-trip: BuildMTxID then MTxIDPath/VerifyMTxIDPath passes for every field index.
func TestT1_1_RoundTrip(t *testing.T) {
	for _, n := range []int{1, 2, 3, 5, 8, 9, 16, 17, 64} {
		fields := synthFields(n)
		for i := 0; i < n; i++ {
			leaf, path, mtxid, err := MTxIDPath(fields, uint8(i))
			if err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
			if !VerifyMTxIDPath(leaf, path, mtxid) {
				t.Fatalf("n=%d i=%d: valid path rejected", n, i)
			}
		}
	}
}

// T1.2 Forgery rejected: flip one byte of any sibling => Verify*Path == false. (I-C1)
func TestT1_2_ForgeryRejected(t *testing.T) {
	fields := synthFields(17)
	for i := 0; i < len(fields); i++ {
		leaf, path, mtxid, err := MTxIDPath(fields, uint8(i))
		if err != nil {
			t.Fatal(err)
		}
		if len(path) == 0 {
			continue
		}
		for j := range path {
			tampered := make([]PathElem, len(path))
			copy(tampered, path)
			s := tampered[j].Sibling
			s[0] ^= 0x01 // flip one byte
			tampered[j].Sibling = s
			if VerifyMTxIDPath(leaf, tampered, mtxid) {
				t.Fatalf("i=%d j=%d: tampered sibling accepted", i, j)
			}
		}
		// flipping the root must also fail
		bad := mtxid
		bad[0] ^= 0x01
		if VerifyMTxIDPath(leaf, path, bad) {
			t.Fatalf("i=%d: tampered root accepted", i)
		}
		// flipping the leaf must also fail
		badLeaf := leaf
		badLeaf[0] ^= 0x01
		if VerifyMTxIDPath(badLeaf, path, mtxid) {
			t.Fatalf("i=%d: tampered leaf accepted", i)
		}
	}
}

// T1.3 Depth law: for synthetic blocks at r in {1e6..1e10}, VerifyToBlockRoot reports
// depth == ceil(log2 T). (Result 4.1 / I-BE1)
//
// We cannot materialise 6e8..6e12 leaves, so we synthesise a VALID inclusion of the
// correct path length and assert the depth bookkeeping. l0 is empty (leaf == TXID),
// so depth == |l1|+|l2| == ceil(log2 T) exactly, matching 03_SCALING_MODEL's table.
func TestT1_3_DepthLaw(t *testing.T) {
	type row struct {
		r      float64
		wantD  int
		wantL1 int
		wantL2 int
	}
	rows := []row{
		{1e6, 30, 20, 10},
		{1e7, 33, 20, 13},
		{1e8, 36, 20, 16},
		{1e9, 40, 20, 20},
		{1e10, 43, 20, 23},
	}
	const S = uint64(1) << 20
	for _, rw := range rows {
		T := uint64(rw.r) * 600
		depth := CeilLog2(T)
		if depth != rw.wantD {
			t.Fatalf("r=%g: depth=%d want %d", rw.r, depth, rw.wantD)
		}
		l1len := CeilLog2(min64(T, S))
		l2len := depth - l1len
		if l1len != rw.wantL1 || l2len != rw.wantL2 {
			t.Fatalf("r=%g: L1=%d L2=%d want %d/%d", rw.r, l1len, l2len, rw.wantL1, rw.wantL2)
		}
		// Build a valid synthetic inclusion of this exact shape and confirm
		// VerifyToBlockRoot accepts it and reports depth == ceil(log2 T).
		txid := DoubleSHA256([]byte(fmt.Sprintf("txid-%g", rw.r)))
		l1 := synthPath(l1len, 1)
		l2 := synthPath(l2len, 2)
		sub := Fold(txid, l1)
		blockRoot := Fold(sub, l2)
		ok, gotDepth := VerifyToBlockRoot(txid, nil, l1, l2, blockRoot)
		if !ok {
			t.Fatalf("r=%g: synthetic inclusion rejected", rw.r)
		}
		if gotDepth != depth {
			t.Fatalf("r=%g: reported depth %d want %d", rw.r, gotDepth, depth)
		}
	}
}

// T1.4 Determinism: BuildMTxID twice on identical fields => identical root + layers. (I-C1)
func TestT1_4_Determinism(t *testing.T) {
	fields := synthFields(13)
	r1, l1, err := BuildMTxID(fields)
	if err != nil {
		t.Fatal(err)
	}
	r2, l2, err := BuildMTxID(fields)
	if err != nil {
		t.Fatal(err)
	}
	if r1 != r2 {
		t.Fatal("non-deterministic root")
	}
	if len(l1) != len(l2) {
		t.Fatal("layer count differs")
	}
	for i := range l1 {
		if len(l1[i]) != len(l2[i]) {
			t.Fatalf("layer %d length differs", i)
		}
		for j := range l1[i] {
			if l1[i][j] != l2[i][j] {
				t.Fatalf("layer %d node %d differs", i, j)
			}
		}
	}
}

// T1.5 Reconstruct-from-root+fields: drop layers, rebuild from fields, root matches.
// (US 2022/0216997 [0166])
func TestT1_5_Reconstruct(t *testing.T) {
	fields := synthFields(21)
	root1, _, err := BuildMTxID(fields)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate storing only root + fields: rebuild from fields alone.
	root2, layers, err := BuildMTxID(fields)
	if err != nil {
		t.Fatal(err)
	}
	if root1 != root2 {
		t.Fatal("rebuilt root mismatch")
	}
	// And every field's path still verifies against the rebuilt root.
	for i := range fields {
		p, _ := MerklePath(layers, i)
		if !VerifyMTxIDPath(leafHash(fields[i]), p, root2) {
			t.Fatalf("field %d path fails after rebuild", i)
		}
	}
}

// T1.6 Depth ceiling: a crafted >255 path is a hard error. (I-C3)
func TestT1_6_DepthCeiling(t *testing.T) {
	leaf := DoubleSHA256([]byte("leaf"))
	long := synthPath(256, 9) // 256 > MaxDepth
	root := Fold(leaf, long)
	// Even though the fold is arithmetically correct, the verifier must reject
	// an over-deep path rather than honour it.
	if VerifyMTxIDPath(leaf, long, root) {
		t.Fatal("over-deep MTxID path accepted")
	}
	ok, _ := VerifyToBlockRoot(leaf, long, nil, nil, root)
	if ok {
		t.Fatal("over-deep composed path accepted")
	}
	if VerifyBlockPath(leaf, long, root) {
		t.Fatal("over-deep block path accepted")
	}
}

// Subtree path length cap (I-C3 at L1).
func TestSubtreePathCap(t *testing.T) {
	txid := DoubleSHA256([]byte("tx"))
	long := synthPath(21, 3) // > 20 elems for a 2^20 subtree
	root := Fold(txid, long)
	if VerifySubtreePath(txid, long, root) {
		t.Fatal("subtree path > 20 accepted")
	}
}

// duplication rule sanity: odd tail folds against itself.
func TestOddDuplication(t *testing.T) {
	leaves := []Hash{
		DoubleSHA256([]byte("a")),
		DoubleSHA256([]byte("b")),
		DoubleSHA256([]byte("c")),
	}
	root, layers, err := BuildMerkleTree(leaves)
	if err != nil {
		t.Fatal(err)
	}
	// manual: H(H(a,b), H(c,c))
	want := HashPair(HashPair(leaves[0], leaves[1]), HashPair(leaves[2], leaves[2]))
	if root != want {
		t.Fatal("odd duplication rule mismatch")
	}
	for i := range leaves {
		p, _ := MerklePath(layers, i)
		if Fold(leaves[i], p) != root {
			t.Fatalf("leaf %d path fails", i)
		}
	}
}

// --- helpers ---

func synthPath(n int, seed byte) []PathElem {
	p := make([]PathElem, n)
	for i := range p {
		p[i] = PathElem{
			Sibling: DoubleSHA256([]byte{seed, byte(i), byte(i >> 8)}),
			Right:   (i+int(seed))%2 == 0,
		}
	}
	return p
}

func min64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

var _ = bytes.Equal
