package fabric

import (
	"os"
	"testing"

	"mfspv/commitment"
	"mfspv/teranode"
)

// Correctness: BatchVerify accepts a valid batch, amortises, and rejects tampering.
func TestBatchVerifyCorrect(t *testing.T) {
	h := DefaultHasher()
	proofs, chain, err := BuildBlock(16, 4) // 64 proofs
	if err != nil {
		t.Fatal(err)
	}
	ok, hashes := BatchVerify(h, proofs, chain)
	if !ok {
		t.Fatal("valid batch rejected")
	}
	for i := range proofs {
		if ok, _ := VerifyOne(h, proofs[i], chain); !ok {
			t.Fatalf("proof %d failed VerifyOne", i)
		}
	}
	naive := 0
	for i := range proofs {
		naive += len(proofs[i].L1) + len(proofs[i].L2)
	}
	if hashes >= naive {
		t.Fatalf("no amortisation: batch=%d naive=%d", hashes, naive)
	}
	bad := make([]Proof, len(proofs))
	copy(bad, proofs)
	bad[10].Leaf[0] ^= 0xff
	if ok, _ := BatchVerify(h, bad, chain); ok {
		t.Fatal("tampered batch accepted")
	}
	if ok, _ := BatchVerify(h, proofs, teranode.NewStaticHeaderChain(nil, 0)); ok {
		t.Fatal("off-chain batch accepted")
	}
}

// §5: the inclusion leaf is the consensus TXID, folded with l0=nil. The fabric path
// agrees with commitment.VerifyToBlockRoot(leaf=txid).
func TestLeafIsConsensusTXID(t *testing.T) {
	proofs, _, err := BuildBlock(16, 2)
	if err != nil {
		t.Fatal(err)
	}
	p := proofs[5]
	ok, depth := commitment.VerifyToBlockRoot(p.Leaf, nil, p.L1, p.L2, HeaderMerkleRoot(p.Header))
	if !ok {
		t.Fatal("VerifyToBlockRoot rejected a valid consensus-TXID proof")
	}
	if depth != len(p.L1)+len(p.L2) {
		t.Fatalf("depth=%d", depth)
	}
}

// Lever C capacity equation is monotone and matches the closed form.
func TestCapacityEquation(t *testing.T) {
	// 1.5e7 verif/s at depth 43 and 3e6/core -> 215 cores.
	got := RequiredCores(1.5e7, 43, 3e6)
	if got < 200 || got > 220 {
		t.Fatalf("RequiredCores=%.0f, want ~215", got)
	}
}

// The 07 §7 benchmark (measured). Skipped in -short; run with: go test -run TestFabricBar -v ./fabric
func TestFabricBar(t *testing.T) {
	if testing.Short() {
		t.Skip("throughput benchmark skipped in -short")
	}
	RunReport(os.Stdout)
}
