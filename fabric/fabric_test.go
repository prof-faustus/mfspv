package fabric

import (
	"os"
	"runtime"
	"testing"
	"time"

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

// Codec round-trips and decoded proofs verify.
func TestCodecRoundTrip(t *testing.T) {
	proofs, chain, err := BuildBlock(8, 3)
	if err != nil {
		t.Fatal(err)
	}
	wire := EncodeBatch(proofs)
	dec, err := DecodeBatch(wire, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(dec) != len(proofs) {
		t.Fatalf("decoded %d want %d", len(dec), len(proofs))
	}
	if ok, _ := BatchVerify(DefaultHasher(), dec, chain); !ok {
		t.Fatal("decoded batch failed to verify")
	}
	// truncation rejected
	if _, err := DecodeBatch(wire[:len(wire)-5], nil); err == nil {
		t.Fatal("truncated batch accepted")
	}
}

// VerifyWire (streaming, zero-alloc) agrees with BatchVerify and rejects tampering.
func TestVerifyWire(t *testing.T) {
	proofs, chain, err := BuildBlock(64, 8)
	if err != nil {
		t.Fatal(err)
	}
	wire := EncodeBatch(proofs)
	v := NewVerifier()
	ok, _, np := v.VerifyWire(DefaultHasher(), wire, chain)
	if !ok || np != len(proofs) {
		t.Fatalf("VerifyWire ok=%v np=%d want %d", ok, np, len(proofs))
	}
	// reuse the same verifier (maps cleared) — must still pass
	if ok, _, _ := v.VerifyWire(DefaultHasher(), wire, chain); !ok {
		t.Fatal("reused verifier failed")
	}
	// tamper a leaf byte in the wire -> reject
	bad := make([]byte, len(wire))
	copy(bad, wire)
	bad[100] ^= 0xff
	if ok, _, _ := v.VerifyWire(DefaultHasher(), bad, chain); ok {
		t.Fatal("tampered wire accepted")
	}
}

// TestCompletePipelineMeetsBar asserts the COMPLETE real pipeline clears the bar on
// a target-class box (>=32 cores). It SKIPS on small CI runners (the bar is defined
// for the deployment server), but always checks correctness of the real path.
func TestCompletePipelineMeetsBar(t *testing.T) {
	if testing.Short() {
		t.Skip("throughput skipped in -short")
	}
	cores := runtime.NumCPU()
	wire, chain, err := BuildBatchAtDepth(46, 1<<18) // depth 46 == 10^11 tx/s level
	if err != nil {
		t.Fatal(err)
	}
	// correctness of the real decode+verify path (always):
	if ok, _, np := NewVerifier().VerifyWire(DefaultHasher(), wire, chain); !ok || np != 1<<18 {
		t.Fatalf("real pipeline verify failed ok=%v np=%d", ok, np)
	}
	if cores < 32 {
		t.Skipf("bar (A>=1.5) is defined for a target server; this box has %d cores", cores)
	}
	v := MeasureStreamThroughput(DefaultHasher(), wire, chain, cores, 500*time.Millisecond)
	if v < Bar {
		t.Fatalf("complete pipeline BELOW bar at depth 46: %.3e verif/s (A=%.2f)", v, v/Bar)
	}
	t.Logf("depth-46 complete pipeline: %.3e verif/s A=%.2f PASS", v, v/Bar)
}
