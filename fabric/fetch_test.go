package fabric

import (
	"testing"

	"mfspv/commitment"
	"mfspv/teranode"
)

// SPV proof-acquisition: Bob has a new tx id, fetches its Merkle path + block from a
// node, and verifies inclusion against his most-work header chain. Unknown tx errors;
// a tampered path or off-chain header is rejected.
func TestFetchInclusion_SPVPull(t *testing.T) {
	n := teranode.NewMockNode(8)

	// Bob's new transaction, sealed in a block alongside others (real subtree/block trees).
	bobTx := commitment.DoubleSHA256([]byte("bob-new-tx"))
	txids := []commitment.Hash{bobTx}
	for i := 0; i < 40; i++ {
		txids = append(txids, commitment.DoubleSHA256([]byte{0x70, byte(i)}))
	}
	if _, err := n.SealBlock(txids, false); err != nil {
		t.Fatal(err)
	}

	// Bob has only the txid; he PULLS the Merkle path + block from the node.
	p, err := Fetch(bobTx, n)
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}
	if p.Leaf != bobTx {
		t.Fatal("fetched proof has wrong leaf")
	}
	if len(p.L1) == 0 {
		t.Fatal("fetched proof has empty Merkle path")
	}

	// Verify inclusion against Bob's most-work header chain (the node, here).
	if ok, _ := VerifyOne(DefaultHasher(), p, n); !ok {
		t.Fatal("fetched inclusion proof failed to verify")
	}

	// A tx the node does not know -> error (no proof to give).
	if _, err := Fetch(commitment.DoubleSHA256([]byte("unknown")), n); err == nil {
		t.Fatal("Fetch returned a proof for an unknown tx")
	}

	// Tampered Merkle path -> rejected.
	bad := p
	bad.L1 = append([]commitment.PathElem(nil), p.L1...)
	bad.L1[0].Sibling[0] ^= 0xff
	if ok, _ := VerifyOne(DefaultHasher(), bad, n); ok {
		t.Fatal("tampered fetched path accepted")
	}

	// Header not on the verifier's chain -> rejected (proof alone is not trust).
	empty := teranode.NewStaticHeaderChain(nil, 0)
	if ok, _ := VerifyOne(DefaultHasher(), p, empty); ok {
		t.Fatal("inclusion accepted with header off the most-work chain")
	}
}
