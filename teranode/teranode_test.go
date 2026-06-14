package teranode

import (
	"testing"

	"mfspv/accumulator"
	"mfspv/commitment"
)

func tx(i int) Hash { return commitment.DoubleSHA256([]byte{0x54, byte(i), byte(i >> 8)}) }

// T6.1 Read-only: the adapter exposes no mutation of header/block format.
// Enforced at compile time by the interface set (no setter methods) plus these
// assertions. (I-TA1)
func TestT6_1_ReadOnly(t *testing.T) {
	var _ ProofSource = (*MockNode)(nil)
	var _ HeaderChain = (*MockNode)(nil)
	var _ UTXOClient = (*MockNode)(nil)
	// The interfaces contain only getters; this test documents the property.
}

// T6.2 Subtree fidelity: SubtreePathFor matches the actual subtree membership and
// folds to the subtree root, with path <= 20 for a <=2^20 subtree. (I-TA2)
func TestT6_2_SubtreeFidelity(t *testing.T) {
	n := NewMockNode(8) // 8 txids per subtree
	var txids []Hash
	for i := 0; i < 50; i++ {
		txids = append(txids, tx(i))
	}
	bh, err := n.SealBlock(txids, false)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		path, subRoot, err := n.SubtreePathFor(txids[i])
		if err != nil {
			t.Fatal(err)
		}
		if len(path) > 20 {
			t.Fatalf("subtree path len %d > 20", len(path))
		}
		if !commitment.VerifySubtreePath(txids[i], path, subRoot) {
			t.Fatalf("tx %d subtree path does not fold to subtree root", i)
		}
		// and the subtree root folds to the block root
		bp, blockRoot, err := n.BlockPathFor(subRoot, bh)
		if err != nil {
			t.Fatal(err)
		}
		if !commitment.VerifyBlockPath(subRoot, bp, blockRoot) {
			t.Fatalf("tx %d block path does not fold to block root", i)
		}
		hdr, _ := n.HeaderFor(bh)
		var hroot Hash
		copy(hroot[:], hdr[36:68])
		if hroot != blockRoot {
			t.Fatal("header merkle root != computed block root")
		}
	}
}

// The mock produces a sound L4 anchor: the gen-tx-committed accRoot binds to the
// carrying block's PoW-sealed root, and a prior header is provable in that accRoot.
func TestMockL4AnchorSound(t *testing.T) {
	n := NewMockNode(4)
	// seal a few ordinary blocks
	var targetHash Hash
	for b := 0; b < 5; b++ {
		var txids []Hash
		for i := 0; i < 6; i++ {
			txids = append(txids, tx(b*100+i))
		}
		h, err := n.SealBlock(txids, false)
		if err != nil {
			t.Fatal(err)
		}
		if b == 2 {
			targetHash = h
		}
	}
	// seal a carrying block committing the accumulator over all prior headers
	var ctx []Hash
	for i := 0; i < 6; i++ {
		ctx = append(ctx, tx(9000+i))
	}
	carrier, err := n.SealBlock(ctx, true)
	if err != nil {
		t.Fatal(err)
	}

	accRoot, genFields, l0, l1, l2, err := n.GenTxAccumulator(carrier)
	if err != nil {
		t.Fatal(err)
	}
	carryRoot, _ := n.BlockRoot(carrier)
	// VerifyAnchor binds accRoot into the carrying block's PoW-sealed root.
	if !accumulator.VerifyAnchor(accRoot, genFields, l0, l1, l2, carryRoot) {
		t.Fatal("L4 anchor failed to bind accRoot to carrying block root")
	}
	// The target header is provable within that accRoot.
	path, root, err := n.ProveHeaderInAccumulator(targetHash, carrier)
	if err != nil {
		t.Fatal(err)
	}
	if root != accRoot {
		t.Fatal("MMR proof root != committed accRoot")
	}
	targetHdr, _ := n.HeaderFor(targetHash)
	if !accumulator.VerifyBlockInChain(targetHdr, path, accRoot) {
		t.Fatal("target header not provable in committed accumulator")
	}
}

// IsUnspent / MarkSpent behave as the double-spend oracle.
func TestUTXOOracle(t *testing.T) {
	n := NewMockNode(4)
	txids := []Hash{tx(1), tx(2)}
	_, err := n.SealBlock(txids, false)
	if err != nil {
		t.Fatal(err)
	}
	op := Outpoint{TXID: tx(1), Vout: 0}
	if ok, _ := n.IsUnspent(op); !ok {
		t.Fatal("fresh outpoint reported spent")
	}
	n.MarkSpent(op)
	if ok, _ := n.IsUnspent(op); ok {
		t.Fatal("spent outpoint reported unspent")
	}
}
