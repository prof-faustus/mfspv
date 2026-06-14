// Package adversarial consolidates the red-team tests of 04_TEST_PLAN.md (A1–A5).
// Every test here asserts a REJECTION: a forgery, an off-chain claim, a flood, or
// an orphaned anchor must NOT be accepted. "SECURITY is 100% perfect or fail."
//
// BSV only.
package adversarial

import (
	"testing"
	"time"

	"mfspv/accumulator"
	"mfspv/bundle"
	"mfspv/commitment"
	"mfspv/dsalert"
	"mfspv/teranode"
)

func mkOutput(t *testing.T, n *teranode.MockNode, salt byte) (bundle.Bundle, bundle.OutputRef) {
	t.Helper()
	fields := commitment.TxFields{
		{Index: 0, Bytes: []byte{0x01, salt}},
		{Index: 1, Bytes: []byte{0xa0, salt}},
		{Index: 2, Bytes: []byte{0xb0, salt}},
	}
	mtxid, _, err := commitment.BuildMTxID(fields)
	if err != nil {
		t.Fatal(err)
	}
	txids := []commitment.Hash{mtxid}
	for i := 0; i < 15; i++ {
		txids = append(txids, commitment.DoubleSHA256([]byte{0x55, salt, byte(i)}))
	}
	if _, err := n.SealBlock(txids, false); err != nil {
		t.Fatal(err)
	}
	out := bundle.OutputRef{TXID: mtxid, Vout: 0}
	b, err := bundle.Build(out, fields, 1, n)
	if err != nil {
		t.Fatal(err)
	}
	return b, out
}

// A1: a collision-free forgery of any path is rejected. Flipping any sibling, the
// leaf, or the header's committed root must break verification.
func TestA1_ForgeryRejected(t *testing.T) {
	n := teranode.NewMockNode(8)
	b, _ := mkOutput(t, n, 0x01)
	if ok, _, _ := bundle.Verify(b, n); !ok {
		t.Fatal("baseline valid bundle was rejected")
	}
	mutate := func(f func(*bundle.Bundle)) {
		c := b
		c.SubtreePath = append([]commitment.PathElem(nil), b.SubtreePath...)
		c.BlockPath = append([]commitment.PathElem(nil), b.BlockPath...)
		c.MTxIDPath = append([]commitment.PathElem(nil), b.MTxIDPath...)
		c.Fields = append(commitment.TxFields(nil), b.Fields...)
		f(&c)
		if ok, _, _ := bundle.Verify(c, n); ok {
			t.Fatal("forged bundle accepted")
		}
	}
	if len(b.SubtreePath) > 0 {
		mutate(func(c *bundle.Bundle) { c.SubtreePath[0].Sibling[0] ^= 0xff })
	}
	if len(b.BlockPath) > 0 {
		mutate(func(c *bundle.Bundle) { c.BlockPath[0].Sibling[0] ^= 0xff })
	}
	if len(b.MTxIDPath) > 0 {
		mutate(func(c *bundle.Bundle) { c.MTxIDPath[0].Sibling[0] ^= 0xff })
	}
	mutate(func(c *bundle.Bundle) { c.Header[36] ^= 0xff })     // tamper committed root
	mutate(func(c *bundle.Bundle) { c.OutputRef.TXID[0] ^= 1 }) // claim a different txid
}

// A2: an alternative header chain without majority work does not anchor. A header
// that is not on Bob's most-work chain and has no valid L4 anchor is rejected.
func TestA2_AlternativeChainRejected(t *testing.T) {
	honest := teranode.NewMockNode(8)
	b, _ := mkOutput(t, honest, 0x02)

	// A different node (a would-be attacker chain) does not contain this header.
	attacker := teranode.NewMockNode(8)
	if ok, _, reason := bundle.Verify(b, attacker); ok || reason != "L3/L4-chain" {
		t.Fatalf("off-chain header accepted: ok=%v reason=%q", ok, reason)
	}

	// A fabricated anchor (accRoot not committed in any PoW-sealed gen tx) must not
	// rescue it: VerifyAnchor fails, so the L4 branch rejects.
	b.Anchor = &bundle.AnchorProof{
		AccRoot:                 commitment.DoubleSHA256([]byte("fake-acc")),
		AccPath:                 nil,
		GenTxFields:             commitment.TxFields{{Index: 1, Bytes: []byte("not-the-accroot")}},
		CarryingBlockMerkleRoot: commitment.DoubleSHA256([]byte("fake-block")),
	}
	if ok, _, _ := bundle.Verify(b, attacker); ok {
		t.Fatal("fabricated L4 anchor accepted")
	}
}

// A3: spam of malformed bundles is rejected at the first failing hash, O(depth),
// with no network call and no panic.
func TestA3_SpamRejectedFailFast(t *testing.T) {
	n := teranode.NewMockNode(8)
	good, _ := mkOutput(t, n, 0x03)
	for i := 0; i < 2000; i++ {
		junk := good
		junk.Fields = append(commitment.TxFields(nil), good.Fields...)
		// 0xFF-prefixed 3-byte garbage can never equal the 2-byte real field.
		junk.Fields[0].Bytes = []byte{0xFF, byte(i), byte(i >> 8)}
		ok, _, reason := bundle.Verify(junk, n)
		if ok {
			t.Fatal("malformed bundle accepted")
		}
		if reason != "L0" {
			t.Fatalf("expected fail-fast at L0, got %q", reason)
		}
	}
	// truncated serialisations are rejected too
	data, _ := bundle.Serialize(good)
	if _, err := bundle.Deserialize(data[:len(data)/2]); err == nil {
		t.Fatal("truncated bundle accepted")
	}
}

// A4: alert flooding without evidence is dropped.
func TestA4_AlertFloodDropped(t *testing.T) {
	bus := dsalert.NewBus()
	out := dsalert.Outpoint{TXID: commitment.DoubleSHA256([]byte("op")), Vout: 0}
	for i := 0; i < 500; i++ {
		// "conflict" with identical txids is not a conflict; also unattested.
		junk := dsalert.Alert{
			Outpoint:    out,
			Evidence:    dsalert.ConflictEvidence{SpendA: commitment.DoubleSHA256([]byte("z")), SpendB: commitment.DoubleSHA256([]byte("z"))},
			AttesterPoW: []byte{byte(i)},
		}
		if bus.Publish(junk) {
			t.Fatal("evidence-free alert accepted")
		}
	}
	if !bus.QuietFor([]dsalert.Outpoint{out}, time.Hour) {
		t.Fatal("flood disturbed the quiet window")
	}
}

// A5: a bundle anchored to an orphaned block has NeedsReanchor true and Verify
// false until reanchored to the winning chain.
func TestA5_OrphanedBlockReanchor(t *testing.T) {
	n := teranode.NewMockNode(8)
	b, out := mkOutput(t, n, 0x05)
	blockHash, _ := n.LocateTx(out.TXID)

	if ok, _, _ := bundle.Verify(b, n); !ok {
		t.Fatal("baseline rejected")
	}
	n.Orphan(blockHash)
	if !bundle.NeedsReanchor(b, n) {
		t.Fatal("orphaned bundle not flagged for reanchor")
	}
	if ok, _, _ := bundle.Verify(b, n); ok {
		t.Fatal("orphaned bundle still verifies")
	}
	n.Restore(blockHash)
	if err := bundle.Reanchor(&b, n); err != nil {
		t.Fatal(err)
	}
	if ok, _, _ := bundle.Verify(b, n); !ok {
		t.Fatal("reanchored bundle does not verify on the winning chain")
	}
}

// A1 (accumulator): a forged header is not provable in an honest MMR.
func TestA1_AccumulatorForgery(t *testing.T) {
	m := accumulator.NewMMR()
	var hdrs [][80]byte
	for i := 0; i < 9; i++ {
		var h [80]byte
		h[0] = byte(i)
		hdrs = append(hdrs, h)
		m.Append(h)
	}
	root := m.Root()
	path, _, _ := m.ProveBlock(4)
	var forged [80]byte
	forged[0] = 0xff
	if accumulator.VerifyBlockInChain(forged, path, root) {
		t.Fatal("forged header accepted by accumulator")
	}
}
