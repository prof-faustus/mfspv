package bundle

import (
	"bytes"
	"testing"

	"mfspv/accumulator"
	"mfspv/commitment"
	"mfspv/teranode"
)

// buildSealedOutput seals a block containing a transaction whose MTxID becomes the
// output TXID, and returns a full-header bundle revealing field index 1.
func buildSealedOutput(t *testing.T, n *teranode.MockNode, salt byte, extra int) (Bundle, OutputRef) {
	t.Helper()
	fields := commitment.TxFields{
		{Index: 0, Bytes: []byte{0x01, salt}},             // version
		{Index: 1, Bytes: []byte{0xaa, 0xbb, salt}},       // the revealed field (e.g. an output)
		{Index: 2, Bytes: []byte{0x10, 0x20, 0x30, salt}}, // scriptSig
		{Index: 3, Bytes: []byte{0xff}},                   // locktime
	}
	mtxid, _, err := commitment.BuildMTxID(fields)
	if err != nil {
		t.Fatal(err)
	}
	// Fill the block with some sibling txids so the trees are non-trivial.
	txids := []Hash{mtxid}
	for i := 0; i < extra; i++ {
		txids = append(txids, commitment.DoubleSHA256([]byte{0x99, salt, byte(i)}))
	}
	if _, err := n.SealBlock(txids, false); err != nil {
		t.Fatal(err)
	}
	out := OutputRef{TXID: mtxid, Vout: 0}
	b, err := Build(out, fields, 1, n)
	if err != nil {
		t.Fatal(err)
	}
	return b, out
}

// T3.1 End-to-end valid: a bundle from a sealed block passes Verify with a
// HeaderChain that contains the header.
func TestT3_1_EndToEndValid(t *testing.T) {
	n := teranode.NewMockNode(8)
	b, _ := buildSealedOutput(t, n, 0x01, 30)
	ok, depth, reason := Verify(b, n)
	if !ok {
		t.Fatalf("valid bundle rejected: reason=%q", reason)
	}
	if depth != len(b.SubtreePath)+len(b.BlockPath) {
		t.Fatalf("depth bookkeeping wrong: %d", depth)
	}
}

// T3.2 Fail-fast reasons: corrupt each level in turn => Verify returns the matching
// reason and stops at the first failure.
func TestT3_2_FailFastReasons(t *testing.T) {
	n := teranode.NewMockNode(8)

	// L0: corrupt the revealed field so it no longer reconstructs the TXID.
	b, _ := buildSealedOutput(t, n, 0x02, 10)
	b.Fields[0].Bytes = append([]byte(nil), b.Fields[0].Bytes...)
	b.Fields[0].Bytes[0] ^= 0xff
	if ok, _, reason := Verify(b, n); ok || reason != "L0" {
		t.Fatalf("L0 corruption: ok=%v reason=%q", ok, reason)
	}

	// L1: corrupt a subtree-path sibling.
	b2, _ := buildSealedOutput(t, n, 0x03, 10)
	if len(b2.SubtreePath) == 0 {
		t.Fatal("need a non-empty subtree path")
	}
	b2.SubtreePath[0].Sibling[0] ^= 0xff
	// A broken L1 yields a wrong block root => L3-bind is where it surfaces in the
	// composed fold (L1/L2 folds always "succeed" arithmetically; the bind check
	// catches the divergence). Assert it fails and does NOT pass.
	if ok, _, reason := Verify(b2, n); ok || reason != "L3-bind" {
		t.Fatalf("L1 corruption: ok=%v reason=%q", ok, reason)
	}

	// L2: corrupt a block-path sibling.
	b3, _ := buildSealedOutput(t, n, 0x04, 10)
	if len(b3.BlockPath) == 0 {
		t.Fatal("need a non-empty block path")
	}
	b3.BlockPath[0].Sibling[0] ^= 0xff
	if ok, _, reason := Verify(b3, n); ok || reason != "L3-bind" {
		t.Fatalf("L2 corruption: ok=%v reason=%q", ok, reason)
	}

	// L3-bind: corrupt the header's merkle root directly.
	b4, _ := buildSealedOutput(t, n, 0x05, 10)
	b4.Header[36] ^= 0xff
	if ok, _, reason := Verify(b4, n); ok || reason != "L3-bind" {
		t.Fatalf("L3 corruption: ok=%v reason=%q", ok, reason)
	}

	// L3/L4-chain: a structurally-valid bundle whose header is NOT on the chain
	// and has no anchor.
	b5, _ := buildSealedOutput(t, n, 0x06, 10)
	empty := teranode.NewMockNode(8) // a chain that does not contain this header
	if ok, _, reason := Verify(b5, empty); ok || reason != "L3/L4-chain" {
		t.Fatalf("off-chain header: ok=%v reason=%q", ok, reason)
	}
}

// T3.3 Frozen core (anti-Utreexo): after a reorg + Reanchor, MTxIDPath/SubtreePath/
// BlockPath/Header are byte-identical; only Anchor/chain selection may change. (I-B1)
func TestT3_3_FrozenCore(t *testing.T) {
	n := teranode.NewMockNode(8)
	b, _ := buildSealedOutput(t, n, 0x07, 25)

	// snapshot the core
	mt := clonePath(b.MTxIDPath)
	st := clonePath(b.SubtreePath)
	bp := clonePath(b.BlockPath)
	hdr := b.Header

	// Reorg elsewhere does not orphan this block; Reanchor must leave the core intact.
	if err := Reanchor(&b, n); err != nil {
		t.Fatal(err)
	}
	if !pathEqual(mt, b.MTxIDPath) || !pathEqual(st, b.SubtreePath) || !pathEqual(bp, b.BlockPath) || hdr != b.Header {
		t.Fatal("frozen core changed across Reanchor on a non-orphaned block")
	}
	if ok, _, reason := Verify(b, n); !ok {
		t.Fatalf("bundle invalid after benign reanchor: %q", reason)
	}
}

// T3.4 Reanchor: NeedsReanchor true iff header off best chain; Reanchor restores
// Verify==true on the new best chain. (Also A5.)
func TestT3_4_Reanchor(t *testing.T) {
	n := teranode.NewMockNode(8)
	b, out := buildSealedOutput(t, n, 0x08, 12)
	blockHash, _ := n.LocateTx(out.TXID)

	if NeedsReanchor(b, n) {
		t.Fatal("freshly built bundle should not need reanchor")
	}

	// Orphan the block: header leaves the best chain.
	n.Orphan(blockHash)
	if !NeedsReanchor(b, n) {
		t.Fatal("orphaned block should need reanchor")
	}
	if ok, _, reason := Verify(b, n); ok || reason != "L3/L4-chain" {
		t.Fatalf("orphaned bundle should fail chain check: ok=%v reason=%q", ok, reason)
	}

	// Re-include on the best chain (reorg settles), then Reanchor.
	n.Restore(blockHash)
	if err := Reanchor(&b, n); err != nil {
		t.Fatal(err)
	}
	if NeedsReanchor(b, n) {
		t.Fatal("reanchored bundle still flagged")
	}
	if ok, _, reason := Verify(b, n); !ok {
		t.Fatalf("reanchored bundle invalid: %q", reason)
	}
}

// T3.5 Inclusion != double-spend (negative): a bundle for an output that has since
// been spent STILL passes Verify (inclusion holds). Verify alone does not imply
// spendable. (§6.3 / I-BB1)
func TestT3_5_InclusionNotDoubleSpend(t *testing.T) {
	n := teranode.NewMockNode(8)
	b, out := buildSealedOutput(t, n, 0x09, 14)
	// Mark the output spent in the live UTXO oracle.
	n.MarkSpent(teranode.Outpoint{TXID: out.TXID, Vout: out.Vout})
	// Inclusion proof must STILL verify — inclusion is a historical fact.
	if ok, _, reason := Verify(b, n); !ok {
		t.Fatalf("inclusion proof must hold regardless of spend status: %q", reason)
	}
	// But the live oracle reports it spent — double-spend is a separate axis.
	if unspent, _ := n.IsUnspent(teranode.Outpoint{TXID: out.TXID, Vout: out.Vout}); unspent {
		t.Fatal("oracle should report the output spent")
	}
}

// Serialize/Deserialize round-trip, including an L4 anchor.
func TestSerializeRoundTrip(t *testing.T) {
	n := teranode.NewMockNode(4)
	b, _ := buildSealedOutput(t, n, 0x0a, 9)

	// no-anchor round trip
	data, err := Serialize(b)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Deserialize(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bundleEqual(b, got) {
		t.Fatal("no-anchor round trip mismatch")
	}

	// with-anchor round trip: attach a synthetic-but-valid anchor.
	b.Anchor = &AnchorProof{
		AccRoot:                 commitment.DoubleSHA256([]byte("acc")),
		AccPath:                 []PathElem{{Sibling: commitment.DoubleSHA256([]byte("s")), Right: true}},
		GenTxFields:             commitment.TxFields{{Index: 1, Bytes: []byte{1, 2, 3}}},
		GenL0:                   []PathElem{{Sibling: commitment.DoubleSHA256([]byte("g0")), Right: false}},
		GenL1:                   nil,
		GenL2:                   []PathElem{{Sibling: commitment.DoubleSHA256([]byte("g2")), Right: true}},
		CarryingBlockMerkleRoot: commitment.DoubleSHA256([]byte("cb")),
		CarryingHeader:          [80]byte{1, 2, 3, 250, 251, 252},
	}
	data2, _ := Serialize(b)
	got2, err := Deserialize(data2)
	if err != nil {
		t.Fatal(err)
	}
	if !bundleEqual(b, got2) {
		t.Fatal("with-anchor round trip mismatch")
	}
}

// Deserialize must reject truncated input (fail-fast against malformed bundles, A3).
func TestDeserializeTruncated(t *testing.T) {
	n := teranode.NewMockNode(4)
	b, _ := buildSealedOutput(t, n, 0x0b, 5)
	data, _ := Serialize(b)
	if _, err := Deserialize(data[:len(data)-3]); err == nil {
		t.Fatal("truncated bundle accepted")
	}
	if _, err := Deserialize(append(data, 0x00)); err == nil {
		t.Fatal("trailing-garbage bundle accepted")
	}
}

// End-to-end L4: a header-pruned verifier (does not contain the header) accepts via
// a sound anchor produced by the node.
func TestL4PrunedVerifier(t *testing.T) {
	n := teranode.NewMockNode(4)
	// target block with our output
	b, out := buildSealedOutput(t, n, 0x0c, 6)
	targetHash, _ := n.LocateTx(out.TXID)
	// seal more blocks, then a carrying block committing the accumulator
	for k := 0; k < 3; k++ {
		_, _ = n.SealBlock([]Hash{commitment.DoubleSHA256([]byte{0x77, byte(k)})}, false)
	}
	carrier, err := n.SealBlock([]Hash{commitment.DoubleSHA256([]byte("c0"))}, true)
	if err != nil {
		t.Fatal(err)
	}
	accRoot, genFields, l0, l1, l2, err := n.GenTxAccumulator(carrier)
	if err != nil {
		t.Fatal(err)
	}
	carryRoot, _ := n.BlockRoot(carrier)
	carryHdr, _ := n.HeaderFor(carrier)
	accPath, _, err := n.ProveHeaderInAccumulator(targetHash, carrier)
	if err != nil {
		t.Fatal(err)
	}
	b.Anchor = &AnchorProof{
		AccRoot:                 accRoot,
		AccPath:                 accPath,
		GenTxFields:             genFields,
		GenL0:                   l0,
		GenL1:                   l1,
		GenL2:                   l2,
		CarryingBlockMerkleRoot: carryRoot,
		CarryingHeader:          carryHdr,
	}
	// A header-PRUNED verifier holds only the recent carrying header (NOT the old
	// target header) yet still accepts via the L4 anchor.
	pruned := teranode.NewStaticHeaderChain([][80]byte{carryHdr}, 100)
	targetHdr, _ := n.HeaderFor(targetHash)
	if pruned.Contains(targetHdr) {
		t.Fatal("pruned verifier should NOT hold the target header")
	}
	if ok, _, reason := Verify(b, pruned); !ok {
		t.Fatalf("L4 pruned verification failed: %q", reason)
	}
	// Sanity: tampering the anchor's accRoot breaks it.
	bad := b
	badAnchor := *b.Anchor
	badAnchor.AccRoot[0] ^= 0xff
	bad.Anchor = &badAnchor
	if ok, _, _ := Verify(bad, pruned); ok {
		t.Fatal("tampered anchor accepted")
	}
	// RT-1: an anchor whose carrying header is NOT on the verifier's chain must be
	// rejected even if its internal algebra is self-consistent (PoW-bypass attempt).
	noCarrier := teranode.NewStaticHeaderChain(nil, 100)
	if ok, _, _ := Verify(b, noCarrier); ok {
		t.Fatal("RT-1: anchor accepted without a trusted carrying header (PoW bypass)")
	}
}

// --- helpers ---

func clonePath(p []PathElem) []PathElem {
	out := make([]PathElem, len(p))
	copy(out, p)
	return out
}

func pathEqual(a, b []PathElem) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Right != b[i].Right || a[i].Sibling != b[i].Sibling {
			return false
		}
	}
	return true
}

func bundleEqual(a, b Bundle) bool {
	if a.OutputRef != b.OutputRef || a.Header != b.Header {
		return false
	}
	if len(a.Fields) != len(b.Fields) {
		return false
	}
	for i := range a.Fields {
		if a.Fields[i].Index != b.Fields[i].Index || !bytes.Equal(a.Fields[i].Bytes, b.Fields[i].Bytes) {
			return false
		}
	}
	if !pathEqual(a.MTxIDPath, b.MTxIDPath) || !pathEqual(a.SubtreePath, b.SubtreePath) || !pathEqual(a.BlockPath, b.BlockPath) {
		return false
	}
	if (a.Anchor == nil) != (b.Anchor == nil) {
		return false
	}
	if a.Anchor != nil {
		if a.Anchor.AccRoot != b.Anchor.AccRoot || a.Anchor.CarryingBlockMerkleRoot != b.Anchor.CarryingBlockMerkleRoot {
			return false
		}
		if a.Anchor.CarryingHeader != b.Anchor.CarryingHeader {
			return false
		}
		if !pathEqual(a.Anchor.AccPath, b.Anchor.AccPath) {
			return false
		}
	}
	return true
}

var _ = accumulator.NewMMR
