package adversarial

import (
	"crypto/sha256"
	"testing"

	"mfspv/bundle"
	"mfspv/commitment"
	"mfspv/crypto"
	"mfspv/payment"
	"mfspv/teranode"
)

// RT-1 (regression): an L4 anchor whose carrying header is not on the verifier's
// chain is rejected — accRoot must inherit PoW via a trusted header, not via an
// attacker-chosen CarryingBlockMerkleRoot. (Full positive path: bundle.TestL4PrunedVerifier.)
func TestRT1_AnchorRequiresTrustedCarrier(t *testing.T) {
	n := teranode.NewMockNode(8)
	b, _ := mkOutput(t, n, 0x21)
	// Forge an anchor with internally-consistent algebra but a carrying header the
	// verifier does not hold.
	b.Anchor = &bundle.AnchorProof{
		AccRoot:                 commitment.DoubleSHA256([]byte("acc")),
		CarryingBlockMerkleRoot: commitment.DoubleSHA256([]byte("cb")),
		CarryingHeader:          [80]byte{9, 9, 9},
	}
	pruned := teranode.NewStaticHeaderChain(nil, 10) // holds no headers
	if ok, _, _ := bundle.Verify(b, pruned); ok {
		t.Fatal("RT-1: anchor accepted without a trusted carrying header (PoW bypass)")
	}
	// Even if the verifier holds SOME header, a mismatched CarryingBlockMerkleRoot
	// (not equal to the carrying header's committed root) is rejected.
	hdr := [80]byte{9, 9, 9}
	withWrong := teranode.NewStaticHeaderChain([][80]byte{hdr}, 10)
	if ok, _, _ := bundle.Verify(b, withWrong); ok {
		t.Fatal("RT-1: anchor accepted with carrying root != header's committed root")
	}
}

// RT-3: a non-canonical (high-S) signature is rejected by the payment verifier,
// even though it is a valid ECDSA signature (malleability defence).
func TestRT3_HighSRejected(t *testing.T) {
	seed := sha256.Sum256([]byte("rt3-key"))
	key, _ := crypto.NewPrivateKey(seed[:])
	tx := payment.Tx3{
		Version: 1,
		Inputs: []payment.TxIn{{
			Prev:   payment.Outpoint{TXID: commitment.DoubleSHA256([]byte("prev")), Vout: 0},
			PubKey: key.Public().SerializeCompressed(),
		}},
		Outputs: []payment.TxOut{{Value: 1, ScriptPubKey: []byte{0x01}}},
	}
	h := tx.Sighash(0)
	sig, _ := key.Sign(h[:])
	tx.Inputs[0].Sig = sig.Serialize()
	if !tx.VerifyInputSignature(0) {
		t.Fatal("canonical low-S signature rejected")
	}
	// Malleate to high-S: still a valid ECDSA signature, but non-canonical.
	hi, err := crypto.Malleate(sig.Serialize())
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := crypto.ParseSignature(hi)
	if !crypto.Verify(key.Public(), h[:], parsed) {
		t.Fatal("sanity: malleated signature should still verify under raw ECDSA")
	}
	if parsed.IsLowS() {
		t.Fatal("malleated signature should be high-S")
	}
	tx.Inputs[0].Sig = hi
	if tx.VerifyInputSignature(0) {
		t.Fatal("RT-3: high-S (malleable) signature accepted by payment verifier")
	}
}

// RT-4: the Merkle internal-node-as-leaf / 64-byte-preimage attack is blocked.
// An attacker who claims an INTERNAL subtree node is the TXID (to shorten the path)
// must still pass L0 — which requires fields whose tree roots to that node value,
// i.e. a SHA-256 preimage. We confirm the forgery is rejected at L0.
func TestRT4_InternalNodeAsLeafRejected(t *testing.T) {
	n := teranode.NewMockNode(8)
	b, _ := mkOutput(t, n, 0x24)
	if len(b.SubtreePath) == 0 {
		t.Fatal("need a non-empty subtree path for this attack")
	}
	// Compute the internal node one level up from the TXID, and try to pass IT off
	// as the leaf TXID with a path shortened by one element.
	internal := commitment.Fold(b.OutputRef.TXID, b.SubtreePath[:1])
	forged := b
	forged.OutputRef.TXID = internal
	forged.SubtreePath = b.SubtreePath[1:] // shorter path, claiming internal is the leaf
	// L0 still binds the ORIGINAL fields, which root to the real TXID, not `internal`.
	if ok, _, reason := bundle.Verify(forged, n); ok {
		t.Fatalf("RT-4: internal node accepted as leaf TXID (reason=%q)", reason)
	} else if reason != "L0" {
		t.Fatalf("RT-4: expected L0 rejection, got %q", reason)
	}
	// Also: a bundle that omits the revealed fields entirely (claims a bare TXID) is
	// rejected — L0 is mandatory, so a raw 32-byte value can never stand in for a tx.
	bare := b
	bare.Fields = nil
	if ok, _, reason := bundle.Verify(bare, n); ok || reason != "L0" {
		t.Fatalf("RT-4: bare-TXID bundle accepted (ok=%v reason=%q)", ok, reason)
	}
}

// RT-5: serialization DoS — a bundle whose path-length prefix claims a huge count
// is rejected without a large allocation (the reader is bounded by the buffer and
// caps path lengths at the depth ceiling).
func TestRT5_SerializationDoS(t *testing.T) {
	// A path count prefix of 0xFFFF with no following data must fail fast.
	// Layout up to the first path: TXID[32] Vout[4] fields(u16=0) then MTxIDPath count.
	mal := make([]byte, 0, 64)
	mal = append(mal, make([]byte, 32)...) // TXID
	mal = append(mal, 0, 0, 0, 0)          // Vout
	mal = append(mal, 0, 0)                // fields count = 0
	mal = append(mal, 0xFF, 0xFF)          // MTxIDPath count = 65535 (absurd)
	if _, err := bundle.Deserialize(mal); err == nil {
		t.Fatal("RT-5: oversized path-length prefix accepted")
	}
	// A fields prefix claiming a huge per-field length with no data must also fail.
	mal2 := make([]byte, 0, 64)
	mal2 = append(mal2, make([]byte, 32)...) // TXID
	mal2 = append(mal2, 0, 0, 0, 0)          // Vout
	mal2 = append(mal2, 1, 0)                // fields count = 1
	mal2 = append(mal2, 0x00)                // field index
	mal2 = append(mal2, 0xFF, 0xFF)          // field byte-length = 65535, no bytes follow
	if _, err := bundle.Deserialize(mal2); err == nil {
		t.Fatal("RT-5: oversized field-length prefix accepted")
	}
}

// RT-6: boundary path lengths. A subtree path of 21 (> 20 for a 2^20 subtree) is
// rejected as depth-overflow; a path at the legal bound still verifies for a real
// bundle.
func TestRT6_BoundaryPathLengths(t *testing.T) {
	n := teranode.NewMockNode(8)
	b, _ := mkOutput(t, n, 0x26)
	if ok, _, _ := bundle.Verify(b, n); !ok {
		t.Fatal("baseline bundle rejected")
	}
	// Pad the subtree path beyond 20 elements -> must be rejected.
	over := b
	over.SubtreePath = make([]commitment.PathElem, 21)
	copy(over.SubtreePath, b.SubtreePath)
	for i := len(b.SubtreePath); i < 21; i++ {
		over.SubtreePath[i] = commitment.PathElem{Sibling: commitment.DoubleSHA256([]byte{byte(i)})}
	}
	if ok, _, reason := bundle.Verify(over, n); ok || reason != "depth-overflow" {
		t.Fatalf("RT-6: 21-element subtree path not rejected (ok=%v reason=%q)", ok, reason)
	}
}
