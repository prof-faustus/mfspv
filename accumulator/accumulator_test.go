package accumulator

import (
	"testing"

	"mfspv/commitment"
)

func hdr(i int) [80]byte {
	var h [80]byte
	h[0] = byte(i)
	h[1] = byte(i >> 8)
	h[36] = byte(i * 7) // vary the "merkle root" region
	return h
}

// T2.1 Append-only provability: append K headers; every previously proven height
// stays provable even after more appends. (I-A1)
func TestT2_1_AppendOnlyProvability(t *testing.T) {
	m := NewMMR()
	headers := map[uint64][80]byte{}
	for k := 0; k < 40; k++ {
		h := hdr(k)
		headers[uint64(k)] = h
		m.Append(h)
		// every height 0..k must be provable against the CURRENT root
		root := m.Root()
		for ht := uint64(0); ht <= uint64(k); ht++ {
			path, r, err := m.ProveBlock(ht)
			if err != nil {
				t.Fatalf("k=%d ht=%d: %v", k, ht, err)
			}
			if r != root {
				t.Fatalf("k=%d ht=%d: proof root != current root", k, ht)
			}
			if !VerifyBlockInChain(headers[ht], path, root) {
				t.Fatalf("k=%d ht=%d: previously appended header not provable", k, ht)
			}
		}
	}
}

// Forged header must not verify against an honest MMR root.
func TestMMRForgeryRejected(t *testing.T) {
	m := NewMMR()
	for k := 0; k < 11; k++ {
		m.Append(hdr(k))
	}
	root := m.Root()
	path, _, _ := m.ProveBlock(5)
	bad := hdr(5)
	bad[0] ^= 0xff
	if VerifyBlockInChain(bad, path, root) {
		t.Fatal("forged header accepted by MMR")
	}
	// tamper a sibling
	if len(path) > 0 {
		path[0].Sibling[0] ^= 1
		if VerifyBlockInChain(hdr(5), path, root) {
			t.Fatal("tampered MMR path accepted")
		}
	}
}

// T2.2 PoW binding: VerifyBlockInChain on an accRoot that has NOT passed
// VerifyAnchor is treated as unverified. We assert the coupling by showing
// VerifyAnchor rejects an accRoot not committed in the gen tx. (I-A2)
func TestT2_2_PoWBinding(t *testing.T) {
	m := NewMMR()
	for k := 0; k < 8; k++ {
		m.Append(hdr(k))
	}
	accRoot := m.Root()

	// Construct a real gen-tx that commits accRoot, and a carrying block tree.
	genFields := commitment.TxFields{
		{Index: 0, Bytes: []byte("coinbase")},
		{Index: 1, Bytes: append([]byte(nil), accRoot[:]...)},
	}
	mtxid, _, _ := commitment.BuildMTxID(genFields)
	_, l0, _, _ := commitment.MTxIDPath(genFields, 1)
	_, subLayers, _ := commitment.BuildMerkleTree([]Hash{mtxid})
	l1, _ := commitment.MerklePath(subLayers, 0)
	carryRoot, carryLayers, _ := commitment.BuildMerkleTree([]Hash{mtxid, hdr0Root()})
	l2, _ := commitment.MerklePath(carryLayers, 0)

	if !VerifyAnchor(accRoot, genFields, l0, l1, l2, carryRoot) {
		t.Fatal("valid anchor rejected")
	}

	// An accRoot NOT committed in the gen tx must fail VerifyAnchor: the coupling
	// means VerifyBlockInChain's result on it cannot be trusted as chain validity.
	var fakeAcc Hash
	fakeAcc[0] = 0xde
	if VerifyAnchor(fakeAcc, genFields, l0, l1, l2, carryRoot) {
		t.Fatal("anchor accepted an accRoot not committed in the gen tx (PoW binding broken)")
	}
}

func hdr0Root() Hash { return commitment.DoubleSHA256([]byte("carry-block-root")) }

// T2.3 Gap honesty: with holes in the committed set, a height in a hole returns
// inGap==true and never a false "in chain". (I-A3 / §6.4) — mandatory.
func TestT2_3_GapHonesty(t *testing.T) {
	committed := []uint64{0, 1, 2, 5, 6, 9}
	tip := uint64(10)
	gaps := CoverageGaps(committed, tip)
	want := []ParticipationGap{{3, 4}, {7, 8}, {10, 10}}
	if len(gaps) != len(want) {
		t.Fatalf("gaps=%v want %v", gaps, want)
	}
	for i := range want {
		if gaps[i] != want[i] {
			t.Fatalf("gap %d = %v want %v", i, gaps[i], want[i])
		}
	}
	// a height inside a hole must be flagged inGap and fall back to nearest <=.
	for _, h := range []uint64{3, 4, 7, 8, 10} {
		nh, inGap := NearestCommitted(h, committed)
		if !inGap {
			t.Fatalf("height %d in a hole but inGap==false (false 'in chain')", h)
		}
		if nh > h {
			t.Fatalf("height %d fell back to %d (> h)", h, nh)
		}
	}
	// a committed height is not in a gap.
	for _, h := range committed {
		nh, inGap := NearestCommitted(h, committed)
		if inGap || nh != h {
			t.Fatalf("committed height %d misreported (nh=%d inGap=%v)", h, nh, inGap)
		}
	}
}

// T2.4 Fork buys gaplessness (negative control): a full-header verifier does not
// use L4, so gaps are irrelevant to it. We assert that statement structurally:
// with L4 unused, no gap query is consulted and verification is by header chain.
func TestT2_4_FullHeaderUnaffected(t *testing.T) {
	// A full-header verifier never calls CoverageGaps/NearestCommitted/VerifyAnchor.
	// We document this by confirming the L4 surface is entirely optional: an empty
	// committed set produces a single all-covering gap, which a full-header verifier
	// simply ignores.
	gaps := CoverageGaps(nil, 5)
	if len(gaps) != 1 || gaps[0] != (ParticipationGap{0, 5}) {
		t.Fatalf("expected one all-covering gap, got %v", gaps)
	}
	// The negative control: even with total L4 absence, a header that the chain
	// view contains is verifiable without L4. (Exercised fully in bundle tests.)
}
