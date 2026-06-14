package dsalert

import (
	"crypto/sha256"
	"testing"
	"time"

	"mfspv/commitment"
	"mfspv/crypto"
)

func op(i int) Outpoint {
	return Outpoint{TXID: commitment.DoubleSHA256([]byte{0x4f, byte(i)}), Vout: uint32(i)}
}
func txid(s string) Hash { return commitment.DoubleSHA256([]byte(s)) }

func ownerKey(seed string) *crypto.PrivateKey {
	h := sha256.Sum256([]byte(seed))
	k, _ := crypto.NewPrivateKey(h[:])
	return k
}

// genuineAlert builds a fully valid, owner-signed, attested double-spend alert.
func genuineAlert(t *testing.T, out Outpoint, key *crypto.PrivateKey, a, b string) Alert {
	t.Helper()
	ev, err := BuildEvidence(key, out, txid(a), txid(b))
	if err != nil {
		t.Fatal(err)
	}
	return Attest(out, ev)
}

// T5.1 Evidence-gated: an alert with no verifiable conflict is dropped. (I-DS1 / RT-2)
func TestT5_1_EvidenceGated(t *testing.T) {
	key := ownerKey("owner-1")

	// same-tx "conflict" is not a conflict
	ev, _ := BuildEvidence(key, op(1), txid("x"), txid("x"))
	if VerifyAlert(Attest(op(1), ev)) {
		t.Fatal("same-tx evidence accepted")
	}

	// empty evidence (no owner key, no sigs)
	if VerifyAlert(Attest(op(1), ConflictEvidence{SpendA: txid("a"), SpendB: txid("b")})) {
		t.Fatal("evidence without owner signatures accepted")
	}

	// FORGED: an attacker without the owner key supplies two distinct hashes and
	// garbage signatures. Must be dropped (cannot fabricate a double-spend). (RT-2)
	forged := Attest(op(1), ConflictEvidence{
		OwnerPubKey: key.Public().SerializeCompressed(),
		SpendA:      txid("a"), SigA: make([]byte, 64),
		SpendB: txid("b"), SigB: make([]byte, 64),
	})
	if VerifyAlert(forged) {
		t.Fatal("forged (unsigned) conflict accepted — flood/censorship vector open")
	}

	// VALID evidence but UNATTESTED (no PoW) is dropped.
	good, _ := BuildEvidence(key, op(1), txid("a"), txid("b"))
	unattested := Alert{Outpoint: op(1), Evidence: good, AttesterPoW: []byte{0}}
	if VerifyAlert(unattested) {
		t.Fatal("unattested alert accepted")
	}

	// VALID evidence signed for the WRONG outpoint must not verify for op(1).
	wrong, _ := BuildEvidence(key, op(2), txid("a"), txid("b")) // signed for op(2)
	mis := Attest(op(1), wrong)                                 // attached to op(1)
	if VerifyAlert(mis) {
		t.Fatal("evidence signed for a different outpoint accepted")
	}
}

// A genuine, owner-signed, attested conflict is admitted.
func TestGenuineConflictAdmitted(t *testing.T) {
	key := ownerKey("owner-2")
	if !VerifyAlert(genuineAlert(t, op(2), key, "spendA", "spendB")) {
		t.Fatal("genuine attested conflict rejected")
	}
}

// T5.2 Conflict detected: a genuine conflicting spend flips QuietFor false.
func TestT5_2_ConflictFlipsQuiet(t *testing.T) {
	bus := NewBus()
	now := time.Unix(1_700_000_000, 0)
	bus.SetClock(func() time.Time { return now })
	key := ownerKey("owner-3")
	outs := []Outpoint{op(3)}

	if !bus.QuietFor(outs, time.Minute) {
		t.Fatal("should be quiet before any alert")
	}
	if !bus.Publish(genuineAlert(t, op(3), key, "c1", "c2")) {
		t.Fatal("genuine alert was not accepted by the bus")
	}
	if bus.QuietFor(outs, time.Minute) {
		t.Fatal("QuietFor still true after a verified conflicting-spend alert")
	}
	now = now.Add(2 * time.Minute)
	if !bus.QuietFor(outs, time.Minute) {
		t.Fatal("alert should have aged out of the window")
	}
}

// Flooding with unverifiable alerts has no effect on QuietFor (A4 / RT-2).
func TestFloodIneffective(t *testing.T) {
	bus := NewBus()
	key := ownerKey("owner-4")
	outs := []Outpoint{op(4)}
	for i := 0; i < 100; i++ {
		// distinct hashes but NO valid owner signature — pure fabrication
		junk := Attest(op(4), ConflictEvidence{
			OwnerPubKey: key.Public().SerializeCompressed(),
			SpendA:      txid(string(rune(i)) + "p"), SigA: make([]byte, 64),
			SpendB: txid(string(rune(i)) + "q"), SigB: make([]byte, 64),
		})
		if bus.Publish(junk) {
			t.Fatal("fabricated alert accepted")
		}
	}
	if !bus.QuietFor(outs, time.Hour) {
		t.Fatal("flood of fabricated alerts disturbed QuietFor")
	}
}

// Subscribers receive verified alerts.
func TestSubscribeDelivery(t *testing.T) {
	bus := NewBus()
	key := ownerKey("owner-5")
	ch, _ := bus.Subscribe(IPv6Group("ff02::dead:beef"))
	bus.Publish(genuineAlert(t, op(5), key, "d1", "d2"))
	select {
	case got := <-ch:
		if got.Outpoint != op(5) {
			t.Fatal("wrong alert delivered")
		}
	default:
		t.Fatal("subscriber did not receive the alert")
	}
}
