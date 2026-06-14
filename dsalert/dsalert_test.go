package dsalert

import (
	"testing"
	"time"

	"mfspv/commitment"
)

func op(i int) Outpoint {
	return Outpoint{TXID: commitment.DoubleSHA256([]byte{0x4f, byte(i)}), Vout: uint32(i)}
}
func txid(s string) Hash { return commitment.DoubleSHA256([]byte(s)) }

// T5.1 Evidence-gated: an alert with no verifiable conflict is dropped. (I-DS1)
func TestT5_1_EvidenceGated(t *testing.T) {
	// same-tx "conflict" is not a conflict
	a := Attest(op(1), ConflictEvidence{SpendA: txid("x"), SpendB: txid("x")})
	if VerifyAlert(a) {
		t.Fatal("same-tx evidence accepted")
	}
	// empty evidence
	a2 := Attest(op(1), ConflictEvidence{SpendA: Hash{}, SpendB: txid("y")})
	if VerifyAlert(a2) {
		t.Fatal("empty evidence accepted")
	}
	// genuine conflict but UNATTESTED (no PoW) is dropped
	a3 := Alert{Outpoint: op(1), Evidence: ConflictEvidence{SpendA: txid("a"), SpendB: txid("b")}, AttesterPoW: []byte{0}}
	if VerifyAlert(a3) {
		t.Fatal("unattested alert accepted (flood vector open)")
	}
}

// A genuine, attested conflict is admitted.
func TestGenuineConflictAdmitted(t *testing.T) {
	a := Attest(op(2), ConflictEvidence{SpendA: txid("spendA"), SpendB: txid("spendB")})
	if !VerifyAlert(a) {
		t.Fatal("genuine attested conflict rejected")
	}
}

// T5.2 Conflict detected: a genuine conflicting spend produces an alert that flips
// QuietFor false within the window.
func TestT5_2_ConflictFlipsQuiet(t *testing.T) {
	bus := NewBus()
	now := time.Unix(1_700_000_000, 0)
	bus.SetClock(func() time.Time { return now })
	outs := []Outpoint{op(3)}

	if !bus.QuietFor(outs, time.Minute) {
		t.Fatal("should be quiet before any alert")
	}
	a := Attest(op(3), ConflictEvidence{SpendA: txid("c1"), SpendB: txid("c2")})
	if !bus.Publish(a) {
		t.Fatal("genuine alert was not accepted by the bus")
	}
	if bus.QuietFor(outs, time.Minute) {
		t.Fatal("QuietFor still true after a verified conflicting-spend alert")
	}
	// After the window passes, it is quiet again.
	now = now.Add(2 * time.Minute)
	if !bus.QuietFor(outs, time.Minute) {
		t.Fatal("alert should have aged out of the window")
	}
}

// Flooding with unverifiable alerts has no effect on QuietFor (A4).
func TestFloodIneffective(t *testing.T) {
	bus := NewBus()
	outs := []Outpoint{op(4)}
	for i := 0; i < 100; i++ {
		junk := Alert{Outpoint: op(4), Evidence: ConflictEvidence{SpendA: txid("z"), SpendB: txid("z")}, AttesterPoW: []byte{byte(i)}}
		if bus.Publish(junk) {
			t.Fatal("junk alert accepted")
		}
	}
	if !bus.QuietFor(outs, time.Hour) {
		t.Fatal("flood of junk alerts disturbed QuietFor")
	}
}

// Subscribers receive verified alerts.
func TestSubscribeDelivery(t *testing.T) {
	bus := NewBus()
	ch, _ := bus.Subscribe(IPv6Group("ff02::dead:beef"))
	a := Attest(op(5), ConflictEvidence{SpendA: txid("d1"), SpendB: txid("d2")})
	bus.Publish(a)
	select {
	case got := <-ch:
		if got.Outpoint != op(5) {
			t.Fatal("wrong alert delivered")
		}
	default:
		t.Fatal("subscriber did not receive the alert")
	}
}
