package walletbob

import (
	"crypto/sha256"
	"testing"
	"time"

	"mfspv/bundle"
	"mfspv/commitment"
	"mfspv/crypto"
	"mfspv/dsalert"
	"mfspv/payment"
	"mfspv/teranode"
	"mfspv/walletalice"
)

// scenario wires a node, seals a funding output for Alice, and returns the pieces
// needed to drive a full push payment.
type scenario struct {
	node   *teranode.MockNode
	bus    *dsalert.Bus
	aliceW *walletalice.Wallet
	bobW   *Wallet
	fund   bundle.Bundle
	aliceK *crypto.PrivateKey
	bobPub *crypto.PublicKey
	now    time.Time
}

func newScenario(t *testing.T) *scenario {
	t.Helper()
	node := teranode.NewMockNode(8)

	// Alice's funding tx fields; field 1 is the spendable output she reveals.
	fields := commitment.TxFields{
		{Index: 0, Bytes: []byte{0x01}},
		{Index: 1, Bytes: []byte("alice-output-1000-sats")},
		{Index: 2, Bytes: []byte{0xde, 0xad}},
	}
	mtxid, _, err := commitment.BuildMTxID(fields)
	if err != nil {
		t.Fatal(err)
	}
	txids := []commitment.Hash{mtxid}
	for i := 0; i < 20; i++ {
		txids = append(txids, commitment.DoubleSHA256([]byte{0x33, byte(i)}))
	}
	if _, err := node.SealBlock(txids, false); err != nil {
		t.Fatal(err)
	}
	out := bundle.OutputRef{TXID: mtxid, Vout: 0}
	fund, err := bundle.Build(out, fields, 1, node)
	if err != nil {
		t.Fatal(err)
	}

	aliceSeed := sha256.Sum256([]byte("alice-key"))
	aliceK, _ := crypto.NewPrivateKey(aliceSeed[:])
	bobSeed := sha256.Sum256([]byte("bob-key"))
	bobK, _ := crypto.NewPrivateKey(bobSeed[:])

	aliceW := walletalice.New()
	aliceW.AddOutput(fund, aliceK)

	bus := dsalert.NewBus()
	now := time.Unix(1_700_000_000, 0)
	bus.SetClock(func() time.Time { return now })

	bobW := New(node, node, bus, func(payment.Tx3) error { return nil })
	bobW.AddReceivingKey(bobK.Public())

	return &scenario{
		node: node, bus: bus, aliceW: aliceW, bobW: bobW,
		fund: fund, aliceK: aliceK, bobPub: bobK.Public(), now: now,
	}
}

// build the template Bob requests and the signed export Alice returns.
func (s *scenario) pay(t *testing.T) ([]byte, payment.Tx3) {
	t.Helper()
	template := payment.Tx3{
		Version: 1,
		Outputs: []payment.TxOut{
			{Value: 900, ScriptPubKey: s.bobPub.SerializeCompressed()},
		},
	}
	signed, err := s.aliceW.FillTemplate(template, []bundle.Bundle{s.fund}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := s.aliceW.Export([]bundle.Bundle{s.fund}, signed)
	if err != nil {
		t.Fatal(err)
	}
	return msg, template
}

// T4.1 Alice offline: Sign/FillTemplate/Export run with no network (the wallet has
// no network handle at all — construction guarantees it). (I-AL1)
func TestT4_1_AliceOffline(t *testing.T) {
	s := newScenario(t)
	// walletalice.Wallet holds no network client; these calls cannot reach a node.
	msg, _ := s.pay(t)
	if len(msg) == 0 {
		t.Fatal("empty export")
	}
}

// T4.2 TXID-only rejected: Export omitting MTxID fields is rejected. (I-AL2)
func TestT4_2_TXIDOnlyRejected(t *testing.T) {
	s := newScenario(t)
	stripped := s.fund
	stripped.Fields = nil // only a TXID remains
	template := payment.Tx3{Outputs: []payment.TxOut{{Value: 900, ScriptPubKey: s.bobPub.SerializeCompressed()}}}
	signed, err := s.aliceW.FillTemplate(template, []bundle.Bundle{s.fund}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.aliceW.Export([]bundle.Bundle{stripped}, signed); err == nil {
		t.Fatal("Export accepted a bundle with no MTxID fields")
	}
}

// T4.3 No keys at till: wallet_bob holds no private keys; storing one is rejected. (I-BB2)
func TestT4_3_NoKeysAtTill(t *testing.T) {
	s := newScenario(t)
	seed := sha256.Sum256([]byte("rogue"))
	k, _ := crypto.NewPrivateKey(seed[:])
	if err := s.bobW.StorePrivateKey(k); err == nil {
		t.Fatal("till accepted a private key")
	}
}

// T4.4 Acceptance separation: AcceptPayment returns accepted only when inclusion
// AND unspent AND alert-quiet AND signature/template pass under RiskPolicy. (I-BB1)
func TestT4_4_AcceptanceSeparation(t *testing.T) {
	s := newScenario(t)
	msg, template := s.pay(t)
	policy := RiskPolicy{Tau: 1000, Window: time.Minute}

	// Happy path: everything passes.
	d, err := s.bobW.AcceptPayment(msg, template, 900, policy)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Accepted {
		t.Fatalf("valid payment rejected: %+v", d)
	}
	if !(d.InclusionOK && d.AllUnspent && d.AlertQuiet && d.SignaturesOK && d.TemplateOK) {
		t.Fatalf("signals inconsistent with acceptance: %+v", d)
	}

	// Inclusion alone is NOT enough: spend the output -> must reject though
	// inclusion still holds. (I-BB1 / §6.3)
	s2 := newScenario(t)
	msg2, template2 := s2.pay(t)
	s2.node.MarkSpent(teranode.Outpoint{TXID: s2.fund.OutputRef.TXID, Vout: 0})
	d2, _ := s2.bobW.AcceptPayment(msg2, template2, 900, policy)
	if d2.Accepted {
		t.Fatal("accepted a double-spent output on inclusion alone")
	}
	if !d2.InclusionOK {
		t.Fatal("inclusion should still hold for a spent output")
	}
	if d2.AllUnspent {
		t.Fatal("oracle should report spent")
	}
}

// T5.2/T5.3 τ behaviour + conflict: acceptance boundary moves with value-at-risk
// and a conflicting-spend alert flips acceptance. τ is read from RiskPolicy.
func TestTauAndAlertBehaviour(t *testing.T) {
	// value-at-risk above τ rejects even when all else is fine.
	s := newScenario(t)
	msg, template := s.pay(t)
	strict := RiskPolicy{Tau: 500, Window: time.Minute}
	d, _ := s.bobW.AcceptPayment(msg, template, 900, strict) // 900 > τ=500
	if d.Accepted {
		t.Fatal("accepted a payment whose value exceeds τ")
	}
	loose := RiskPolicy{Tau: 5000, Window: time.Minute}
	d2, _ := s.bobW.AcceptPayment(msg, template, 900, loose) // 900 <= τ=5000
	if !d2.Accepted {
		t.Fatalf("rejected a payment within τ: %+v", d2)
	}

	// a conflicting-spend alert within the window flips acceptance to reject.
	s3 := newScenario(t)
	msg3, template3 := s3.pay(t)
	op := dsalert.Outpoint{TXID: s3.fund.OutputRef.TXID, Vout: 0}
	dsSeed := sha256.Sum256([]byte("double-spender"))
	dsKey, _ := crypto.NewPrivateKey(dsSeed[:])
	ev, err := dsalert.BuildEvidence(dsKey, op,
		commitment.DoubleSHA256([]byte("honest-spend")),
		commitment.DoubleSHA256([]byte("double-spend")))
	if err != nil {
		t.Fatal(err)
	}
	if !s3.bus.Publish(dsalert.Attest(op, ev)) {
		t.Fatal("genuine alert not accepted by bus")
	}
	d3, _ := s3.bobW.AcceptPayment(msg3, template3, 900, RiskPolicy{Tau: 5000, Window: time.Minute})
	if d3.Accepted {
		t.Fatal("accepted despite a verified conflicting-spend alert")
	}
	if d3.AlertQuiet {
		t.Fatal("alert window should not be quiet")
	}
}

// A3: a malformed/garbage message is rejected fail-fast, with no panic.
func TestMalformedMessageRejected(t *testing.T) {
	s := newScenario(t)
	if _, err := s.bobW.AcceptPayment([]byte{0x00, 0x01, 0x02}, payment.Tx3{}, 1, RiskPolicy{Tau: 1, Window: time.Second}); err == nil {
		t.Fatal("garbage message accepted")
	}
}

// A tampered signature is rejected.
func TestTamperedSignatureRejected(t *testing.T) {
	s := newScenario(t)
	msg, template := s.pay(t)
	m, _ := payment.DecodeMessage(msg)
	m.Tx.Inputs[0].Sig[0] ^= 0xff
	bad, _ := m.Encode()
	d, _ := s.bobW.AcceptPayment(bad, template, 900, RiskPolicy{Tau: 5000, Window: time.Minute})
	if d.Accepted || d.SignaturesOK {
		t.Fatal("accepted a tampered signature")
	}
}
