package walletbob

import (
	"sync"
	"testing"
	"time"

	"mfspv/payment"
)

// node models a Teranode peer: it receives a broadcast Tx3, validates every input
// signature, and (if accepted) records it as seen. A real node also does full
// script/UTXO validation; here we exercise the signature + acceptance the SPV push
// relies on.
type node struct {
	mu   sync.Mutex
	seen map[string]bool
}

func newNode() *node { return &node{seen: map[string]bool{}} }

func (n *node) submit(tx payment.Tx3) bool {
	for i := range tx.Inputs {
		if !tx.VerifyInputSignature(i) {
			return false
		}
	}
	n.mu.Lock()
	n.seen[string(tx.Inputs[0].Sig)] = true
	n.mu.Unlock()
	return true
}

// TestE2E_SPV_PushToNodes is the complete SPV protocol of the design:
// Bob -> Alice (request), Alice -> Bob (signed Tx3 + inclusion path), Bob verifies
// LOCALLY, then Alice AND Bob push the Tx to 2-3 nodes. Asserts the whole flow.
func TestE2E_SPV_PushToNodes(t *testing.T) {
	s := newScenario(t)

	// [1->2] Alice gives Bob the signed Tx3 + the inclusion path (the bundle).
	msg, template := s.pay(t)

	// 2 or 3 nodes the parties will push to.
	nodes := []*node{newNode(), newNode(), newNode()}

	// Bob's till broadcasts the accepted Tx to ALL nodes (the "push to 2-3 nodes").
	bob := New(s.node, s.node, s.bus, func(tx payment.Tx3) error {
		for _, nd := range nodes {
			if !nd.submit(tx) {
				t.Errorf("node rejected Bob's broadcast")
			}
		}
		return nil
	})
	bob.AddReceivingKey(s.bobPub)

	// [3] Bob verifies LOCALLY (path + signature + unspent + value + alert-quiet).
	d, err := bob.AcceptPayment(msg, template, 900, RiskPolicy{Tau: 5000, Window: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Accepted {
		t.Fatalf("Bob did not accept a valid SPV payment: %+v", d)
	}
	if !d.SignaturesOK || !d.InclusionOK {
		t.Fatalf("inclusion/signature not verified: %+v", d)
	}

	// [4] Push to the nodes: Bob broadcasts; Alice independently pushes too.
	m, _ := payment.DecodeMessage(msg)
	if err := bob.Broadcast(m.Tx); err != nil {
		t.Fatal(err)
	}
	for _, nd := range nodes { // Alice also pushes (Merchant->Customer->...->Network)
		if !nd.submit(m.Tx) {
			t.Fatal("node rejected Alice's push")
		}
	}

	// Every node accepted the pushed Tx.
	for i, nd := range nodes {
		nd.mu.Lock()
		ok := nd.seen[string(m.Tx.Inputs[0].Sig)]
		nd.mu.Unlock()
		if !ok {
			t.Fatalf("node %d never accepted the pushed Tx", i)
		}
	}

	// A node MUST reject a tampered Tx (signature broken) — the push is not blind.
	bad := m.Tx
	bad.Inputs = append([]payment.TxIn(nil), m.Tx.Inputs...)
	bad.Inputs[0].Sig = append([]byte(nil), m.Tx.Inputs[0].Sig...)
	bad.Inputs[0].Sig[0] ^= 0xff
	if nodes[0].submit(bad) {
		t.Fatal("node accepted a tampered Tx push")
	}
}
