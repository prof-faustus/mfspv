// Package walletbob is the point-of-sale merchant wallet (02_MODULE_SPECS.md
// §wallet_bob, §3.2). Bob is ONLINE: he keeps the constant ~4.2 MB/year header
// chain (or a pruned view + L4 anchor), verifies inclusion LOCALLY, queries the
// live UTXO set, consults the double-spend alert layer, and broadcasts.
//
// Invariants:
//   - I-BB1 Separation: inclusion (step 2) and double-spend (steps 3–4) are
//     distinct; a passing inclusion check NEVER alone yields "accepted".
//   - I-BB2 No keys at till: the wallet stores only receiving public keys, never
//     private keys.
//   - I-BB3 τ is policy: the protocol provides signals; the accept/reject
//     threshold lives in RiskPolicy, owned by the merchant, never hard-coded.
//
// BSV only.
package walletbob

import (
	"errors"
	"time"

	"mfspv/bundle"
	"mfspv/crypto"
	"mfspv/dsalert"
	"mfspv/payment"
	"mfspv/teranode"
)

// RiskPolicy is the merchant-owned 0-confirmation acceptance policy (I-BB3).
//
//	Tau    : maximum value-at-risk the merchant accepts at 0-conf.
//	Window : trailing quiet window required with no conflicting-spend alert.
type RiskPolicy struct {
	Tau    float64
	Window time.Duration
}

// Decide combines the protocol signals into an accept/reject decision. Inclusion
// alone is never sufficient: unspent AND alert-quiet AND value-within-τ are all
// required (encodes I-BB1).
func (p RiskPolicy) Decide(valueAtRisk float64, inclusionOK, allUnspent, alertQuiet bool) bool {
	if !inclusionOK || !allUnspent || !alertQuiet {
		return false
	}
	return valueAtRisk <= p.Tau
}

// Decision is the outcome of AcceptPayment, with each signal exposed for audit.
type Decision struct {
	Accepted     bool
	Reason       string
	InclusionOK  bool
	AllUnspent   bool
	AlertQuiet   bool
	SignaturesOK bool
	TemplateOK   bool
}

// Wallet is Bob's till.
type Wallet struct {
	headers     teranode.HeaderChain
	utxo        teranode.UTXOClient
	alerts      *dsalert.Bus
	broadcaster func(payment.Tx3) error

	// receiving public keys only (I-BB2). There is deliberately NO field for
	// private keys anywhere in this struct.
	receiving map[string]*crypto.PublicKey
}

// New builds a till wired to the header view, UTXO oracle, alert bus and a
// broadcast function.
func New(headers teranode.HeaderChain, utxo teranode.UTXOClient, alerts *dsalert.Bus, broadcaster func(payment.Tx3) error) *Wallet {
	return &Wallet{
		headers:     headers,
		utxo:        utxo,
		alerts:      alerts,
		broadcaster: broadcaster,
		receiving:   map[string]*crypto.PublicKey{},
	}
}

// AddReceivingKey registers a PUBLIC key the till can be paid to.
func (w *Wallet) AddReceivingKey(pub *crypto.PublicKey) {
	w.receiving[string(pub.SerializeCompressed())] = pub
}

// ErrNoKeysAtTill is returned by any attempt to place private key material at the
// point of sale (I-BB2).
var ErrNoKeysAtTill = errors.New("walletbob: private keys must never be stored at the till (I-BB2)")

// StorePrivateKey always fails: it exists solely to make the I-BB2 prohibition
// explicit and testable. The till has no code path that retains a private key.
func (w *Wallet) StorePrivateKey(_ *crypto.PrivateKey) error { return ErrNoKeysAtTill }

// AcceptPayment runs the full point-of-sale decision over an exported message.
//
//  1. Deserialize bundles + Tx3.
//  2. For each input: bundle.Verify (LOCAL, fail-fast inclusion).
//  3. For each input.OutputRef: utxo.IsUnspent (NETWORK: Teranode utxo).
//  4. alerts.QuietFor(outpoints, policy.Window): no conflicting-spend alert.
//  5. Verify Alice's signatures; verify Tx3 matches the requested template.
//  6. Decision = policy.Decide(valueAtRisk, inclusionOK, allUnspent, alertQuiet).
//
// template is Bob's original request; the payment must reproduce its outputs.
func (w *Wallet) AcceptPayment(msg []byte, template payment.Tx3, valueAtRisk float64, policy RiskPolicy) (Decision, error) {
	d := Decision{}
	m, err := payment.DecodeMessage(msg)
	if err != nil {
		return d, err
	}
	if len(m.Bundles) != len(m.Tx.Inputs) {
		return d, errors.New("walletbob: bundle count != input count")
	}

	// 2. Inclusion (LOCAL, fail-fast). Each bundle must verify AND match its input.
	d.InclusionOK = true
	for i := range m.Bundles {
		b := m.Bundles[i]
		if b.OutputRef.TXID != m.Tx.Inputs[i].Prev.TXID || b.OutputRef.Vout != m.Tx.Inputs[i].Prev.Vout {
			d.InclusionOK = false
			d.Reason = "bundle/input mismatch"
			break
		}
		if ok, _, reason := bundle.Verify(b, w.headers); !ok {
			d.InclusionOK = false
			d.Reason = "inclusion:" + reason
			break
		}
	}

	// 3. Liveness (NETWORK). Distinct from inclusion (I-BB1).
	d.AllUnspent = true
	var outpoints []dsalert.Outpoint
	for i := range m.Tx.Inputs {
		op := teranode.Outpoint{TXID: m.Tx.Inputs[i].Prev.TXID, Vout: m.Tx.Inputs[i].Prev.Vout}
		unspent, err := w.utxo.IsUnspent(op)
		if err != nil {
			return d, err
		}
		if !unspent {
			d.AllUnspent = false
		}
		outpoints = append(outpoints, dsalert.Outpoint{TXID: op.TXID, Vout: op.Vout})
	}

	// 4. Alert-quiet window.
	d.AlertQuiet = true
	if w.alerts != nil {
		d.AlertQuiet = w.alerts.QuietFor(outpoints, policy.Window)
	}

	// 5. Signatures + template match.
	d.SignaturesOK = true
	for i := range m.Tx.Inputs {
		if !m.Tx.VerifyInputSignature(i) {
			d.SignaturesOK = false
			break
		}
	}
	d.TemplateOK = templateSatisfied(template, m.Tx)

	// 6. Final decision. Inclusion alone is never enough (I-BB1).
	allOK := d.InclusionOK && d.SignaturesOK && d.TemplateOK
	d.Accepted = allOK && policy.Decide(valueAtRisk, d.InclusionOK, d.AllUnspent, d.AlertQuiet)
	if d.Accepted {
		d.Reason = "accepted"
	} else if d.Reason == "" {
		switch {
		case !d.SignaturesOK:
			d.Reason = "signature"
		case !d.TemplateOK:
			d.Reason = "template"
		case !d.AllUnspent:
			d.Reason = "double-spend:utxo-spent"
		case !d.AlertQuiet:
			d.Reason = "double-spend:alert"
		default:
			d.Reason = "risk-policy:value-exceeds-tau"
		}
	}
	return d, nil
}

// Broadcast sends Tx3 to the network (only call after AcceptPayment accepted).
func (w *Wallet) Broadcast(tx payment.Tx3) error {
	if w.broadcaster == nil {
		return errors.New("walletbob: no broadcaster configured")
	}
	return w.broadcaster(tx)
}

// templateSatisfied checks every output Bob requested is present in the payment
// with the same value and script (Alice may add a change output beyond these).
func templateSatisfied(template, tx payment.Tx3) bool {
	for _, want := range template.Outputs {
		found := false
		for _, got := range tx.Outputs {
			if got.Value == want.Value && bytesEqual(got.ScriptPubKey, want.ScriptPubKey) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
