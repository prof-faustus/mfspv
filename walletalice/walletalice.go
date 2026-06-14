// Package walletalice is the offline customer wallet (02_MODULE_SPECS.md
// §wallet_alice, §3.2). Alice is OFFLINE: she holds her spendable outputs' proof
// bundles, her private keys, and (optionally) headers. Every operation is
// computable with no network access (I-AL1, smart-card capable).
//
// I-AL2 (TXID sufficiency): providing only a TXID is INSUFFICIENT; Export always
// ships the fields needed to reconstruct MTxID. Enforced in Export.
//
// BSV only.
package walletalice

import (
	"errors"

	"mfspv/bundle"
	"mfspv/crypto"
	"mfspv/payment"
)

// Wallet is Alice's offline store.
type Wallet struct {
	bundles map[outKey]bundle.Bundle
	keys    map[outKey]*crypto.PrivateKey
}

type outKey struct {
	txid bundle.Hash
	vout uint32
}

// New creates an empty offline wallet.
func New() *Wallet {
	return &Wallet{
		bundles: map[outKey]bundle.Bundle{},
		keys:    map[outKey]*crypto.PrivateKey{},
	}
}

// AddOutput stores a spendable output: its proof bundle and the spending key.
func (w *Wallet) AddOutput(b bundle.Bundle, key *crypto.PrivateKey) {
	k := outKey{b.OutputRef.TXID, b.OutputRef.Vout}
	w.bundles[k] = b
	w.keys[k] = key
}

var (
	ErrNoKey    = errors.New("walletalice: no key for input")
	ErrInputIdx = errors.New("walletalice: input index out of range")
	ErrNoBundle = errors.New("walletalice: no bundle for input")
	ErrTXIDOnly = errors.New("walletalice: refusing to export a bundle without MTxID fields (TXID alone is insufficient, I-AL2)")
)

// Sign produces Alice's ECDSA signature for input inputIdx of tx, using key. It is
// fully offline. (I-AL1)
func (w *Wallet) Sign(tx *payment.Tx3, inputIdx int, key *crypto.PrivateKey) ([]byte, error) {
	if inputIdx < 0 || inputIdx >= len(tx.Inputs) {
		return nil, ErrInputIdx
	}
	if key == nil {
		return nil, ErrNoKey
	}
	h := tx.Sighash(inputIdx)
	sig, err := key.Sign(h[:])
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
}

// FillTemplate completes Bob's payment template by attaching Alice's inputs,
// signing each, and (optionally) appending a change output. It runs offline.
//
// template carries Bob's output(s). inputs are the bundles Alice spends; for each
// she must hold the corresponding key. changeScript, if non-nil, receives any
// surplus value (computed by the caller; here we just append it when changeValue>0).
func (w *Wallet) FillTemplate(template payment.Tx3, inputs []bundle.Bundle, changeScript []byte, changeValue uint64) (payment.Tx3, error) {
	tx := template
	tx.Inputs = nil
	for _, b := range inputs {
		k := outKey{b.OutputRef.TXID, b.OutputRef.Vout}
		key, ok := w.keys[k]
		if !ok {
			return payment.Tx3{}, ErrNoKey
		}
		tx.Inputs = append(tx.Inputs, payment.TxIn{
			Prev:   payment.Outpoint{TXID: b.OutputRef.TXID, Vout: b.OutputRef.Vout},
			PubKey: key.Public().SerializeCompressed(),
		})
	}
	if changeValue > 0 && changeScript != nil {
		tx.Outputs = append(tx.Outputs, payment.TxOut{Value: changeValue, ScriptPubKey: changeScript})
	}
	// Sign each input over the now-complete structure.
	for i, b := range inputs {
		k := outKey{b.OutputRef.TXID, b.OutputRef.Vout}
		sig, err := w.Sign(&tx, i, w.keys[k])
		if err != nil {
			return payment.Tx3{}, err
		}
		tx.Inputs[i].Sig = sig
	}
	return tx, nil
}

// Export produces the §3.2[2] message Alice sends Bob: the signed tx plus one
// bundle per input. It REFUSES any bundle that lacks the fields needed to rebuild
// MTxID (I-AL2): a TXID alone is insufficient.
func (w *Wallet) Export(inputs []bundle.Bundle, signedTx payment.Tx3) ([]byte, error) {
	for i := range inputs {
		// A bundle with no revealed fields carries only a TXID — insufficient to
		// reconstruct MTxID. Refuse it (I-AL2).
		if len(inputs[i].Fields) == 0 {
			return nil, ErrTXIDOnly
		}
	}
	msg := payment.Message{Tx: signedTx, Bundles: inputs}
	return msg.Encode()
}
