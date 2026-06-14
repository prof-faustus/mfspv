// Package payment holds the transaction type (Tx3) and the wire message Alice
// pushes to Bob (§3.2 step [2]): the signed spending transaction plus, per input,
// its proof bundle. Shared by wallet_alice and wallet_bob so neither imports the
// other.
//
// BSV only.
package payment

import (
	"encoding/binary"
	"errors"

	"mfspv/bundle"
	"mfspv/commitment"
	"mfspv/crypto"
)

type Hash = commitment.Hash

// Outpoint references a previous output.
type Outpoint struct {
	TXID Hash
	Vout uint32
}

// TxIn spends a previous output, carrying the spender's signature and public key.
type TxIn struct {
	Prev   Outpoint
	Sig    []byte // 64-byte secp256k1 (r‖s), empty until signed
	PubKey []byte // 33-byte compressed
}

// TxOut creates a new output.
type TxOut struct {
	Value        uint64
	ScriptPubKey []byte
}

// Tx3 is the payment transaction (the project's "Tx3").
type Tx3 struct {
	Version  uint32
	Inputs   []TxIn
	Outputs  []TxOut
	LockTime uint32
}

// preimage serialises the transaction with input scripts blanked, for sighashing.
// inputIdx selects which input is being signed; all sig fields are excluded so the
// signature commits to the transaction structure and amounts, not to itself.
func (t *Tx3) preimage(inputIdx int) []byte {
	w := &buf{}
	w.u32(t.Version)
	w.u32(uint32(len(t.Inputs)))
	for _, in := range t.Inputs {
		w.bytes(in.Prev.TXID[:])
		w.u32(in.Prev.Vout)
		w.bytes(in.PubKey)
	}
	w.u32(uint32(len(t.Outputs)))
	for _, out := range t.Outputs {
		w.u64(out.Value)
		w.u32(uint32(len(out.ScriptPubKey)))
		w.bytes(out.ScriptPubKey)
	}
	w.u32(t.LockTime)
	w.u32(uint32(inputIdx))
	return w.b
}

// Sighash returns the 32-byte digest signed for inputIdx.
func (t *Tx3) Sighash(inputIdx int) Hash {
	return commitment.DoubleSHA256(t.preimage(inputIdx))
}

// VerifyInputSignature checks the signature on input inputIdx against the public
// key carried in that input.
func (t *Tx3) VerifyInputSignature(inputIdx int) bool {
	if inputIdx < 0 || inputIdx >= len(t.Inputs) {
		return false
	}
	in := t.Inputs[inputIdx]
	if len(in.Sig) != 64 || len(in.PubKey) != 33 {
		return false
	}
	pub, err := parseCompressed(in.PubKey)
	if err != nil {
		return false
	}
	sig, err := crypto.ParseSignature(in.Sig)
	if err != nil {
		return false
	}
	h := t.Sighash(inputIdx)
	return crypto.Verify(pub, h[:], sig)
}

// Message is the §3.2[2] payload: the signed tx and one bundle per input.
type Message struct {
	Tx      Tx3
	Bundles []bundle.Bundle
}

// Encode serialises the message (length-prefixed).
func (m *Message) Encode() ([]byte, error) {
	w := &buf{}
	if err := encodeTx(w, &m.Tx); err != nil {
		return nil, err
	}
	w.u32(uint32(len(m.Bundles)))
	for i := range m.Bundles {
		bb, err := bundle.Serialize(m.Bundles[i])
		if err != nil {
			return nil, err
		}
		w.u32(uint32(len(bb)))
		w.bytes(bb)
	}
	return w.b, nil
}

// DecodeMessage parses a message.
func DecodeMessage(data []byte) (*Message, error) {
	r := &rdr{b: data}
	m := &Message{}
	if err := decodeTx(r, &m.Tx); err != nil {
		return nil, err
	}
	n := r.u32()
	if r.err != nil {
		return nil, r.err
	}
	for i := uint32(0); i < n; i++ {
		ln := int(r.u32())
		bb := r.take(ln)
		if r.err != nil {
			return nil, r.err
		}
		b, err := bundle.Deserialize(bb)
		if err != nil {
			return nil, err
		}
		m.Bundles = append(m.Bundles, b)
	}
	if r.err != nil {
		return nil, r.err
	}
	if r.off != len(r.b) {
		return nil, errors.New("payment: trailing bytes after message")
	}
	return m, nil
}

func parseCompressed(b []byte) (*crypto.PublicKey, error) {
	return crypto.ParseCompressed(b)
}

// --- tx codec ---

func encodeTx(w *buf, t *Tx3) error {
	w.u32(t.Version)
	w.u32(uint32(len(t.Inputs)))
	for _, in := range t.Inputs {
		w.bytes(in.Prev.TXID[:])
		w.u32(in.Prev.Vout)
		w.u16(uint16(len(in.Sig)))
		w.bytes(in.Sig)
		w.u16(uint16(len(in.PubKey)))
		w.bytes(in.PubKey)
	}
	w.u32(uint32(len(t.Outputs)))
	for _, o := range t.Outputs {
		w.u64(o.Value)
		w.u32(uint32(len(o.ScriptPubKey)))
		w.bytes(o.ScriptPubKey)
	}
	w.u32(t.LockTime)
	return nil
}

func decodeTx(r *rdr, t *Tx3) error {
	t.Version = r.u32()
	ni := r.u32()
	for i := uint32(0); i < ni && r.err == nil; i++ {
		var in TxIn
		_ = r.read(in.Prev.TXID[:])
		in.Prev.Vout = r.u32()
		in.Sig = append([]byte(nil), r.take(int(r.u16()))...)
		in.PubKey = append([]byte(nil), r.take(int(r.u16()))...)
		t.Inputs = append(t.Inputs, in)
	}
	no := r.u32()
	for i := uint32(0); i < no && r.err == nil; i++ {
		var o TxOut
		o.Value = r.u64()
		o.ScriptPubKey = append([]byte(nil), r.take(int(r.u32()))...)
		t.Outputs = append(t.Outputs, o)
	}
	t.LockTime = r.u32()
	return r.err
}

// --- low-level buffers ---

type buf struct{ b []byte }

func (w *buf) u16(v uint16) {
	var x [2]byte
	binary.LittleEndian.PutUint16(x[:], v)
	w.b = append(w.b, x[:]...)
}
func (w *buf) u32(v uint32) {
	var x [4]byte
	binary.LittleEndian.PutUint32(x[:], v)
	w.b = append(w.b, x[:]...)
}
func (w *buf) u64(v uint64) {
	var x [8]byte
	binary.LittleEndian.PutUint64(x[:], v)
	w.b = append(w.b, x[:]...)
}
func (w *buf) bytes(b []byte) { w.b = append(w.b, b...) }

type rdr struct {
	b   []byte
	off int
	err error
}

func (r *rdr) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || r.off+n > len(r.b) {
		r.err = errors.New("payment: truncated message")
		return nil
	}
	out := r.b[r.off : r.off+n]
	r.off += n
	return out
}
func (r *rdr) read(dst []byte) error {
	b := r.take(len(dst))
	if b != nil {
		copy(dst, b)
	}
	return r.err
}
func (r *rdr) u16() uint16 {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint16(b)
}
func (r *rdr) u32() uint32 {
	b := r.take(4)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(b)
}
func (r *rdr) u64() uint64 {
	b := r.take(8)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint64(b)
}
