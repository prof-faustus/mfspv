package bundle

import (
	"encoding/binary"
	"errors"

	"mfspv/commitment"
)

// Wire format: compact, length-prefixed, deterministic. All integers little-endian.
//
//	OutputRef.TXID            [32]
//	OutputRef.Vout            u32
//	Fields                    u16 count, then each: Index u8, len u16, bytes
//	MTxIDPath / SubtreePath / BlockPath : each u16 count, then each elem: Right u8, Sibling[32]
//	Header                    [80]
//	HasAnchor                 u8 (0/1)
//	  Anchor.AccRoot          [32]
//	  Anchor.AccPath          path
//	  Anchor.GenTxFields      fields
//	  Anchor.GenL0/L1/L2      path, path, path
//	  Anchor.CarryingBlockMerkleRoot [32]

var ErrTruncated = errors.New("bundle: truncated or malformed serialization")

func Serialize(b Bundle) ([]byte, error) {
	w := &writer{}
	w.bytes(b.OutputRef.TXID[:])
	w.u32(b.OutputRef.Vout)
	w.fields(b.Fields)
	w.path(b.MTxIDPath)
	w.path(b.SubtreePath)
	w.path(b.BlockPath)
	w.bytes(b.Header[:])
	if b.Anchor == nil {
		w.u8(0)
	} else {
		w.u8(1)
		a := b.Anchor
		w.bytes(a.AccRoot[:])
		w.path(a.AccPath)
		w.fields(a.GenTxFields)
		w.path(a.GenL0)
		w.path(a.GenL1)
		w.path(a.GenL2)
		w.bytes(a.CarryingBlockMerkleRoot[:])
		w.bytes(a.CarryingHeader[:])
	}
	return w.buf, nil
}

func Deserialize(data []byte) (Bundle, error) {
	r := &reader{buf: data}
	var b Bundle
	if err := r.read(b.OutputRef.TXID[:]); err != nil {
		return Bundle{}, err
	}
	b.OutputRef.Vout = r.u32()
	b.Fields = r.fields()
	b.MTxIDPath = r.path()
	b.SubtreePath = r.path()
	b.BlockPath = r.path()
	if err := r.read(b.Header[:]); err != nil {
		return Bundle{}, err
	}
	has := r.u8()
	if has == 1 {
		a := &AnchorProof{}
		if err := r.read(a.AccRoot[:]); err != nil {
			return Bundle{}, err
		}
		a.AccPath = r.path()
		a.GenTxFields = r.fields()
		a.GenL0 = r.path()
		a.GenL1 = r.path()
		a.GenL2 = r.path()
		if err := r.read(a.CarryingBlockMerkleRoot[:]); err != nil {
			return Bundle{}, err
		}
		if err := r.read(a.CarryingHeader[:]); err != nil {
			return Bundle{}, err
		}
		b.Anchor = a
	}
	if r.err != nil {
		return Bundle{}, r.err
	}
	if r.off != len(r.buf) {
		return Bundle{}, ErrTruncated
	}
	return b, nil
}

// --- writer ---

type writer struct{ buf []byte }

func (w *writer) u8(v byte) { w.buf = append(w.buf, v) }
func (w *writer) u16(v uint16) {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], v)
	w.buf = append(w.buf, b[:]...)
}
func (w *writer) u32(v uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	w.buf = append(w.buf, b[:]...)
}
func (w *writer) bytes(b []byte) { w.buf = append(w.buf, b...) }

func (w *writer) path(p []PathElem) {
	w.u16(uint16(len(p)))
	for _, e := range p {
		if e.Right {
			w.u8(1)
		} else {
			w.u8(0)
		}
		w.bytes(e.Sibling[:])
	}
}

func (w *writer) fields(fs TxFields) {
	w.u16(uint16(len(fs)))
	for _, f := range fs {
		w.u8(f.Index)
		w.u16(uint16(len(f.Bytes)))
		w.bytes(f.Bytes)
	}
}

// --- reader ---

type reader struct {
	buf []byte
	off int
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if r.off+n > len(r.buf) {
		r.err = ErrTruncated
		return nil
	}
	out := r.buf[r.off : r.off+n]
	r.off += n
	return out
}

func (r *reader) read(dst []byte) error {
	b := r.take(len(dst))
	if b == nil {
		return r.err
	}
	copy(dst, b)
	return nil
}

func (r *reader) u8() byte {
	b := r.take(1)
	if b == nil {
		return 0
	}
	return b[0]
}
func (r *reader) u16() uint16 {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint16(b)
}
func (r *reader) u32() uint32 {
	b := r.take(4)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(b)
}

func (r *reader) path() []PathElem {
	n := int(r.u16())
	if r.err != nil || n == 0 {
		return nil
	}
	if n > commitment.MaxDepth+1 { // guard against malicious length claims
		r.err = ErrTruncated
		return nil
	}
	p := make([]PathElem, 0, n)
	for i := 0; i < n; i++ {
		right := r.u8() == 1
		var sib Hash
		if err := r.read(sib[:]); err != nil {
			return nil
		}
		p = append(p, PathElem{Sibling: sib, Right: right})
	}
	return p
}

func (r *reader) fields() TxFields {
	n := int(r.u16())
	if r.err != nil || n == 0 {
		return nil
	}
	fs := make(TxFields, 0, n)
	for i := 0; i < n; i++ {
		idx := r.u8()
		ln := int(r.u16())
		b := r.take(ln)
		if r.err != nil {
			return nil
		}
		buf := make([]byte, ln)
		copy(buf, b)
		fs = append(fs, commitment.FieldLeaf{Index: idx, Bytes: buf})
	}
	return fs
}
