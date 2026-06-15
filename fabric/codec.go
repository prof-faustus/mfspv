package fabric

import (
	"encoding/binary"
	"errors"
)

// Wire codec for inclusion proofs — the REAL bytes a payer pushes to a verifier
// (07 §5: leaf = consensus TXID; the object carries TXID + L1 + L2 + header).
// Benchmarks decode from these bytes before verifying, so the measured cost is the
// real end-to-end path (deserialize + verify), not a hash-only microbenchmark.
//
// Per proof: Leaf[32] | L1count u8 | L1[ Right u8, Sib[32] ]* | SubtreeRoot[32]
//            | L2count u8 | L2[ Right u8, Sib[32] ]* | Header[80]
// A batch is the length-prefixed concatenation: count u32, then each proof
// length-prefixed (u32) for independent decoding.

var errTruncated = errors.New("fabric: truncated proof bytes")

// EncodeProof appends the wire encoding of p to dst.
func EncodeProof(dst []byte, p *Proof) []byte {
	dst = append(dst, p.Leaf[:]...)
	dst = append(dst, byte(len(p.L1)))
	for i := range p.L1 {
		if p.L1[i].Right {
			dst = append(dst, 1)
		} else {
			dst = append(dst, 0)
		}
		dst = append(dst, p.L1[i].Sibling[:]...)
	}
	dst = append(dst, p.SubtreeRoot[:]...)
	dst = append(dst, byte(len(p.L2)))
	for i := range p.L2 {
		if p.L2[i].Right {
			dst = append(dst, 1)
		} else {
			dst = append(dst, 0)
		}
		dst = append(dst, p.L2[i].Sibling[:]...)
	}
	dst = append(dst, p.Header[:]...)
	return dst
}

// EncodeBatch serialises a batch of proofs (length-prefixed).
func EncodeBatch(proofs []Proof) []byte {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, uint32(len(proofs)))
	for i := range proofs {
		var pb []byte
		pb = EncodeProof(pb, &proofs[i])
		var lp [4]byte
		binary.LittleEndian.PutUint32(lp[:], uint32(len(pb)))
		out = append(out, lp[:]...)
		out = append(out, pb...)
	}
	return out
}

// decoder is a bounds-checked reader over a byte slice.
type decoder struct {
	b   []byte
	off int
}

func (d *decoder) take(n int) ([]byte, bool) {
	if n < 0 || d.off+n > len(d.b) {
		return nil, false
	}
	s := d.b[d.off : d.off+n]
	d.off += n
	return s, true
}

func decodePath(d *decoder) ([]PathElem, bool) {
	cb, ok := d.take(1)
	if !ok {
		return nil, false
	}
	n := int(cb[0])
	if n == 0 {
		return nil, true
	}
	if n > 64 { // depth ceiling guard (>255 impossible; subtree<=20, block modest)
		return nil, false
	}
	p := make([]PathElem, n)
	for i := 0; i < n; i++ {
		rb, ok := d.take(1)
		if !ok {
			return nil, false
		}
		sb, ok := d.take(32)
		if !ok {
			return nil, false
		}
		p[i].Right = rb[0] == 1
		copy(p[i].Sibling[:], sb)
	}
	return p, true
}

// DecodeProof decodes one proof from d.
func decodeProof(d *decoder) (Proof, bool) {
	var p Proof
	s, ok := d.take(32)
	if !ok {
		return p, false
	}
	copy(p.Leaf[:], s)
	if p.L1, ok = decodePath(d); !ok {
		return p, false
	}
	if s, ok = d.take(32); !ok {
		return p, false
	}
	copy(p.SubtreeRoot[:], s)
	if p.L2, ok = decodePath(d); !ok {
		return p, false
	}
	if s, ok = d.take(80); !ok {
		return p, false
	}
	copy(p.Header[:], s)
	return p, true
}

// DecodeBatch decodes a batch produced by EncodeBatch into dst (reused across calls
// to avoid re-allocating the outer slice). Returns the decoded proofs.
func DecodeBatch(data []byte, dst []Proof) ([]Proof, error) {
	if len(data) < 4 {
		return nil, errTruncated
	}
	n := int(binary.LittleEndian.Uint32(data[:4]))
	d := &decoder{b: data, off: 4}
	if cap(dst) < n {
		dst = make([]Proof, 0, n)
	}
	dst = dst[:0]
	for i := 0; i < n; i++ {
		lp, ok := d.take(4)
		if !ok {
			return nil, errTruncated
		}
		plen := int(binary.LittleEndian.Uint32(lp))
		pb, ok := d.take(plen)
		if !ok {
			return nil, errTruncated
		}
		pd := &decoder{b: pb}
		p, ok := decodeProof(pd)
		if !ok {
			return nil, errTruncated
		}
		dst = append(dst, p)
	}
	return dst, nil
}
