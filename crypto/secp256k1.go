// Package crypto is a self-contained secp256k1 ECDSA implementation (the BSV
// signature curve), with RFC 6979 deterministic nonces and low-S normalisation.
//
// It exists so wallet_alice / wallet_bob can sign and verify with ZERO external
// dependencies (the module builds and tests offline). Arithmetic uses math/big
// and is therefore NOT constant-time; constant-time hardening is a production
// task and is noted here, not hidden. The MF-SPV security claims (inclusion
// soundness) rest on the Merkle layer, not on this signer; this provides the
// spend-authorisation that the push protocol requires.
//
// BSV only: secp256k1, the curve of the original Bitcoin protocol.
package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"math/big"
)

// secp256k1 domain parameters.
var (
	curveP  = mustHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
	curveN  = mustHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	curveB  = big.NewInt(7)
	curveGx = mustHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	curveGy = mustHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
	nHalf   = new(big.Int).Rsh(curveN, 1)
)

func mustHex(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("crypto: bad constant " + s)
	}
	return n
}

// PrivateKey is a secp256k1 scalar in [1, n-1].
type PrivateKey struct{ D *big.Int }

// PublicKey is a point on secp256k1.
type PublicKey struct{ X, Y *big.Int }

// Errors.
var (
	ErrInvalidKey = errors.New("crypto: invalid private key")
	ErrSign       = errors.New("crypto: signing failed")
)

// ---------------------------------------------------------------------------
// Point arithmetic (affine, big.Int).
// ---------------------------------------------------------------------------

func isInfinity(x, y *big.Int) bool { return x == nil && y == nil }

func pointDouble(x1, y1 *big.Int) (*big.Int, *big.Int) {
	if isInfinity(x1, y1) || y1.Sign() == 0 {
		return nil, nil
	}
	// lambda = 3x^2 / 2y   (a = 0)
	num := new(big.Int).Mul(x1, x1)
	num.Mul(num, big.NewInt(3))
	den := new(big.Int).Lsh(y1, 1)
	den.ModInverse(den, curveP)
	lam := num.Mul(num, den)
	lam.Mod(lam, curveP)

	x3 := new(big.Int).Mul(lam, lam)
	x3.Sub(x3, new(big.Int).Lsh(x1, 1))
	x3.Mod(x3, curveP)

	y3 := new(big.Int).Sub(x1, x3)
	y3.Mul(y3, lam)
	y3.Sub(y3, y1)
	y3.Mod(y3, curveP)
	return x3, y3
}

func pointAdd(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	if isInfinity(x1, y1) {
		return x2, y2
	}
	if isInfinity(x2, y2) {
		return x1, y1
	}
	if x1.Cmp(x2) == 0 {
		if y1.Cmp(y2) == 0 {
			return pointDouble(x1, y1)
		}
		return nil, nil // P + (-P) = infinity
	}
	// lambda = (y2 - y1)/(x2 - x1)
	num := new(big.Int).Sub(y2, y1)
	den := new(big.Int).Sub(x2, x1)
	den.ModInverse(den, curveP)
	lam := num.Mul(num, den)
	lam.Mod(lam, curveP)

	x3 := new(big.Int).Mul(lam, lam)
	x3.Sub(x3, x1)
	x3.Sub(x3, x2)
	x3.Mod(x3, curveP)

	y3 := new(big.Int).Sub(x1, x3)
	y3.Mul(y3, lam)
	y3.Sub(y3, y1)
	y3.Mod(y3, curveP)
	return x3, y3
}

func scalarMult(k *big.Int, x, y *big.Int) (*big.Int, *big.Int) {
	var rx, ry *big.Int // infinity
	for i := k.BitLen() - 1; i >= 0; i-- {
		rx, ry = pointDouble(rx, ry)
		if k.Bit(i) == 1 {
			rx, ry = pointAdd(rx, ry, x, y)
		}
	}
	return rx, ry
}

func scalarBaseMult(k *big.Int) (*big.Int, *big.Int) {
	return scalarMult(k, curveGx, curveGy)
}

// onCurve reports whether (x,y) satisfies y^2 = x^3 + 7 (mod p) and is in field range.
func onCurve(x, y *big.Int) bool {
	if x == nil || y == nil {
		return false
	}
	if x.Sign() < 0 || y.Sign() < 0 || x.Cmp(curveP) >= 0 || y.Cmp(curveP) >= 0 {
		return false
	}
	lhs := new(big.Int).Mul(y, y)
	lhs.Mod(lhs, curveP)
	rhs := new(big.Int).Mul(x, x)
	rhs.Mul(rhs, x)
	rhs.Add(rhs, curveB)
	rhs.Mod(rhs, curveP)
	return lhs.Cmp(rhs) == 0
}

// ---------------------------------------------------------------------------
// Keys.
// ---------------------------------------------------------------------------

// NewPrivateKey derives a private key from 32 bytes of entropy (interpreted as a
// big-endian scalar, reduced into [1, n-1]).
func NewPrivateKey(seed []byte) (*PrivateKey, error) {
	d := new(big.Int).SetBytes(seed)
	d.Mod(d, new(big.Int).Sub(curveN, big.NewInt(1)))
	d.Add(d, big.NewInt(1)) // ensure 1 <= d <= n-1
	return &PrivateKey{D: d}, nil
}

// Public returns the public key for a private key.
func (k *PrivateKey) Public() *PublicKey {
	x, y := scalarBaseMult(k.D)
	return &PublicKey{X: x, Y: y}
}

// SerializeCompressed returns the 33-byte compressed public key (0x02/0x03 ‖ X).
func (p *PublicKey) SerializeCompressed() []byte {
	out := make([]byte, 33)
	if p.Y.Bit(0) == 0 {
		out[0] = 0x02
	} else {
		out[0] = 0x03
	}
	xb := p.X.Bytes()
	copy(out[33-len(xb):], xb)
	return out
}

// ParseCompressed decompresses a 33-byte compressed public key (0x02/0x03 ‖ X),
// recovering Y by solving y^2 = x^3 + 7 (mod p) and selecting the parity.
func ParseCompressed(b []byte) (*PublicKey, error) {
	if len(b) != 33 || (b[0] != 0x02 && b[0] != 0x03) {
		return nil, errors.New("crypto: bad compressed public key")
	}
	x := new(big.Int).SetBytes(b[1:])
	if x.Cmp(curveP) >= 0 {
		return nil, errors.New("crypto: x out of field range")
	}
	// y^2 = x^3 + 7
	rhs := new(big.Int).Mul(x, x)
	rhs.Mul(rhs, x)
	rhs.Add(rhs, curveB)
	rhs.Mod(rhs, curveP)
	// y = rhs^((p+1)/4) mod p  (p ≡ 3 mod 4 for secp256k1)
	exp := new(big.Int).Add(curveP, big.NewInt(1))
	exp.Rsh(exp, 2)
	y := new(big.Int).Exp(rhs, exp, curveP)
	// verify it is a real square root
	chk := new(big.Int).Mul(y, y)
	chk.Mod(chk, curveP)
	if chk.Cmp(rhs) != 0 {
		return nil, errors.New("crypto: point not on curve")
	}
	wantOdd := b[0] == 0x03
	if (y.Bit(0) == 1) != wantOdd {
		y.Sub(curveP, y)
	}
	pub := &PublicKey{X: x, Y: y}
	if !onCurve(pub.X, pub.Y) {
		return nil, errors.New("crypto: decompressed point not on curve")
	}
	return pub, nil
}

// Equal reports key equality in constant time over the serialised form.
func (p *PublicKey) Equal(other *PublicKey) bool {
	if p == nil || other == nil {
		return false
	}
	return subtle.ConstantTimeCompare(p.SerializeCompressed(), other.SerializeCompressed()) == 1
}

// ---------------------------------------------------------------------------
// RFC 6979 deterministic nonce.
// ---------------------------------------------------------------------------

func rfc6979Nonce(d *big.Int, hash []byte) *big.Int {
	holen := sha256.Size
	rolen := 32
	bx := append(int2octets(d, rolen), bits2octets(hash, rolen)...)

	v := bytes_repeat(0x01, holen)
	kk := bytes_repeat(0x00, holen)

	kk = hmacSHA(kk, concat(v, []byte{0x00}, bx))
	v = hmacSHA(kk, v)
	kk = hmacSHA(kk, concat(v, []byte{0x01}, bx))
	v = hmacSHA(kk, v)

	for {
		var t []byte
		for len(t) < rolen {
			v = hmacSHA(kk, v)
			t = append(t, v...)
		}
		k := bits2int(t, rolen*8)
		if k.Sign() > 0 && k.Cmp(curveN) < 0 {
			return k
		}
		kk = hmacSHA(kk, append(v, 0x00))
		v = hmacSHA(kk, v)
	}
}

func hmacSHA(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

func bytes_repeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func int2octets(v *big.Int, rolen int) []byte {
	b := v.Bytes()
	if len(b) < rolen {
		pad := make([]byte, rolen-len(b))
		return append(pad, b...)
	}
	if len(b) > rolen {
		return b[len(b)-rolen:]
	}
	return b
}

func bits2int(b []byte, qlen int) *big.Int {
	v := new(big.Int).SetBytes(b)
	if len(b)*8 > qlen {
		v.Rsh(v, uint(len(b)*8-qlen))
	}
	return v
}

func bits2octets(b []byte, rolen int) []byte {
	z1 := bits2int(b, curveN.BitLen())
	z2 := new(big.Int).Sub(z1, curveN)
	if z2.Sign() < 0 {
		return int2octets(z1, rolen)
	}
	return int2octets(z2, rolen)
}

// ---------------------------------------------------------------------------
// Sign / Verify.
// ---------------------------------------------------------------------------

// Signature is a (r,s) pair, serialised as 64 big-endian bytes (32‖32).
type Signature struct{ R, S *big.Int }

// Sign produces a deterministic (RFC 6979), low-S ECDSA signature over a 32-byte
// message hash.
func (k *PrivateKey) Sign(hash []byte) (*Signature, error) {
	if k == nil || k.D == nil || k.D.Sign() == 0 || k.D.Cmp(curveN) >= 0 {
		return nil, ErrInvalidKey
	}
	z := bits2int(hash, curveN.BitLen())
	for i := 0; i < 1000; i++ {
		kNonce := rfc6979Nonce(k.D, hash)
		if i > 0 { // extremely unlikely retry path; perturb deterministically
			kNonce = rfc6979Nonce(k.D, sha256sum(append(hash, byte(i))))
		}
		rx, _ := scalarBaseMult(kNonce)
		r := new(big.Int).Mod(rx, curveN)
		if r.Sign() == 0 {
			continue
		}
		kInv := new(big.Int).ModInverse(kNonce, curveN)
		s := new(big.Int).Mul(r, k.D)
		s.Add(s, z)
		s.Mul(s, kInv)
		s.Mod(s, curveN)
		if s.Sign() == 0 {
			continue
		}
		if s.Cmp(nHalf) > 0 { // low-S normalisation (BSV policy)
			s.Sub(curveN, s)
		}
		return &Signature{R: r, S: s}, nil
	}
	return nil, ErrSign
}

// Verify reports whether sig is a valid signature of hash under pub.
func Verify(pub *PublicKey, hash []byte, sig *Signature) bool {
	if pub == nil || sig == nil || sig.R == nil || sig.S == nil {
		return false
	}
	if !onCurve(pub.X, pub.Y) {
		return false
	}
	if sig.R.Sign() <= 0 || sig.R.Cmp(curveN) >= 0 || sig.S.Sign() <= 0 || sig.S.Cmp(curveN) >= 0 {
		return false
	}
	z := bits2int(hash, curveN.BitLen())
	w := new(big.Int).ModInverse(sig.S, curveN)
	u1 := new(big.Int).Mul(z, w)
	u1.Mod(u1, curveN)
	u2 := new(big.Int).Mul(sig.R, w)
	u2.Mod(u2, curveN)

	x1, y1 := scalarBaseMult(u1)
	x2, y2 := scalarMult(u2, pub.X, pub.Y)
	x, _ := pointAdd(x1, y1, x2, y2)
	if x == nil {
		return false
	}
	x.Mod(x, curveN)
	return x.Cmp(sig.R) == 0
}

// IsLowS reports whether S is in the lower half of the curve order (S <= n/2).
// Non-low-S signatures are malleable (n-S is also valid); canonical verifiers
// reject them to prevent transaction-ID malleability.
func (s *Signature) IsLowS() bool {
	if s == nil || s.S == nil {
		return false
	}
	return s.S.Cmp(nHalf) <= 0
}

// Serialize returns the 64-byte (R‖S) form.
func (s *Signature) Serialize() []byte {
	out := make([]byte, 64)
	rb := s.R.Bytes()
	sb := s.S.Bytes()
	copy(out[32-len(rb):32], rb)
	copy(out[64-len(sb):], sb)
	return out
}

// Malleate returns the other valid form of a signature, (R, n-S). It is the
// canonical malleability transform: the result verifies identically under raw
// ECDSA but has the opposite low-S parity. Exposed so callers can test that they
// reject non-canonical signatures.
func Malleate(sig64 []byte) ([]byte, error) {
	s, err := ParseSignature(sig64)
	if err != nil {
		return nil, err
	}
	ns := new(big.Int).Sub(curveN, s.S)
	return (&Signature{R: s.R, S: ns}).Serialize(), nil
}

// ParseSignature parses a 64-byte (R‖S) signature.
func ParseSignature(b []byte) (*Signature, error) {
	if len(b) != 64 {
		return nil, errors.New("crypto: signature must be 64 bytes")
	}
	return &Signature{
		R: new(big.Int).SetBytes(b[:32]),
		S: new(big.Int).SetBytes(b[32:]),
	}, nil
}

func sha256sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
