package crypto

// Constant-time secp256k1 scalar multiplication (the SAME secp256k1 curve as the
// rest of this package — only a side-channel-hardened implementation).
//
// It uses fixed 4x64-bit limb GF(p) arithmetic (no data-dependent branches or
// memory indexing), complete (exception-free) addition formulas for a=0
// (Renes-Costello-Batina 2016, Alg. 7), and a double-and-add-ALWAYS ladder with a
// masked constant-time point select. The secret scalar's bits drive only a masked
// select, never a branch. Field inversion is Fermat (exponent p-2 is public, so the
// square-multiply chain is constant by construction).
//
// Correctness is cross-checked against the big.Int reference (scalarBaseMult) by a
// differential oracle over random scalars (ct_test.go). Used by signing for the
// secret k*G step. NOTE (honest scope): the mod-n scalar steps of ECDSA still use
// math/big; for production, the node's audited libsecp256k1 remains recommended.

import (
	"encoding/binary"
	"math/big"
	"math/bits"
)

// feFromBig converts x (assumed in [0,p)) to a field element.
func feFromBig(x *big.Int) fe {
	var b [32]byte
	x.FillBytes(b[:])
	return fe{
		binary.BigEndian.Uint64(b[24:32]),
		binary.BigEndian.Uint64(b[16:24]),
		binary.BigEndian.Uint64(b[8:16]),
		binary.BigEndian.Uint64(b[0:8]),
	}
}

// big converts a field element to a big.Int.
func (f fe) big() *big.Int {
	var b [32]byte
	binary.BigEndian.PutUint64(b[24:32], f[0])
	binary.BigEndian.PutUint64(b[16:24], f[1])
	binary.BigEndian.PutUint64(b[8:16], f[2])
	binary.BigEndian.PutUint64(b[0:8], f[3])
	return new(big.Int).SetBytes(b[:])
}

// scalarBits returns k's low 256 bits as little-endian words.
func scalarBits(k *big.Int) [4]uint64 {
	var b [32]byte
	k.FillBytes(b[:])
	return [4]uint64{
		binary.BigEndian.Uint64(b[24:32]),
		binary.BigEndian.Uint64(b[16:24]),
		binary.BigEndian.Uint64(b[8:16]),
		binary.BigEndian.Uint64(b[0:8]),
	}
}

// p = 2^256 - 2^32 - 977; little-endian limbs.
var pl = [4]uint64{0xFFFFFFFEFFFFFC2F, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}

// feC = 2^256 mod p = 2^32 + 977.
const feC = 0x1000003D1

// fe is a GF(p) element, fully reduced to [0,p) after every exported op.
type fe [4]uint64

// feCondSubP returns a-p if a>=p else a (constant time).
func feCondSubP(a fe) fe {
	var r fe
	var b uint64
	r[0], b = bits.Sub64(a[0], pl[0], 0)
	r[1], b = bits.Sub64(a[1], pl[1], b)
	r[2], b = bits.Sub64(a[2], pl[2], b)
	r[3], b = bits.Sub64(a[3], pl[3], b)
	// b==0 => a>=p => choose r; b==1 => a<p => choose a.
	mask := b - 1 // 0->0xFFFF..(choose r); 1->0 (choose a)
	var out fe
	out[0] = (r[0] & mask) | (a[0] &^ mask)
	out[1] = (r[1] & mask) | (a[1] &^ mask)
	out[2] = (r[2] & mask) | (a[2] &^ mask)
	out[3] = (r[3] & mask) | (a[3] &^ mask)
	return out
}

func feAdd(a, b fe) fe {
	var r fe
	var c uint64
	r[0], c = bits.Add64(a[0], b[0], 0)
	r[1], c = bits.Add64(a[1], b[1], c)
	r[2], c = bits.Add64(a[2], b[2], c)
	r[3], c = bits.Add64(a[3], b[3], c)
	// fold the 2^256 carry (==> +c*feC), possibly twice.
	r[0], c = bits.Add64(r[0], c*feC, 0)
	r[1], c = bits.Add64(r[1], 0, c)
	r[2], c = bits.Add64(r[2], 0, c)
	r[3], c = bits.Add64(r[3], 0, c)
	r[0], c = bits.Add64(r[0], c*feC, 0)
	r[1], c = bits.Add64(r[1], 0, c)
	r[2], c = bits.Add64(r[2], 0, c)
	r[3], c = bits.Add64(r[3], 0, c)
	return feCondSubP(r)
}

func feSub(a, b fe) fe {
	var r fe
	var br uint64
	r[0], br = bits.Sub64(a[0], b[0], 0)
	r[1], br = bits.Sub64(a[1], b[1], br)
	r[2], br = bits.Sub64(a[2], b[2], br)
	r[3], br = bits.Sub64(a[3], b[3], br)
	// if borrow, add p (mask = 0-borrow).
	mask := uint64(0) - br
	var c uint64
	r[0], c = bits.Add64(r[0], pl[0]&mask, 0)
	r[1], c = bits.Add64(r[1], pl[1]&mask, c)
	r[2], c = bits.Add64(r[2], pl[2]&mask, c)
	r[3], c = bits.Add64(r[3], pl[3]&mask, c)
	_ = c
	return r
}

// mul256by64 returns a (4-limb) * b (64-bit) as 5 limbs.
func mul256by64(a [4]uint64, b uint64) [5]uint64 {
	var m [5]uint64
	var carry uint64
	for i := 0; i < 4; i++ {
		hi, lo := bits.Mul64(a[i], b)
		s, c := bits.Add64(lo, carry, 0)
		m[i] = s
		carry = hi + c
	}
	m[4] = carry
	return m
}

func feMul(a, b fe) fe {
	// schoolbook 4x4 -> 8 limbs
	var t [8]uint64
	for i := 0; i < 4; i++ {
		var carry uint64
		for j := 0; j < 4; j++ {
			hi, lo := bits.Mul64(a[i], b[j])
			s, c1 := bits.Add64(t[i+j], lo, 0)
			s, c2 := bits.Add64(s, carry, 0)
			t[i+j] = s
			carry = hi + c1 + c2
		}
		t[i+4] += carry
	}
	// reduce 512 -> 256 using 2^256 == feC (mod p)
	hi := [4]uint64{t[4], t[5], t[6], t[7]}
	m := mul256by64(hi, feC)
	var r fe
	var c uint64
	r[0], c = bits.Add64(t[0], m[0], 0)
	r[1], c = bits.Add64(t[1], m[1], c)
	r[2], c = bits.Add64(t[2], m[2], c)
	r[3], c = bits.Add64(t[3], m[3], c)
	r4 := m[4] + c
	// fold r4 (bits above 2^256): += r4*feC
	h4, l4 := bits.Mul64(r4, feC)
	r[0], c = bits.Add64(r[0], l4, 0)
	r[1], c = bits.Add64(r[1], h4, c)
	r[2], c = bits.Add64(r[2], 0, c)
	r[3], c = bits.Add64(r[3], 0, c)
	// fold any final carry
	r[0], c = bits.Add64(r[0], c*feC, 0)
	r[1], c = bits.Add64(r[1], 0, c)
	r[2], c = bits.Add64(r[2], 0, c)
	r[3], c = bits.Add64(r[3], 0, c)
	return feCondSubP(r)
}

func feSqr(a fe) fe { return feMul(a, a) }

// feInv returns a^(p-2) mod p (Fermat). Exponent is public => constant chain.
func feInv(a fe) fe {
	// p-2 little-endian limbs.
	exp := [4]uint64{0xFFFFFFFEFFFFFC2D, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}
	res := fe{1, 0, 0, 0}
	for word := 3; word >= 0; word-- {
		for bit := 63; bit >= 0; bit-- {
			res = feSqr(res)
			if (exp[word]>>uint(bit))&1 == 1 {
				res = feMul(res, a)
			}
		}
	}
	return res
}

func feIsZero(a fe) bool { return a[0]|a[1]|a[2]|a[3] == 0 }

// feCSelect returns a if choose==1 else b (constant time). choose must be 0 or 1.
func feCSelect(choose uint64, a, b fe) fe {
	mask := uint64(0) - choose
	return fe{
		(a[0] & mask) | (b[0] &^ mask),
		(a[1] & mask) | (b[1] &^ mask),
		(a[2] & mask) | (b[2] &^ mask),
		(a[3] & mask) | (b[3] &^ mask),
	}
}

// ---------------------------------------------------------------------------
// Projective point (X:Y:Z), x=X/Z. Identity = (0,1,0).
// ---------------------------------------------------------------------------

type jac struct{ X, Y, Z fe }

var feB3 = fe{21, 0, 0, 0} // 3*b, b=7

// completeAdd: Renes-Costello-Batina 2016 Algorithm 7 (a=0), exception-free.
func completeAdd(p, q jac) jac {
	X1, Y1, Z1 := p.X, p.Y, p.Z
	X2, Y2, Z2 := q.X, q.Y, q.Z
	t0 := feMul(X1, X2)
	t1 := feMul(Y1, Y2)
	t2 := feMul(Z1, Z2)
	t3 := feAdd(X1, Y1)
	t4 := feAdd(X2, Y2)
	t3 = feMul(t3, t4)
	t4 = feAdd(t0, t1)
	t3 = feSub(t3, t4)
	t4 = feAdd(Y1, Z1)
	X3 := feAdd(Y2, Z2)
	t4 = feMul(t4, X3)
	X3 = feAdd(t1, t2)
	t4 = feSub(t4, X3)
	X3 = feAdd(X1, Z1)
	Y3 := feAdd(X2, Z2)
	X3 = feMul(X3, Y3)
	Y3 = feAdd(t0, t2)
	Y3 = feSub(X3, Y3)
	X3 = feAdd(t0, t0)
	t0 = feAdd(X3, t0)
	t2 = feMul(feB3, t2)
	Z3 := feAdd(t1, t2)
	t1 = feSub(t1, t2)
	Y3 = feMul(feB3, Y3)
	X3 = feMul(t4, Y3)
	t2 = feMul(t3, t1)
	X3 = feSub(t2, X3)
	Y3 = feMul(Y3, t0)
	t1 = feMul(t1, Z3)
	Y3 = feAdd(t1, Y3)
	t0 = feMul(t0, t3)
	Z3 = feMul(Z3, t4)
	Z3 = feAdd(Z3, t0)
	return jac{X3, Y3, Z3}
}

func jacCSelect(choose uint64, a, b jac) jac {
	return jac{feCSelect(choose, a.X, b.X), feCSelect(choose, a.Y, b.Y), feCSelect(choose, a.Z, b.Z)}
}

var identity = jac{fe{0, 0, 0, 0}, fe{1, 0, 0, 0}, fe{0, 0, 0, 0}}

// ctBaseG is the generator in projective coordinates, for constant-time signing.
var ctBaseG = jac{feFromBig(curveGx), feFromBig(curveGy), fe{1, 0, 0, 0}}

// scalarMultCT computes k*P over fixed 256 bits, double-and-add-always with a
// masked select — constant control flow regardless of the secret bits of k.
func scalarMultCT(kBits [4]uint64, P jac) jac {
	R := identity
	for word := 3; word >= 0; word-- {
		for bit := 63; bit >= 0; bit-- {
			R = completeAdd(R, R)
			T := completeAdd(R, P)
			b := (kBits[word] >> uint(bit)) & 1
			R = jacCSelect(b, T, R)
		}
	}
	return R
}

// affineXBytes returns the affine x-coordinate of a projective point as 32 BE bytes.
func (P jac) affineX() fe {
	zi := feInv(P.Z)
	return feMul(P.X, zi)
}

func (P jac) affineXY() (fe, fe) {
	zi := feInv(P.Z)
	return feMul(P.X, zi), feMul(P.Y, zi)
}
