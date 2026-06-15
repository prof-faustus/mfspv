package crypto

import (
	"math/big"
	"math/rand"
	"testing"
)

// randFe returns a random field element in [0,p) plus its big.Int.
func randFe(rng *rand.Rand) (fe, *big.Int) {
	x := new(big.Int).Rand(rng, curveP)
	return feFromBig(x), x
}

// Field arithmetic must agree with big.Int mod p over many random inputs.
func TestFieldVsBigInt(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	for i := 0; i < 200000; i++ {
		fa, a := randFe(rng)
		fb, b := randFe(rng)

		if got := feAdd(fa, fb).big(); got.Cmp(new(big.Int).Mod(new(big.Int).Add(a, b), curveP)) != 0 {
			t.Fatalf("add mismatch at %d", i)
		}
		if got := feSub(fa, fb).big(); got.Cmp(new(big.Int).Mod(new(big.Int).Sub(a, b), curveP)) != 0 {
			t.Fatalf("sub mismatch at %d", i)
		}
		if got := feMul(fa, fb).big(); got.Cmp(new(big.Int).Mod(new(big.Int).Mul(a, b), curveP)) != 0 {
			t.Fatalf("mul mismatch at %d", i)
		}
	}
}

// Fermat inverse must match big.Int ModInverse.
func TestFieldInverse(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 5000; i++ {
		fa, a := randFe(rng)
		if a.Sign() == 0 {
			continue
		}
		want := new(big.Int).ModInverse(a, curveP)
		if got := feInv(fa).big(); got.Cmp(want) != 0 {
			t.Fatalf("inv mismatch at %d", i)
		}
	}
}

// Differential oracle: the constant-time scalar multiplication must equal the
// big.Int reference scalarBaseMult for random scalars (the core correctness gate).
func TestScalarMultCTvsReference(t *testing.T) {
	rng := rand.New(rand.NewSource(2024))
	G := jac{feFromBig(curveGx), feFromBig(curveGy), fe{1, 0, 0, 0}}
	for i := 0; i < 2000; i++ {
		k := new(big.Int).Rand(rng, curveN)
		if k.Sign() == 0 {
			k.SetInt64(1)
		}
		R := scalarMultCT(scalarBits(k), G)
		x, y := R.affineXY()
		wx, wy := scalarBaseMult(k)
		if x.big().Cmp(wx) != 0 || y.big().Cmp(wy) != 0 {
			t.Fatalf("scalarMultCT mismatch at i=%d k=%x", i, k)
		}
	}
}

// KAT: 2*G via the constant-time path matches the published constant.
func TestCTTwoG(t *testing.T) {
	G := jac{feFromBig(curveGx), feFromBig(curveGy), fe{1, 0, 0, 0}}
	R := scalarMultCT(scalarBits(big.NewInt(2)), G)
	x, y := R.affineXY()
	wantX, _ := new(big.Int).SetString("C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5", 16)
	wantY, _ := new(big.Int).SetString("1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A", 16)
	if x.big().Cmp(wantX) != 0 || y.big().Cmp(wantY) != 0 {
		t.Fatal("constant-time 2G mismatch")
	}
}
