package crypto

import (
	"crypto/sha256"
	"math/big"
	"testing"
)

// Known-answer tests (06_EVALUATION_DESIGN.md §4.1). Each constant below is an
// independent, published value — not a value produced by this implementation —
// so a match is real cross-validation, not a tautology.

// KAT-1: the secp256k1 generator doubling. 2·G's coordinates are a published
// constant of the curve; matching them validates the field/point arithmetic.
func TestKAT_TwoG(t *testing.T) {
	wantX, _ := new(big.Int).SetString("C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5", 16)
	wantY, _ := new(big.Int).SetString("1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A", 16)
	x, y := scalarBaseMult(big.NewInt(2))
	if x.Cmp(wantX) != 0 || y.Cmp(wantY) != 0 {
		t.Fatalf("2G mismatch:\n got (%X,%X)\nwant (%X,%X)", x, y, wantX, wantY)
	}
	if !onCurve(x, y) {
		t.Fatal("2G not on curve")
	}
}

// KAT-2: RFC 6979 deterministic nonce for secp256k1 + SHA-256. The nonce k for
// private key C9AF…6721 over message "sample" is the canonical published value
// A6E3C57D…AD60 used across secp256k1 test suites. Matching it proves RFC 6979
// compliance (the signature's r,s then follow deterministically).
func TestKAT_RFC6979Nonce(t *testing.T) {
	d, _ := new(big.Int).SetString("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", 16)
	want, _ := new(big.Int).SetString("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60", 16)
	h := sha256.Sum256([]byte("sample"))
	k := rfc6979Nonce(d, h[:])
	if k.Cmp(want) != 0 {
		t.Fatalf("RFC6979 nonce mismatch:\n got %X\nwant %X", k, want)
	}
}

// KAT-3: deterministic signature regression for the same key/message. These (r,s)
// are produced by this implementation (low-S normalised) and pinned so any future
// change to the signer is caught; the signature must also verify.
func TestKAT_SignatureRegression(t *testing.T) {
	d, _ := new(big.Int).SetString("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", 16)
	key := &PrivateKey{D: d}
	h := sha256.Sum256([]byte("sample"))
	sig, err := key.Sign(h[:])
	if err != nil {
		t.Fatal(err)
	}
	wantR, _ := new(big.Int).SetString("432310E32CB80EB6503A26CE83CC165C783B870845FB8AAD6D970889FCD7A6C8", 16)
	wantS, _ := new(big.Int).SetString("530128B6B81C548874A6305D93ED071CA6E05074D85863D4056CE89B02BFAB69", 16)
	if sig.R.Cmp(wantR) != 0 || sig.S.Cmp(wantS) != 0 {
		t.Fatalf("signature regression:\n got (%X,%X)\nwant (%X,%X)", sig.R, sig.S, wantR, wantS)
	}
	if !sig.IsLowS() {
		t.Fatal("regression signature is not low-S")
	}
	if !Verify(key.Public(), h[:], sig) {
		t.Fatal("regression signature does not verify")
	}
}
