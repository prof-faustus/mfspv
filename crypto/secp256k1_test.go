package crypto

import (
	"crypto/sha256"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	for i := 0; i < 25; i++ {
		seed := sha256.Sum256([]byte{byte(i), 0xab})
		key, err := NewPrivateKey(seed[:])
		if err != nil {
			t.Fatal(err)
		}
		pub := key.Public()
		if !onCurve(pub.X, pub.Y) {
			t.Fatal("derived public key not on curve")
		}
		msg := sha256.Sum256([]byte{byte(i), 0x01, 0x02})
		sig, err := key.Sign(msg[:])
		if err != nil {
			t.Fatal(err)
		}
		if !Verify(pub, msg[:], sig) {
			t.Fatalf("i=%d valid signature rejected", i)
		}
		// wrong message must fail
		bad := msg
		bad[0] ^= 0x01
		if Verify(pub, bad[:], sig) {
			t.Fatalf("i=%d signature verified for wrong message", i)
		}
		// wrong key must fail
		seed2 := sha256.Sum256([]byte{byte(i), 0xcd})
		key2, _ := NewPrivateKey(seed2[:])
		if Verify(key2.Public(), msg[:], sig) {
			t.Fatalf("i=%d signature verified under wrong key", i)
		}
	}
}

func TestDeterministicNonce(t *testing.T) {
	seed := sha256.Sum256([]byte("determinism"))
	key, _ := NewPrivateKey(seed[:])
	msg := sha256.Sum256([]byte("same message"))
	s1, _ := key.Sign(msg[:])
	s2, _ := key.Sign(msg[:])
	if s1.R.Cmp(s2.R) != 0 || s1.S.Cmp(s2.S) != 0 {
		t.Fatal("RFC6979 signatures not deterministic")
	}
}

func TestLowS(t *testing.T) {
	seed := sha256.Sum256([]byte("low-s"))
	key, _ := NewPrivateKey(seed[:])
	for i := 0; i < 10; i++ {
		msg := sha256.Sum256([]byte{byte(i)})
		sig, _ := key.Sign(msg[:])
		if sig.S.Cmp(nHalf) > 0 {
			t.Fatal("signature is not low-S")
		}
	}
}

func TestSerializeRoundTrip(t *testing.T) {
	seed := sha256.Sum256([]byte("ser"))
	key, _ := NewPrivateKey(seed[:])
	msg := sha256.Sum256([]byte("m"))
	sig, _ := key.Sign(msg[:])
	parsed, err := ParseSignature(sig.Serialize())
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(key.Public(), msg[:], parsed) {
		t.Fatal("re-parsed signature failed to verify")
	}
}
