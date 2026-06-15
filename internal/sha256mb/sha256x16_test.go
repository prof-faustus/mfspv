package sha256mb

import (
	"crypto/sha256"
	"math/rand"
	"testing"
	"time"
)

func refDouble(m []byte) [32]byte { h := sha256.Sum256(m); return sha256.Sum256(h[:]) }

func TestDoubleSHA256x16KAT(t *testing.T) {
	if !Available() {
		t.Log("AVX-512 not available; testing scalar fallback path")
	}
	rng := rand.New(rand.NewSource(1))
	for iter := 0; iter < 20000; iter++ {
		var msgs [16][64]byte
		for i := range msgs {
			rng.Read(msgs[i][:])
		}
		var out [16][32]byte
		DoubleSHA256x16(&msgs, &out)
		for i := 0; i < 16; i++ {
			if out[i] != refDouble(msgs[i][:]) {
				t.Fatalf("lane %d mismatch at iter %d", i, iter)
			}
		}
	}
}

func TestThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	var msgs [16][64]byte
	for i := range msgs {
		msgs[i][0] = byte(i)
	}
	var out [16][32]byte
	N := 2_000_000
	st := time.Now()
	for i := 0; i < N; i++ {
		DoubleSHA256x16(&msgs, &out)
	}
	el := time.Since(st)
	perHash := float64(N*16) / el.Seconds()
	t.Logf("AVX512=%v  1-core: %.3e double-sha/s (%.1f M HashPair/s/core)", Available(), perHash, perHash/1e6)
}
