package bench

// Real Lever-A backend using minio/sha256-simd — an audited, hardware-dispatched
// SHA-256 (SHA-NI on x86 with the extension, ARMv8 crypto on arm64, AVX fallback).
// This is a REAL accelerated backend, not a placeholder; verification output is
// identical SHA-256d (asserted by KAT in backend_minio_test.go). BSV only.

import (
	msha "github.com/minio/sha256-simd"

	"mfspv/commitment"
)

// minioHashPair computes SHA-256d(l ‖ r) via the minio hardware-dispatched engine.
func minioHashPair(l, r commitment.Hash) commitment.Hash {
	var buf [64]byte
	copy(buf[:32], l[:])
	copy(buf[32:], r[:])
	h1 := msha.Sum256(buf[:])
	return commitment.Hash(msha.Sum256(h1[:]))
}

// MinioBackend is the audited hardware-dispatched SHA-256d backend (Lever A).
func MinioBackend() Backend {
	return Backend{
		Name:     "minio-sha-ni",
		HashPair: minioHashPair,
		HashPairBatch: func(l, r, out []commitment.Hash) {
			for i := range out {
				out[i] = minioHashPair(l[i], r[i])
			}
		},
		Lanes: 1,
	}
}
