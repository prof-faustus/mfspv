//go:build !amd64 || noasm || appengine || !gc

package sha256mb

import "crypto/sha256"

// Size is the SHA-256 digest length.
const Size = 32

// Available reports whether the AVX-512 16-lane kernel runs on this CPU (no on non-amd64).
func Available() bool { return false }

// DoubleSHA256x16 computes SHA-256d of 16 messages (scalar fallback).
func DoubleSHA256x16(msgs *[16][64]byte, out *[16][Size]byte) {
	for i := 0; i < 16; i++ {
		h := sha256.Sum256(msgs[i][:])
		(*out)[i] = sha256.Sum256(h[:])
	}
}

// Hasher is the scalar fallback reusable 16-lane double-SHA-256 context.
type Hasher struct{}

// NewHasher returns a scalar fallback hasher.
func NewHasher() *Hasher { return &Hasher{} }

// DoubleSHA256x16 computes SHA-256d of 16 messages (scalar).
func (h *Hasher) DoubleSHA256x16(msgs *[16][64]byte, out *[16][Size]byte) {
	for i := 0; i < 16; i++ {
		x := sha256.Sum256(msgs[i][:])
		(*out)[i] = sha256.Sum256(x[:])
	}
}
