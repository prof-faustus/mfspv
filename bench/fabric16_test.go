package bench

import "testing"

// The 16-lane AVX-512 lockstep fold must verify a valid batch exactly and reject
// tampering — identical SHA-256d semantics to the scalar path (the kernel is KAT
// byte-identical; here we check the verifier built on it).
func TestFabric16Correctness(t *testing.T) {
	const P, S = 4096, 16
	proofs := BuildBatch(43, P, S)
	if got := CountValid16(proofs); got != P {
		t.Fatalf("valid batch: CountValid16=%d want %d (AVX512=%v)", got, P, Avx512Available())
	}
	// tamper one leaf -> that proof (and only it) must fail.
	proofs[100].Leaf[0] ^= 0xff
	if got := CountValid16(proofs); got != P-1 {
		t.Fatalf("tampered batch: CountValid16=%d want %d", got, P-1)
	}
}
