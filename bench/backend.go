package bench

// Lever A — pluggable SHA-256d hashing backend (07_VERIFICATION_FABRIC.md §4).
//
// The verifier's per-proof work is intrinsic (D = ceil(log2 T) SHA-256d compressions
// on the consensus path); what is free to redesign is HOW those hashes are computed.
// This file defines one interface with capability-selected implementations:
//
//   - software     : Go crypto/sha256 single-message (commitment.HashPair). On a CPU
//                    WITH SHA extensions Go already emits SHA-NI here, so "software"
//                    is the best single-message path the box can do; on a CPU without
//                    them it is the pure-software path (the measured anchor).
//   - multibuf     : an N-way multi-buffer interface (AVX2/AVX-512 would hash 8/16
//                    INDEPENDENT messages per lane-stream). A true SIMD backend is an
//                    assembly/cgo task; here we provide the interface and a correct
//                    SCALAR stand-in so the batch verifier and benchmark are real and
//                    measured. The asm backend is the documented accelerator; this
//                    file never claims a speedup it did not measure.
//
// Verification output is identical across backends (same SHA-256d). BSV only.

import "mfspv/commitment"

// HashPairFn computes the internal-node hash SHA-256d(left ‖ right).
type HashPairFn func(l, r commitment.Hash) commitment.Hash

// Backend is a capability-selected SHA-256d engine.
type Backend struct {
	Name     string
	HashPair HashPairFn
	// HashPairBatch hashes k independent (l,r) pairs into out[0:k]. A SIMD backend
	// overrides this with a multi-buffer kernel; the scalar stand-in loops HashPair.
	HashPairBatch func(l, r, out []commitment.Hash)
	Lanes         int // independent messages per multi-buffer call (1 for software)
}

// SoftwareBackend is the measured single-message path (SHA-NI if the CPU exposes it).
func SoftwareBackend() Backend {
	return Backend{
		Name:     "software",
		HashPair: commitment.HashPair,
		HashPairBatch: func(l, r, out []commitment.Hash) {
			for i := range out {
				out[i] = commitment.HashPair(l[i], r[i])
			}
		},
		Lanes: 1,
	}
}

// MultiBufScalarBackend is the N-way multi-buffer INTERFACE with a correct scalar
// implementation (no SIMD speedup). It exists so the batch verifier exercises the
// multi-message API and the benchmark can be wired to a real asm/cgo backend by
// replacing HashPairBatch. lanes documents the intended SIMD width.
func MultiBufScalarBackend(lanes int) Backend {
	if lanes < 1 {
		lanes = 8
	}
	b := SoftwareBackend()
	b.Name = "multibuf-scalar(x" + itoa(lanes) + ")"
	b.Lanes = lanes
	return b
}

// AvailableBackends returns the backends to benchmark on this box. The AVX2/AVX-512
// multi-buffer asm backend is NOT registered here (unimplemented); when added it
// appends with Lanes 8/16 and its own HashPairBatch. SHA-NI is not a separate entry
// because Go folds it into the software path automatically; CapabilityNote() records
// whether the measured rate indicates hardware acceleration.
func AvailableBackends() []Backend {
	return []Backend{SoftwareBackend(), MinioBackend()}
}

// ShaSoftwareReference is a conservative pure-software SHA-256d/s/core figure used
// only to flag whether the measured rate indicates hardware SHA acceleration.
const ShaSoftwareReference = 6_000_000.0

// CapabilityNote measures the box's single-core SHA-256d rate and reports whether it
// looks hardware-accelerated (SHA-NI/ARMv8-crypto present) or pure software.
func CapabilityNote() (perCoreRate float64, note string) {
	perCoreRate = HashRatePerSec(0)
	if perCoreRate > 3*ShaSoftwareReference {
		note = "hardware SHA acceleration present (SHA-NI / ARMv8-crypto) — rate >> software reference"
	} else {
		note = "pure-software SHA-256d path (no SHA-NI exposed) — the unaccelerated anchor"
	}
	return
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
