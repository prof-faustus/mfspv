// Package sha256mb provides 16-way multi-buffer SHA-256d using the AVX-512 16-lane
// kernel, driven SYNCHRONOUSLY (no channels) to batch 16 independent Merkle-fold
// hashes per call. The assembly kernel (sha256x16_amd64.s) and the round table below
// are VENDORED VERBATIM from github.com/minio/sha256-simd v1.0.1 (Apache-2.0) — an
// audited implementation, not hand-written. Output is byte-identical to crypto/sha256
// (asserted by KAT in sha256x16_test.go). BSV only.

//go:build amd64 && !noasm && !appengine && gc

package sha256mb

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/klauspost/cpuid/v2"
)

// Size is the SHA-256 digest length.
const Size = 32

// SHA-256 initial hash values.
const (
	init0 = 0x6A09E667
	init1 = 0xBB67AE85
	init2 = 0x3C6EF372
	init3 = 0xA54FF53A
	init4 = 0x510E527F
	init5 = 0x9B05688C
	init6 = 0x1F83D9AB
	init7 = 0x5BE0CD19
)

//go:noescape
func sha256X16Avx512(digests *[512]byte, scratch *[512]byte, table *[512]uint64, mask []uint64, inputs [16][]byte)

var table = [512]uint64{
	0x428a2f98428a2f98, 0x428a2f98428a2f98, 0x428a2f98428a2f98, 0x428a2f98428a2f98,
	0x428a2f98428a2f98, 0x428a2f98428a2f98, 0x428a2f98428a2f98, 0x428a2f98428a2f98,
	0x7137449171374491, 0x7137449171374491, 0x7137449171374491, 0x7137449171374491,
	0x7137449171374491, 0x7137449171374491, 0x7137449171374491, 0x7137449171374491,
	0xb5c0fbcfb5c0fbcf, 0xb5c0fbcfb5c0fbcf, 0xb5c0fbcfb5c0fbcf, 0xb5c0fbcfb5c0fbcf,
	0xb5c0fbcfb5c0fbcf, 0xb5c0fbcfb5c0fbcf, 0xb5c0fbcfb5c0fbcf, 0xb5c0fbcfb5c0fbcf,
	0xe9b5dba5e9b5dba5, 0xe9b5dba5e9b5dba5, 0xe9b5dba5e9b5dba5, 0xe9b5dba5e9b5dba5,
	0xe9b5dba5e9b5dba5, 0xe9b5dba5e9b5dba5, 0xe9b5dba5e9b5dba5, 0xe9b5dba5e9b5dba5,
	0x3956c25b3956c25b, 0x3956c25b3956c25b, 0x3956c25b3956c25b, 0x3956c25b3956c25b,
	0x3956c25b3956c25b, 0x3956c25b3956c25b, 0x3956c25b3956c25b, 0x3956c25b3956c25b,
	0x59f111f159f111f1, 0x59f111f159f111f1, 0x59f111f159f111f1, 0x59f111f159f111f1,
	0x59f111f159f111f1, 0x59f111f159f111f1, 0x59f111f159f111f1, 0x59f111f159f111f1,
	0x923f82a4923f82a4, 0x923f82a4923f82a4, 0x923f82a4923f82a4, 0x923f82a4923f82a4,
	0x923f82a4923f82a4, 0x923f82a4923f82a4, 0x923f82a4923f82a4, 0x923f82a4923f82a4,
	0xab1c5ed5ab1c5ed5, 0xab1c5ed5ab1c5ed5, 0xab1c5ed5ab1c5ed5, 0xab1c5ed5ab1c5ed5,
	0xab1c5ed5ab1c5ed5, 0xab1c5ed5ab1c5ed5, 0xab1c5ed5ab1c5ed5, 0xab1c5ed5ab1c5ed5,
	0xd807aa98d807aa98, 0xd807aa98d807aa98, 0xd807aa98d807aa98, 0xd807aa98d807aa98,
	0xd807aa98d807aa98, 0xd807aa98d807aa98, 0xd807aa98d807aa98, 0xd807aa98d807aa98,
	0x12835b0112835b01, 0x12835b0112835b01, 0x12835b0112835b01, 0x12835b0112835b01,
	0x12835b0112835b01, 0x12835b0112835b01, 0x12835b0112835b01, 0x12835b0112835b01,
	0x243185be243185be, 0x243185be243185be, 0x243185be243185be, 0x243185be243185be,
	0x243185be243185be, 0x243185be243185be, 0x243185be243185be, 0x243185be243185be,
	0x550c7dc3550c7dc3, 0x550c7dc3550c7dc3, 0x550c7dc3550c7dc3, 0x550c7dc3550c7dc3,
	0x550c7dc3550c7dc3, 0x550c7dc3550c7dc3, 0x550c7dc3550c7dc3, 0x550c7dc3550c7dc3,
	0x72be5d7472be5d74, 0x72be5d7472be5d74, 0x72be5d7472be5d74, 0x72be5d7472be5d74,
	0x72be5d7472be5d74, 0x72be5d7472be5d74, 0x72be5d7472be5d74, 0x72be5d7472be5d74,
	0x80deb1fe80deb1fe, 0x80deb1fe80deb1fe, 0x80deb1fe80deb1fe, 0x80deb1fe80deb1fe,
	0x80deb1fe80deb1fe, 0x80deb1fe80deb1fe, 0x80deb1fe80deb1fe, 0x80deb1fe80deb1fe,
	0x9bdc06a79bdc06a7, 0x9bdc06a79bdc06a7, 0x9bdc06a79bdc06a7, 0x9bdc06a79bdc06a7,
	0x9bdc06a79bdc06a7, 0x9bdc06a79bdc06a7, 0x9bdc06a79bdc06a7, 0x9bdc06a79bdc06a7,
	0xc19bf174c19bf174, 0xc19bf174c19bf174, 0xc19bf174c19bf174, 0xc19bf174c19bf174,
	0xc19bf174c19bf174, 0xc19bf174c19bf174, 0xc19bf174c19bf174, 0xc19bf174c19bf174,
	0xe49b69c1e49b69c1, 0xe49b69c1e49b69c1, 0xe49b69c1e49b69c1, 0xe49b69c1e49b69c1,
	0xe49b69c1e49b69c1, 0xe49b69c1e49b69c1, 0xe49b69c1e49b69c1, 0xe49b69c1e49b69c1,
	0xefbe4786efbe4786, 0xefbe4786efbe4786, 0xefbe4786efbe4786, 0xefbe4786efbe4786,
	0xefbe4786efbe4786, 0xefbe4786efbe4786, 0xefbe4786efbe4786, 0xefbe4786efbe4786,
	0x0fc19dc60fc19dc6, 0x0fc19dc60fc19dc6, 0x0fc19dc60fc19dc6, 0x0fc19dc60fc19dc6,
	0x0fc19dc60fc19dc6, 0x0fc19dc60fc19dc6, 0x0fc19dc60fc19dc6, 0x0fc19dc60fc19dc6,
	0x240ca1cc240ca1cc, 0x240ca1cc240ca1cc, 0x240ca1cc240ca1cc, 0x240ca1cc240ca1cc,
	0x240ca1cc240ca1cc, 0x240ca1cc240ca1cc, 0x240ca1cc240ca1cc, 0x240ca1cc240ca1cc,
	0x2de92c6f2de92c6f, 0x2de92c6f2de92c6f, 0x2de92c6f2de92c6f, 0x2de92c6f2de92c6f,
	0x2de92c6f2de92c6f, 0x2de92c6f2de92c6f, 0x2de92c6f2de92c6f, 0x2de92c6f2de92c6f,
	0x4a7484aa4a7484aa, 0x4a7484aa4a7484aa, 0x4a7484aa4a7484aa, 0x4a7484aa4a7484aa,
	0x4a7484aa4a7484aa, 0x4a7484aa4a7484aa, 0x4a7484aa4a7484aa, 0x4a7484aa4a7484aa,
	0x5cb0a9dc5cb0a9dc, 0x5cb0a9dc5cb0a9dc, 0x5cb0a9dc5cb0a9dc, 0x5cb0a9dc5cb0a9dc,
	0x5cb0a9dc5cb0a9dc, 0x5cb0a9dc5cb0a9dc, 0x5cb0a9dc5cb0a9dc, 0x5cb0a9dc5cb0a9dc,
	0x76f988da76f988da, 0x76f988da76f988da, 0x76f988da76f988da, 0x76f988da76f988da,
	0x76f988da76f988da, 0x76f988da76f988da, 0x76f988da76f988da, 0x76f988da76f988da,
	0x983e5152983e5152, 0x983e5152983e5152, 0x983e5152983e5152, 0x983e5152983e5152,
	0x983e5152983e5152, 0x983e5152983e5152, 0x983e5152983e5152, 0x983e5152983e5152,
	0xa831c66da831c66d, 0xa831c66da831c66d, 0xa831c66da831c66d, 0xa831c66da831c66d,
	0xa831c66da831c66d, 0xa831c66da831c66d, 0xa831c66da831c66d, 0xa831c66da831c66d,
	0xb00327c8b00327c8, 0xb00327c8b00327c8, 0xb00327c8b00327c8, 0xb00327c8b00327c8,
	0xb00327c8b00327c8, 0xb00327c8b00327c8, 0xb00327c8b00327c8, 0xb00327c8b00327c8,
	0xbf597fc7bf597fc7, 0xbf597fc7bf597fc7, 0xbf597fc7bf597fc7, 0xbf597fc7bf597fc7,
	0xbf597fc7bf597fc7, 0xbf597fc7bf597fc7, 0xbf597fc7bf597fc7, 0xbf597fc7bf597fc7,
	0xc6e00bf3c6e00bf3, 0xc6e00bf3c6e00bf3, 0xc6e00bf3c6e00bf3, 0xc6e00bf3c6e00bf3,
	0xc6e00bf3c6e00bf3, 0xc6e00bf3c6e00bf3, 0xc6e00bf3c6e00bf3, 0xc6e00bf3c6e00bf3,
	0xd5a79147d5a79147, 0xd5a79147d5a79147, 0xd5a79147d5a79147, 0xd5a79147d5a79147,
	0xd5a79147d5a79147, 0xd5a79147d5a79147, 0xd5a79147d5a79147, 0xd5a79147d5a79147,
	0x06ca635106ca6351, 0x06ca635106ca6351, 0x06ca635106ca6351, 0x06ca635106ca6351,
	0x06ca635106ca6351, 0x06ca635106ca6351, 0x06ca635106ca6351, 0x06ca635106ca6351,
	0x1429296714292967, 0x1429296714292967, 0x1429296714292967, 0x1429296714292967,
	0x1429296714292967, 0x1429296714292967, 0x1429296714292967, 0x1429296714292967,
	0x27b70a8527b70a85, 0x27b70a8527b70a85, 0x27b70a8527b70a85, 0x27b70a8527b70a85,
	0x27b70a8527b70a85, 0x27b70a8527b70a85, 0x27b70a8527b70a85, 0x27b70a8527b70a85,
	0x2e1b21382e1b2138, 0x2e1b21382e1b2138, 0x2e1b21382e1b2138, 0x2e1b21382e1b2138,
	0x2e1b21382e1b2138, 0x2e1b21382e1b2138, 0x2e1b21382e1b2138, 0x2e1b21382e1b2138,
	0x4d2c6dfc4d2c6dfc, 0x4d2c6dfc4d2c6dfc, 0x4d2c6dfc4d2c6dfc, 0x4d2c6dfc4d2c6dfc,
	0x4d2c6dfc4d2c6dfc, 0x4d2c6dfc4d2c6dfc, 0x4d2c6dfc4d2c6dfc, 0x4d2c6dfc4d2c6dfc,
	0x53380d1353380d13, 0x53380d1353380d13, 0x53380d1353380d13, 0x53380d1353380d13,
	0x53380d1353380d13, 0x53380d1353380d13, 0x53380d1353380d13, 0x53380d1353380d13,
	0x650a7354650a7354, 0x650a7354650a7354, 0x650a7354650a7354, 0x650a7354650a7354,
	0x650a7354650a7354, 0x650a7354650a7354, 0x650a7354650a7354, 0x650a7354650a7354,
	0x766a0abb766a0abb, 0x766a0abb766a0abb, 0x766a0abb766a0abb, 0x766a0abb766a0abb,
	0x766a0abb766a0abb, 0x766a0abb766a0abb, 0x766a0abb766a0abb, 0x766a0abb766a0abb,
	0x81c2c92e81c2c92e, 0x81c2c92e81c2c92e, 0x81c2c92e81c2c92e, 0x81c2c92e81c2c92e,
	0x81c2c92e81c2c92e, 0x81c2c92e81c2c92e, 0x81c2c92e81c2c92e, 0x81c2c92e81c2c92e,
	0x92722c8592722c85, 0x92722c8592722c85, 0x92722c8592722c85, 0x92722c8592722c85,
	0x92722c8592722c85, 0x92722c8592722c85, 0x92722c8592722c85, 0x92722c8592722c85,
	0xa2bfe8a1a2bfe8a1, 0xa2bfe8a1a2bfe8a1, 0xa2bfe8a1a2bfe8a1, 0xa2bfe8a1a2bfe8a1,
	0xa2bfe8a1a2bfe8a1, 0xa2bfe8a1a2bfe8a1, 0xa2bfe8a1a2bfe8a1, 0xa2bfe8a1a2bfe8a1,
	0xa81a664ba81a664b, 0xa81a664ba81a664b, 0xa81a664ba81a664b, 0xa81a664ba81a664b,
	0xa81a664ba81a664b, 0xa81a664ba81a664b, 0xa81a664ba81a664b, 0xa81a664ba81a664b,
	0xc24b8b70c24b8b70, 0xc24b8b70c24b8b70, 0xc24b8b70c24b8b70, 0xc24b8b70c24b8b70,
	0xc24b8b70c24b8b70, 0xc24b8b70c24b8b70, 0xc24b8b70c24b8b70, 0xc24b8b70c24b8b70,
	0xc76c51a3c76c51a3, 0xc76c51a3c76c51a3, 0xc76c51a3c76c51a3, 0xc76c51a3c76c51a3,
	0xc76c51a3c76c51a3, 0xc76c51a3c76c51a3, 0xc76c51a3c76c51a3, 0xc76c51a3c76c51a3,
	0xd192e819d192e819, 0xd192e819d192e819, 0xd192e819d192e819, 0xd192e819d192e819,
	0xd192e819d192e819, 0xd192e819d192e819, 0xd192e819d192e819, 0xd192e819d192e819,
	0xd6990624d6990624, 0xd6990624d6990624, 0xd6990624d6990624, 0xd6990624d6990624,
	0xd6990624d6990624, 0xd6990624d6990624, 0xd6990624d6990624, 0xd6990624d6990624,
	0xf40e3585f40e3585, 0xf40e3585f40e3585, 0xf40e3585f40e3585, 0xf40e3585f40e3585,
	0xf40e3585f40e3585, 0xf40e3585f40e3585, 0xf40e3585f40e3585, 0xf40e3585f40e3585,
	0x106aa070106aa070, 0x106aa070106aa070, 0x106aa070106aa070, 0x106aa070106aa070,
	0x106aa070106aa070, 0x106aa070106aa070, 0x106aa070106aa070, 0x106aa070106aa070,
	0x19a4c11619a4c116, 0x19a4c11619a4c116, 0x19a4c11619a4c116, 0x19a4c11619a4c116,
	0x19a4c11619a4c116, 0x19a4c11619a4c116, 0x19a4c11619a4c116, 0x19a4c11619a4c116,
	0x1e376c081e376c08, 0x1e376c081e376c08, 0x1e376c081e376c08, 0x1e376c081e376c08,
	0x1e376c081e376c08, 0x1e376c081e376c08, 0x1e376c081e376c08, 0x1e376c081e376c08,
	0x2748774c2748774c, 0x2748774c2748774c, 0x2748774c2748774c, 0x2748774c2748774c,
	0x2748774c2748774c, 0x2748774c2748774c, 0x2748774c2748774c, 0x2748774c2748774c,
	0x34b0bcb534b0bcb5, 0x34b0bcb534b0bcb5, 0x34b0bcb534b0bcb5, 0x34b0bcb534b0bcb5,
	0x34b0bcb534b0bcb5, 0x34b0bcb534b0bcb5, 0x34b0bcb534b0bcb5, 0x34b0bcb534b0bcb5,
	0x391c0cb3391c0cb3, 0x391c0cb3391c0cb3, 0x391c0cb3391c0cb3, 0x391c0cb3391c0cb3,
	0x391c0cb3391c0cb3, 0x391c0cb3391c0cb3, 0x391c0cb3391c0cb3, 0x391c0cb3391c0cb3,
	0x4ed8aa4a4ed8aa4a, 0x4ed8aa4a4ed8aa4a, 0x4ed8aa4a4ed8aa4a, 0x4ed8aa4a4ed8aa4a,
	0x4ed8aa4a4ed8aa4a, 0x4ed8aa4a4ed8aa4a, 0x4ed8aa4a4ed8aa4a, 0x4ed8aa4a4ed8aa4a,
	0x5b9cca4f5b9cca4f, 0x5b9cca4f5b9cca4f, 0x5b9cca4f5b9cca4f, 0x5b9cca4f5b9cca4f,
	0x5b9cca4f5b9cca4f, 0x5b9cca4f5b9cca4f, 0x5b9cca4f5b9cca4f, 0x5b9cca4f5b9cca4f,
	0x682e6ff3682e6ff3, 0x682e6ff3682e6ff3, 0x682e6ff3682e6ff3, 0x682e6ff3682e6ff3,
	0x682e6ff3682e6ff3, 0x682e6ff3682e6ff3, 0x682e6ff3682e6ff3, 0x682e6ff3682e6ff3,
	0x748f82ee748f82ee, 0x748f82ee748f82ee, 0x748f82ee748f82ee, 0x748f82ee748f82ee,
	0x748f82ee748f82ee, 0x748f82ee748f82ee, 0x748f82ee748f82ee, 0x748f82ee748f82ee,
	0x78a5636f78a5636f, 0x78a5636f78a5636f, 0x78a5636f78a5636f, 0x78a5636f78a5636f,
	0x78a5636f78a5636f, 0x78a5636f78a5636f, 0x78a5636f78a5636f, 0x78a5636f78a5636f,
	0x84c8781484c87814, 0x84c8781484c87814, 0x84c8781484c87814, 0x84c8781484c87814,
	0x84c8781484c87814, 0x84c8781484c87814, 0x84c8781484c87814, 0x84c8781484c87814,
	0x8cc702088cc70208, 0x8cc702088cc70208, 0x8cc702088cc70208, 0x8cc702088cc70208,
	0x8cc702088cc70208, 0x8cc702088cc70208, 0x8cc702088cc70208, 0x8cc702088cc70208,
	0x90befffa90befffa, 0x90befffa90befffa, 0x90befffa90befffa, 0x90befffa90befffa,
	0x90befffa90befffa, 0x90befffa90befffa, 0x90befffa90befffa, 0x90befffa90befffa,
	0xa4506ceba4506ceb, 0xa4506ceba4506ceb, 0xa4506ceba4506ceb, 0xa4506ceba4506ceb,
	0xa4506ceba4506ceb, 0xa4506ceba4506ceb, 0xa4506ceba4506ceb, 0xa4506ceba4506ceb,
	0xbef9a3f7bef9a3f7, 0xbef9a3f7bef9a3f7, 0xbef9a3f7bef9a3f7, 0xbef9a3f7bef9a3f7,
	0xbef9a3f7bef9a3f7, 0xbef9a3f7bef9a3f7, 0xbef9a3f7bef9a3f7, 0xbef9a3f7bef9a3f7,
	0xc67178f2c67178f2, 0xc67178f2c67178f2, 0xc67178f2c67178f2, 0xc67178f2c67178f2,
	0xc67178f2c67178f2, 0xc67178f2c67178f2, 0xc67178f2c67178f2, 0xc67178f2c67178f2}

// blockAvx512 (vendored from minio/sha256-simd) runs the 16-lane kernel and returns
// the 16 lane digests.
func blockAvx512(digests *[512]byte, input [16][]byte, mask []uint64) [16][Size]byte {
	scratch := [512]byte{}
	sha256X16Avx512(digests, &scratch, &table, mask, input)
	output := [16][Size]byte{}
	for i := 0; i < 16; i++ {
		output[i] = getDigest(i, digests[:])
	}
	return output
}

// getDigest (vendored) extracts lane `index` from the transposed state.
func getDigest(index int, state []byte) (sum [Size]byte) {
	for j := 0; j < 16; j += 2 {
		for i := index*4 + j*Size; i < index*4+(j+1)*Size; i += Size {
			binary.BigEndian.PutUint32(sum[j*2:], binary.LittleEndian.Uint32(state[i:i+4]))
		}
	}
	return
}

func initialState() [512]byte {
	var d [512]byte
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(d[(i+0*16)*4:], init0)
		binary.LittleEndian.PutUint32(d[(i+1*16)*4:], init1)
		binary.LittleEndian.PutUint32(d[(i+2*16)*4:], init2)
		binary.LittleEndian.PutUint32(d[(i+3*16)*4:], init3)
		binary.LittleEndian.PutUint32(d[(i+4*16)*4:], init4)
		binary.LittleEndian.PutUint32(d[(i+5*16)*4:], init5)
		binary.LittleEndian.PutUint32(d[(i+6*16)*4:], init6)
		binary.LittleEndian.PutUint32(d[(i+7*16)*4:], init7)
	}
	return d
}

var hasAVX512 = cpuid.CPU.Supports(cpuid.AVX512F, cpuid.AVX512DQ, cpuid.AVX512BW, cpuid.AVX512VL)

// Available reports whether the AVX-512 16-lane kernel runs on this CPU.
func Available() bool { return hasAVX512 }

// DoubleSHA256x16 computes SHA-256d of 16 independent 64-byte messages in one 16-lane
// batch (the Merkle-fold HashPair batch). Falls back to scalar if AVX-512 is absent.
func DoubleSHA256x16(msgs *[16][64]byte, out *[16][Size]byte) {
	if !hasAVX512 {
		for i := 0; i < 16; i++ {
			h := sha256.Sum256(msgs[i][:])
			(*out)[i] = sha256.Sum256(h[:])
		}
		return
	}
	var in1 [16][]byte
	var b1 [16][128]byte
	for i := 0; i < 16; i++ {
		copy(b1[i][:64], msgs[i][:])
		b1[i][64] = 0x80
		binary.BigEndian.PutUint64(b1[i][120:128], 512) // 64-byte msg = 512 bits
		in1[i] = b1[i][:]
	}
	d1 := initialState()
	h1 := blockAvx512(&d1, in1, []uint64{0xffff, 0xffff})

	var in2 [16][]byte
	var b2 [16][64]byte
	for i := 0; i < 16; i++ {
		copy(b2[i][:32], h1[i][:])
		b2[i][32] = 0x80
		binary.BigEndian.PutUint64(b2[i][56:64], 256) // 32-byte msg = 256 bits
		in2[i] = b2[i][:]
	}
	d2 := initialState()
	*out = blockAvx512(&d2, in2, []uint64{0xffff})
}

// Hasher is a REUSABLE, allocation-free 16-lane double-SHA-256 context. Create one
// per worker; DoubleSHA256x16 reuses its internal buffers (no per-call heap), which
// is what lets the 16-lane kernel run at full rate in a tight fold loop.
type Hasher struct {
	scratch [512]byte
	state   [512]byte
	b1      [16][128]byte
	b2      [16][64]byte
	in1     [16][]byte
	in2     [16][]byte
}

// NewHasher returns a reusable 16-lane hasher with zero-initialised padding.
func NewHasher() *Hasher {
	h := &Hasher{}
	for i := 0; i < 16; i++ {
		h.b1[i][64] = 0x80
		binary.BigEndian.PutUint64(h.b1[i][120:128], 512)
		h.b2[i][32] = 0x80
		binary.BigEndian.PutUint64(h.b2[i][56:64], 256)
		h.in1[i] = h.b1[i][:]
		h.in2[i] = h.b2[i][:]
	}
	return h
}

var mask2 = []uint64{0xffff, 0xffff}
var mask1 = []uint64{0xffff}

// DoubleSHA256x16 computes SHA-256d of 16 messages with no allocation.
func (h *Hasher) DoubleSHA256x16(msgs *[16][64]byte, out *[16][Size]byte) {
	if !hasAVX512 {
		for i := 0; i < 16; i++ {
			x := sha256.Sum256(msgs[i][:])
			(*out)[i] = sha256.Sum256(x[:])
		}
		return
	}
	// round 1: 64-byte message (data already padded with 0x80/len in NewHasher).
	for i := 0; i < 16; i++ {
		copy(h.b1[i][:64], msgs[i][:])
	}
	h.state = initState
	sha256X16Avx512(&h.state, &h.scratch, &table, mask2, h.in1)
	for i := 0; i < 16; i++ {
		d := getDigest(i, h.state[:])
		copy(h.b2[i][:32], d[:])
	}
	// round 2: 32-byte message.
	h.state = initState
	sha256X16Avx512(&h.state, &h.scratch, &table, mask1, h.in2)
	for i := 0; i < 16; i++ {
		(*out)[i] = getDigest(i, h.state[:])
	}
}

var initState = initialState()
