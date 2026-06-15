// Command verifyfabric runs the 07_VERIFICATION_FABRIC benchmark on the target box:
// REAL batch inclusion-verification throughput vs the >=1.5e7 verifications/s bar,
// across backends (Lever A) and batch densities (Lever B), plus the capacity equation
// (Lever C). Every fold is real SHA-256d over real Merkle paths. BSV only.
//
//	go run ./cmd/verifyfabric                 # measure on a 64-core box
//	go run ./cmd/verifyfabric -dur 3s -r 1e11
//
// Honest by construction: it prints the MEASURED A = verif/s / 1.5e7 with PASS/FAIL
// per (rate, backend, density). Until a row reports A>=1.5 the bar is reported as not
// met on that measured path — never assumed (07 §8).
package main

import (
	"flag"
	"fmt"
	"runtime"
	"time"

	"mfspv/bench"
)

func main() {
	dur := flag.Duration("dur", 2*time.Second, "measurement window per cell")
	workers := flag.Int("workers", runtime.NumCPU(), "parallel verifier cores")
	flag.Parse()

	rates := []float64{1e10, 1e11} // depth 43 and 46 (the operating point)
	densities := []float64{1, 64, 1024}
	backends := bench.AvailableBackends()

	perCore, note := bench.CapabilityNote()
	fmt.Printf("# 07 Verification-Fabric benchmark (BSV only)\n")
	fmt.Printf("cores=%d  per-core SHA-256d=%.3e /s  [%s]\n", *workers, perCore, note)
	fmt.Printf("bar = %.2e verifications/s  (A = verif/s / bar; PASS iff A>=1.0)\n\n", bench.VerifBar)

	fmt.Printf("%-6s %-22s %-9s %-12s %-7s %s\n", "depth", "backend", "density", "verif/s", "A", "result")
	for _, r := range rates {
		rows := bench.MeasureFabric(r, densities, backends, *workers, *dur)
		for _, row := range rows {
			res := "FAIL"
			if row.Pass {
				res = "PASS"
			}
			fmt.Printf("%-6d %-22s %-9.0f %-12.3e %-7.2f %s\n",
				row.Depth, row.Backend, row.Density, row.VerifPerS, row.A, res)
		}
		fmt.Println()
	}

	// Lever C — capacity equation: software cores needed to reach the edge bar.
	fmt.Printf("## Lever C — capacity to reach the %.2e/s bar (single-proof, no batching)\n", bench.VerifBar)
	fmt.Printf("%-8s %-6s %-16s %-16s\n", "r", "depth", "cores(software)", "cores(SHA-NI)")
	for _, r := range []float64{1e10, 1e11} {
		depth, cSW, cNI := bench.FabricCapacityForBar(r, perCore)
		fmt.Printf("%-8.0e %-6d %-16.0f %-16.1f\n", r, depth, cSW, cNI)
	}
	fmt.Printf("\n(64-core box rate is the measured anchor; SHA-NI uses %.0e/s/core; "+
		"batching/scale-out compose on top per 07 §4.)\n", bench.ShaNiRatePerCore)
}
