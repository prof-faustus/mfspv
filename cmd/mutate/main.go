// Command mutate is a self-contained, dependency-free mutation-testing gate for
// the security-critical operators named in 06_EVALUATION_DESIGN.md §4.4: it flips
// a comparison/boolean in each of Fold, Verify*, VerifyToBlockRoot, VerifyAnchor,
// VerifyBlockInChain, Decide, the low-S / onCurve checks, the L4 carrying-header
// gate, and the alert/value checks, then runs the test suite and asserts the mutant
// is KILLED (tests fail). A surviving security-critical mutant is a blocking defect.
//
// Run from the repository root:  go run ./cmd/mutate
//
// This complements (and needs no network, unlike) gremlins/go-mutesting; a
// gremlins.yaml is also shipped for the external-tool path.
//
// BSV only.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type mutation struct {
	file string
	old  string
	new  string
	desc string
}

// Each mutation targets a security-critical predicate; every one MUST be killed.
var mutations = []mutation{
	// commitment — the Merkle fold and verifiers
	{"commitment/commitment.go", "if e.Right {", "if !e.Right {", "Fold: invert sibling side"},
	{"commitment/commitment.go", "return root == blockMerkleRoot, depth", "return root != blockMerkleRoot, depth", "VerifyToBlockRoot: invert root check"},
	{"commitment/commitment.go", "return Fold(leaf, path) == mtxid", "return Fold(leaf, path) != mtxid", "VerifyMTxIDPath: invert"},
	{"commitment/commitment.go", "if len(path) > 20 {", "if len(path) > 21 {", "VerifySubtreePath: loosen cap to 21"},
	// crypto — signature canonicality and verification
	{"crypto/secp256k1.go", "return s.S.Cmp(nHalf) <= 0", "return s.S.Cmp(nHalf) >= 0", "IsLowS: invert low-S test"},
	{"crypto/secp256k1.go", "return x.Cmp(sig.R) == 0", "return x.Cmp(sig.R) != 0", "Verify: invert r comparison"},
	{"crypto/secp256k1.go", "return lhs.Cmp(rhs) == 0", "return lhs.Cmp(rhs) != 0", "onCurve: invert"},
	// bundle — inclusion + L4 anchor gate
	{"bundle/bundle.go", "if mtxid != b.OutputRef.TXID {", "if mtxid == b.OutputRef.TXID {", "Verify: invert L0 TXID bind"},
	{"bundle/bundle.go", "if blockRoot != HeaderMerkleRoot(b.Header) {", "if blockRoot == HeaderMerkleRoot(b.Header) {", "Verify: invert L3 bind"},
	{"bundle/bundle.go", "if !headersView.Contains(a.CarryingHeader) {", "if headersView.Contains(a.CarryingHeader) {", "anchorBindsToChain: drop carrier check (RT-1)"},
	{"bundle/bundle.go", "if HeaderMerkleRoot(a.CarryingHeader) != a.CarryingBlockMerkleRoot {", "if HeaderMerkleRoot(a.CarryingHeader) == a.CarryingBlockMerkleRoot {", "anchorBindsToChain: invert root match"},
	// accumulator — L4 binding
	{"accumulator/accumulator.go", "return root == carryingBlockMerkleRoot", "return root != carryingBlockMerkleRoot", "VerifyAnchor: invert"},
	{"accumulator/accumulator.go", "return commitment.Fold(leaf, path) == accRoot", "return commitment.Fold(leaf, path) != accRoot", "VerifyBlockInChain: invert"},
	// dsalert — evidence gate
	{"dsalert/dsalert.go", "if ev.SpendA == ev.SpendB {", "if ev.SpendA != ev.SpendB {", "VerifyAlert: invert same-tx check"},
	{"dsalert/dsalert.go", "if !crypto.Verify(pub, mA[:], sigA) || !crypto.Verify(pub, mB[:], sigB) {", "if crypto.Verify(pub, mA[:], sigA) || !crypto.Verify(pub, mB[:], sigB) {", "VerifyAlert: drop sigA check"},
	// walletbob — risk policy + value conservation
	{"walletbob/walletbob.go", "return valueAtRisk <= p.Tau", "return valueAtRisk >= p.Tau", "Decide: invert tau threshold"},
	{"walletbob/walletbob.go", "d.ValueOK = sumIn >= sumOut", "d.ValueOK = sumIn <= sumOut", "AcceptPayment: invert value conservation"},
}

func main() {
	killed, survived, errored := 0, 0, 0
	var survivors []string
	for i, m := range mutations {
		orig, err := os.ReadFile(m.file)
		if err != nil {
			fmt.Printf("[ERR ] %-44s cannot read %s: %v\n", m.desc, m.file, err)
			errored++
			continue
		}
		s := string(orig)
		if n := strings.Count(s, m.old); n != 1 {
			fmt.Printf("[ERR ] %-44s target occurs %d times (need 1): %q\n", m.desc, n, m.old)
			errored++
			continue
		}
		mutated := strings.Replace(s, m.old, m.new, 1)
		if err := os.WriteFile(m.file, []byte(mutated), 0o644); err != nil {
			fmt.Printf("[ERR ] %-44s write: %v\n", m.desc, err)
			errored++
			continue
		}
		ok := runTests()
		// always revert
		if err := os.WriteFile(m.file, orig, 0o644); err != nil {
			fmt.Printf("FATAL: could not revert %s: %v\n", m.file, err)
			os.Exit(2)
		}
		if ok {
			// tests passed with the mutation in place -> mutant SURVIVED (bad)
			survived++
			survivors = append(survivors, m.desc)
			fmt.Printf("[LIVE] %2d/%2d %-44s SURVIVED (tests still pass!)\n", i+1, len(mutations), m.desc)
		} else {
			killed++
			fmt.Printf("[KILL] %2d/%2d %-44s killed\n", i+1, len(mutations), m.desc)
		}
	}

	total := killed + survived
	score := 0.0
	if total > 0 {
		score = float64(killed) / float64(total)
	}
	fmt.Printf("\nmutation score: %d/%d = %.3f  (errored targets: %d)\n", killed, total, score, errored)
	gateOK := errored == 0 && survived == 0 && score >= 0.85
	if !gateOK {
		fmt.Println("GATE FAILED (06_EVALUATION_DESIGN §4.4 / §10): score < 0.85, surviving security-critical mutant, or unmatched target.")
		if len(survivors) > 0 {
			fmt.Println("survivors:")
			for _, s := range survivors {
				fmt.Println("  -", s)
			}
		}
		os.Exit(1)
	}
	fmt.Println("GATE PASSED: all security-critical mutants killed.")
}

// runTests returns true iff the suite PASSES (mutant survived). The -short flag
// keeps each run fast while retaining the killer tests.
func runTests() bool {
	cmd := exec.Command("go", "test", "-short", "-count=1", "./...")
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() == nil
}
