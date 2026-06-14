// Command mfspv is a demonstration runner for the Merkle-Forest SPV build. It
// prints the derived scaling table (03_SCALING_MODEL.md) and drives one complete
// push payment (Alice -> Bob -> verify -> accept), so the whole pipeline can be
// observed end-to-end.
//
// BSV only.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"mfspv/bench"
	"mfspv/bundle"
	"mfspv/commitment"
	"mfspv/crypto"
	"mfspv/dsalert"
	"mfspv/payment"
	"mfspv/teranode"
	"mfspv/walletalice"
	"mfspv/walletbob"
)

func main() {
	eval := flag.Bool("eval", false, "emit environment.json + claims.csv and tagged M/D/S results (06_EVALUATION_DESIGN.md §8)")
	flag.Parse()
	if *eval {
		reproduce()
		return
	}
	fmt.Println("Merkle-Forest SPV (MF-SPV) — BSV/Teranode. Demonstration runner.")
	fmt.Println()
	printScaling()
	fmt.Println()
	printCapacity()
	fmt.Println()
	runPayment()
}

// reproduce regenerates the evaluation artifacts (06_EVALUATION_DESIGN.md §8):
// environment.json (machine-readable platform record) and claims.csv (every claim
// ID mapped to its falsifying test), printing each reported number tagged with its
// class M(easured) / D(erived) / S(imulated).
func reproduce() {
	rate := bench.HashRatePerSec(0)
	env := map[string]any{
		"go_version":                        runtime.Version(),
		"goos":                              runtime.GOOS,
		"goarch":                            runtime.GOARCH,
		"num_cpu":                           runtime.NumCPU(),
		"gomaxprocs":                        runtime.GOMAXPROCS(0),
		"git_commit":                        gitCommit(),
		"measured_sha256d_per_sec_per_core": int64(rate),
		"timestamp_utc":                     time.Now().UTC().Format(time.RFC3339),
		"note":                              "BSV only. sha256d rate is software path unless SHA-NI is present; see SECURITY.md.",
	}
	writeJSON("environment.json", env)
	writeFile("claims.csv", claimsCSV())

	fmt.Println("== MF-SPV reproduce (06_EVALUATION_DESIGN.md) ==")
	fmt.Printf("env: %s %s/%s, %d cores, %s, %.2f M sha256d/s/core [M]\n",
		runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU(),
		gitCommit(), rate/1e6)
	fmt.Printf("header dataset: %d B/yr (~%.2f MB) [D, R2]\n",
		bench.HeaderGrowthBytesPerYear(), float64(bench.HeaderGrowthBytesPerYear())/1e6)
	fmt.Println("scaling table (depth/proofB = S; subtrees = D):")
	for _, row := range bench.SweepThroughputExtended() {
		fmt.Printf("  r=%-7.0e depth=%-3d proofB=%-5d subtrees=%-11d push=%d pull=%d [S/D]\n",
			row.R, row.Depth, row.ProofBytes, row.Subtrees, row.PushNetBytes, row.PullNetBytes)
	}
	for _, r := range []float64{1e10, 1e11, 1e12} {
		c := bench.PlanCapacity(r, rate)
		fmt.Printf("  capacity r=%-7.0e seal~%.2e h/s ~%.0f SHA-NI cores [D, R5]\n",
			c.R, c.InclusiveHashRate, c.CoresShaNi)
	}
	fmt.Println("wrote environment.json and claims.csv")
	fmt.Println("verify: `go test ./...` (Functional), `go test -shuffle=on ./...` (order-independent)")
}

func gitCommit() string {
	out, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

func writeJSON(path string, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	writeFile(path, string(b)+"\n")
}

func writeFile(path, content string) {
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write", path, ":", err)
	}
}

// claimsCSV maps every paper claim ID (06 §2 / PAPER Appendix D) to its class and
// the falsifying test, so a reviewer can audit claim-by-claim.
func claimsCSV() string {
	rows := [][4]string{
		{"id", "claim", "class", "falsifying_test"},
		{"X-DL", "depth==ceil(log2 T)", "S", "commitment.TestT1_3_DepthLaw;bench.TestT7_TargetTable"},
		{"X-R1", "proof=32*depth; +416B 1e6->1e10; 1472B@1e11", "D+S", "bench.TestR1_ProofGrowth;bench.TestScale100BillionTPS"},
		{"X-R2", "header dataset ~4.2MB/yr, constant in r", "D", "bench.TestT7_3_HeaderConstant"},
		{"X-R3", "verify ~ log T, not linear", "M+S", "bench.TestEQ3_ScalingLawRegression;bench.TestT7_4_LogarithmicVerify"},
		{"X-R4", "push proof network bytes == 0", "M", "bench.TestT7_5_PushVsPull"},
		{"X-CAP", "seal ~2r SHA256d/s; 100B tps capacity", "M+D", "bench.TestCapacity100BillionTPS"},
		{"X-FROZEN", "L0-L3 path byte-frozen after sealing", "M", "bundle.TestT3_3_FrozenCore"},
		{"X-PRIV", "reveal one field, not whole tx", "M", "bundle.TestT3_*"},
		{"S1", "inclusion forgery rejected (MC + p_upper)", "M", "adversarial.TestS1_MonteCarloForgery;TestA1_ForgeryRejected"},
		{"S2", "field reordering rejected", "M", "adversarial.TestS2_FieldReordering"},
		{"S3", "duplication grants no non-member inclusion", "M", "adversarial.TestS3_DuplicationAmbiguity"},
		{"S4", "alternative chain rejected", "M", "adversarial.TestA2_AlternativeChainRejected"},
		{"S5", "L4 anchor PoW-gated (RT-1)", "M", "adversarial.TestRT1_AnchorRequiresTrustedCarrier;bundle.TestL4PrunedVerifier"},
		{"S6", "absent-period gap honesty", "M", "accumulator.TestT2_3_GapHonesty"},
		{"S7", "DoS: fail-fast, bounded, evidence-gated alerts", "M", "adversarial.TestA3_SpamRejectedFailFast;TestA4_AlertFloodDropped;TestRT5_SerializationDoS"},
		{"S8", "inclusion != double-spend", "M", "bundle.TestT3_5_InclusionNotDoubleSpend;walletbob.TestT4_4_AcceptanceSeparation"},
		{"S9", "signature malleability rejected (low-S)", "M", "adversarial.TestRT3_HighSRejected"},
		{"S9b", "alert unforgeable + owner-bound (RT-2/RT-7)", "M", "dsalert.TestT5_1_EvidenceGated;TestRT7_OwnerBoundAlerts"},
		{"S10", "no private keys at till", "M", "walletbob.TestT4_3_NoKeysAtTill"},
		{"KAT", "sha256d/2G/RFC6979 known-answer", "M", "crypto.TestKAT_TwoG;TestKAT_RFC6979Nonce;commitment.TestKAT_DoubleSHA256"},
		{"DIFF", "merkle vs independent oracle (incl odd)", "M", "commitment.TestDifferentialMerkle"},
	}
	var sb strings.Builder
	for _, r := range rows {
		// minimal CSV quoting (fields contain ';' not ',')
		sb.WriteString(strings.Join(r[:], ","))
		sb.WriteString("\n")
	}
	return sb.String()
}

func printCapacity() {
	fmt.Println("== Running at 100 billion tx/s (1e11) — capacity ==")
	rate := bench.HashRatePerSec(0)
	fmt.Printf("This machine: %.2f M SHA-256d/s/core (software path).\n", rate/1e6)
	for _, r := range []float64{1e10, 1e11, 1e12} {
		c := bench.PlanCapacity(r, rate)
		fmt.Printf("r=%-6.0e  seal: %.2e hashes/s (incl leaf), ~%.0f cores @sw / ~%.0f cores @SHA-NI  | edge proof: %d B\n",
			c.R, c.InclusiveHashRate, c.CoresMeasured, c.CoresShaNi, c.ProofBytes)
	}
	// Edge: actually sustain verification at the 1e11 depth, single vs multi core.
	ep := bench.ProfileEdge(1e11, 8, 200_000_000) // 0.2s per measurement
	fmt.Printf("Edge @1e11 (depth %d, %d B): %.0f verifies/s/core, %.0f verifies/s on %d cores (stateless, linear).\n",
		ep.Depth, ep.ProofBytes, ep.VerifiesPerSec1, ep.VerifiesPerSecN, ep.Workers)
	fmt.Println("Note: ordering/validating the txs is Teranode's sharded job (bounded by Teranode,")
	fmt.Println("not by SPV); MF-SPV guarantees the proof layer adds no ceiling and the edge scales.")
}

func printScaling() {
	fmt.Println("== Scaling model (derived, 03_SCALING_MODEL.md) ==")
	fmt.Printf("%-6s %-16s %-6s %-9s %-12s %-4s %-4s %-9s %-9s\n",
		"r", "T=r*600", "depth", "proofB", "subtrees", "L1", "L2", "push", "pull")
	for _, row := range bench.SweepThroughput(nil) {
		fmt.Printf("%-6.0e %-16d %-6d %-9d %-12d %-4d %-4d %-9d %-9d\n",
			row.R, row.T, row.Depth, row.ProofBytes, row.Subtrees, row.L1Len, row.L2Len,
			row.PushNetBytes, row.PullNetBytes)
	}
	fmt.Printf("Header dataset: %d bytes/year (~%.1f MB/yr), constant in r.\n",
		bench.HeaderGrowthBytesPerYear(), float64(bench.HeaderGrowthBytesPerYear())/1e6)
	lo, hi := bench.Row(1e6), bench.Row(1e10)
	fmt.Printf("R1: proof grows %d->%d B (+%d B / +%d hashes) across 1e6->1e10 tx/s.\n",
		lo.ProofBytes, hi.ProofBytes, hi.ProofBytes-lo.ProofBytes, hi.Depth-lo.Depth)
}

func runPayment() {
	fmt.Println("== End-to-end push payment ==")
	node := teranode.NewMockNode(8)

	// Alice's funding transaction; field 1 is the spendable output.
	fields := commitment.TxFields{
		{Index: 0, Bytes: []byte{0x01}},
		{Index: 1, Bytes: []byte("alice-output-1000-sats")},
		{Index: 2, Bytes: []byte{0xde, 0xad, 0xbe, 0xef}},
	}
	mtxid, _, _ := commitment.BuildMTxID(fields)
	txids := []commitment.Hash{mtxid}
	for i := 0; i < 40; i++ {
		txids = append(txids, commitment.DoubleSHA256([]byte{0x33, byte(i)}))
	}
	blockHash, _ := node.SealBlock(txids, false)
	fmt.Printf("Sealed block with %d txs; block hash %x...\n", len(txids), blockHash[:6])

	out := bundle.OutputRef{TXID: mtxid, Vout: 0}
	fund, _ := bundle.Build(out, fields, 1, node)
	data, _ := bundle.Serialize(fund)
	fmt.Printf("Alice's bundle: %d path hashes (L1=%d, L2=%d), %d serialized bytes.\n",
		len(fund.SubtreePath)+len(fund.BlockPath), len(fund.SubtreePath), len(fund.BlockPath), len(data))

	// Keys.
	as := sha256.Sum256([]byte("alice"))
	aliceK, _ := crypto.NewPrivateKey(as[:])
	bs := sha256.Sum256([]byte("bob"))
	bobK, _ := crypto.NewPrivateKey(bs[:])

	// Alice (offline) fills + signs + exports.
	aliceW := walletalice.New()
	aliceW.AddOutput(fund, aliceK)
	template := payment.Tx3{Version: 1, Outputs: []payment.TxOut{
		{Value: 900, ScriptPubKey: bobK.Public().SerializeCompressed()},
	}}
	signed, _ := aliceW.FillTemplate(template, []bundle.Bundle{fund}, nil, 0)
	msg, _ := aliceW.Export([]bundle.Bundle{fund}, signed)
	fmt.Printf("Alice exported a %d-byte message (offline).\n", len(msg))

	// Bob (online till) verifies + decides.
	bus := dsalert.NewBus()
	bobW := walletbob.New(node, node, bus, func(payment.Tx3) error { return nil })
	bobW.AddReceivingKey(bobK.Public())
	policy := walletbob.RiskPolicy{Tau: 5000, Window: time.Minute}

	d, err := bobW.AcceptPayment(msg, template, 900, policy)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("Bob decision: accepted=%v reason=%q [inclusion=%v unspent=%v quiet=%v sig=%v template=%v]\n",
		d.Accepted, d.Reason, d.InclusionOK, d.AllUnspent, d.AlertQuiet, d.SignaturesOK, d.TemplateOK)

	// Show double-spend orthogonality: same proof, but the output is now spent.
	node.MarkSpent(teranode.Outpoint{TXID: out.TXID, Vout: 0})
	d2, _ := bobW.AcceptPayment(msg, template, 900, policy)
	fmt.Printf("After double-spend: accepted=%v reason=%q (inclusion still %v — proof is fail-fast, not DS protection)\n",
		d2.Accepted, d2.Reason, d2.InclusionOK)
}
