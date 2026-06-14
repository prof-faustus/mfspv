// Command mfspv is a demonstration runner for the Merkle-Forest SPV build. It
// prints the derived scaling table (03_SCALING_MODEL.md) and drives one complete
// push payment (Alice -> Bob -> verify -> accept), so the whole pipeline can be
// observed end-to-end.
//
// BSV only.
package main

import (
	"crypto/sha256"
	"fmt"
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
	fmt.Println("Merkle-Forest SPV (MF-SPV) — BSV/Teranode. Demonstration runner.")
	fmt.Println()
	printScaling()
	fmt.Println()
	printCapacity()
	fmt.Println()
	runPayment()
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
