package fabric

import (
	"runtime"
	"testing"
	"time"
)

// PULL at scale: a node serves Merkle paths for many txs; every fetched proof must
// verify. Exercises proof acquisition + verification across the whole served block.
func TestPullAtScale(t *testing.T) {
	subCap, numSub := 1024, 8 // 8,192 real txs (CI-safe)
	if !testing.Short() {
		subCap, numSub = 4096, 16 // 65,536 on a full run
	}
	node, txids, err := BuildServedBlock(subCap, numSub)
	if err != nil {
		t.Fatal(err)
	}
	h := DefaultHasher()
	for _, txid := range txids {
		p, err := Fetch(txid, node)
		if err != nil {
			t.Fatalf("Fetch failed for a served tx: %v", err)
		}
		if ok, _ := VerifyOne(h, p, node); !ok {
			t.Fatal("a served+fetched proof failed to verify")
		}
	}
	// throughput must be positive (sanity); the absolute pull rate is serving-bound
	// and reported by cmd/verifyfabric.
	if v := MeasurePullThroughput(node, txids, runtime.NumCPU(), 150*time.Millisecond); v <= 0 {
		t.Fatal("pull throughput non-positive")
	}
}
