package bench

import (
	"testing"
	"time"
)

// Whole-block verification rebuilds the forest with the 16-lane kernel and the root
// must match the reference (real verification, not a hash microbenchmark).
func TestVerifyWholeBlockCorrect(t *testing.T) {
	tps, ok := VerifyWholeBlockThroughput(1<<12, 2, 100*time.Millisecond)
	if !ok {
		t.Fatal("whole-block rebuild produced a wrong root")
	}
	if tps <= 0 {
		t.Fatal("non-positive throughput")
	}
	t.Logf("whole-block verify: %.3e tx/s (2 cores, root-correct)", tps)
}
