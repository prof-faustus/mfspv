// Package dsalert is the double-spend ALERT layer of MF-SPV (02_MODULE_SPECS.md
// §dsalert, §3.2(b)). It is the network-alert half of double-spend handling, kept
// ORTHOGONAL to the inclusion proof (§6.3): a PoW-attested, IPv6-multicast alert
// carrying evidence of a conflicting spend lets a merchant reject within the
// propagation window.
//
// Invariants:
//   - I-DS1 Evidence-gated: an alert with no verifiable conflicting-spend evidence
//     is dropped (prevents alert-flooding as a censorship/DoS vector).
//   - I-DS2 Advisory: alerts feed RiskPolicy; they are NOT consensus.
//
// BSV only.
package dsalert

import (
	"encoding/binary"
	"sync"
	"time"

	"mfspv/commitment"
)

type Hash = commitment.Hash

// Outpoint identifies the contested output.
type Outpoint struct {
	TXID Hash
	Vout uint32
}

// ConflictEvidence is two DISTINCT transactions that both spend the same outpoint.
// Verifiable on its face: a real double-spend exhibits two different spending txids
// for one outpoint.
type ConflictEvidence struct {
	SpendA Hash // txid of the first spend
	SpendB Hash // txid of the conflicting spend
}

// Alert is a double-spend notification.
type Alert struct {
	Outpoint    Outpoint
	Evidence    ConflictEvidence
	AttesterPoW []byte // nonce whose hash over the alert meets PoWBits leading-zero bits
}

// PoWBits is the attestation difficulty: the alert digest must have at least this
// many leading zero bits. It is small here so tests can mine quickly; production
// sets it to a value tied to recent block difficulty (prior-PoW attestation, §3.2b).
const PoWBits = 12

// alertDigest binds outpoint + evidence + nonce into a single hash.
func alertDigest(a Alert) Hash {
	buf := make([]byte, 0, 32+4+32+32+len(a.AttesterPoW))
	buf = append(buf, a.Outpoint.TXID[:]...)
	var v [4]byte
	binary.LittleEndian.PutUint32(v[:], a.Outpoint.Vout)
	buf = append(buf, v[:]...)
	buf = append(buf, a.Evidence.SpendA[:]...)
	buf = append(buf, a.Evidence.SpendB[:]...)
	buf = append(buf, a.AttesterPoW...)
	return commitment.DoubleSHA256(buf)
}

func leadingZeroBits(h Hash) int {
	n := 0
	for _, b := range h {
		if b == 0 {
			n += 8
			continue
		}
		for bit := 7; bit >= 0; bit-- {
			if b&(1<<uint(bit)) == 0 {
				n++
			} else {
				return n
			}
		}
	}
	return n
}

// Attest finds a nonce so the alert meets PoWBits (prior-work attestation). It
// returns the completed alert. Used by an honest attester observing a conflict.
func Attest(out Outpoint, ev ConflictEvidence) Alert {
	a := Alert{Outpoint: out, Evidence: ev}
	var nonce uint64
	for {
		var nb [8]byte
		binary.LittleEndian.PutUint64(nb[:], nonce)
		a.AttesterPoW = nb[:]
		if leadingZeroBits(alertDigest(a)) >= PoWBits {
			return a
		}
		nonce++
	}
}

// VerifyAlert reports whether an alert is admissible (I-DS1). It requires:
//   - genuine conflict evidence: two DISTINCT spends of the SAME outpoint;
//   - a valid prior-work attestation meeting PoWBits.
//
// An alert failing either is dropped.
func VerifyAlert(a Alert) (ok bool) {
	if a.Evidence.SpendA == a.Evidence.SpendB {
		return false // not a conflict: same transaction
	}
	if a.Evidence.SpendA == (Hash{}) || a.Evidence.SpendB == (Hash{}) {
		return false // empty evidence
	}
	if leadingZeroBits(alertDigest(a)) < PoWBits {
		return false // unattested -> dropped (anti-flood)
	}
	return true
}

// ---------------------------------------------------------------------------
// Subscription + quiet-window query.
// ---------------------------------------------------------------------------

// IPv6Group is a multicast group address (modelled as a string here).
type IPv6Group string

// Bus is an in-process stand-in for the IPv6-multicast transport. It records
// verified alerts with timestamps so QuietFor can answer the merchant's policy.
type Bus struct {
	mu   sync.Mutex
	subs []chan Alert
	seen map[Outpoint]time.Time // last VERIFIED alert per outpoint
	now  func() time.Time
}

// NewBus creates an alert bus.
func NewBus() *Bus {
	return &Bus{seen: map[Outpoint]time.Time{}, now: time.Now}
}

// SetClock overrides the clock (tests).
func (b *Bus) SetClock(now func() time.Time) { b.now = now }

// Subscribe returns a channel of alerts for a group. (Group is advisory in this
// in-process model; all subscribers receive verified alerts.)
func (b *Bus) Subscribe(group IPv6Group) (<-chan Alert, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan Alert, 64)
	b.subs = append(b.subs, ch)
	return ch, nil
}

// Publish verifies an alert (I-DS1) and, only if admissible, records it and fans
// it out to subscribers. Unverifiable alerts are dropped silently (anti-flood).
// Returns whether the alert was accepted.
func (b *Bus) Publish(a Alert) bool {
	if !VerifyAlert(a) {
		return false
	}
	b.mu.Lock()
	b.seen[a.Outpoint] = b.now()
	subs := append([]chan Alert(nil), b.subs...)
	b.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- a:
		default: // never block the publisher
		}
	}
	return true
}

// QuietFor reports whether NONE of the outpoints has a verified alert within the
// trailing window. quiet==true means no conflicting-spend alert was seen.
func (b *Bus) QuietFor(outpoints []Outpoint, window time.Duration) (quiet bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cutoff := b.now().Add(-window)
	for _, op := range outpoints {
		if ts, ok := b.seen[op]; ok && ts.After(cutoff) {
			return false
		}
	}
	return true
}
