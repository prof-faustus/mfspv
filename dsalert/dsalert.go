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
	"mfspv/crypto"
)

type Hash = commitment.Hash

// Outpoint identifies the contested output.
type Outpoint struct {
	TXID Hash
	Vout uint32
}

// ConflictEvidence proves a genuine double-spend: the holder of OwnerPubKey
// authorised TWO DIFFERENT spends (SpendA != SpendB) of the SAME outpoint, by
// signing each. This is UNFORGEABLE without the owner's private key — closing the
// flood/censorship vector where anyone could assert a "conflict" from two random
// hashes (RT-2). The signed message for each spend is H(outpoint ‖ spendTxID).
type ConflictEvidence struct {
	OwnerPubKey []byte // 33-byte compressed key that authorised both spends
	SpendA      Hash   // txid of the first spend
	SigA        []byte // owner's signature over H(outpoint ‖ SpendA)
	SpendB      Hash   // txid of the conflicting spend
	SigB        []byte // owner's signature over H(outpoint ‖ SpendB)
}

// spendMessage is the digest the owner signs to authorise spending `outpoint` in
// the transaction `spendTx`.
func spendMessage(out Outpoint, spendTx Hash) Hash {
	buf := make([]byte, 0, 32+4+32)
	buf = append(buf, out.TXID[:]...)
	var v [4]byte
	binary.LittleEndian.PutUint32(v[:], out.Vout)
	buf = append(buf, v[:]...)
	buf = append(buf, spendTx[:]...)
	return commitment.DoubleSHA256(buf)
}

// SignSpend produces the owner's authorisation of spending `out` in `spendTx`.
// (Used to assemble genuine conflict evidence.)
func SignSpend(key *crypto.PrivateKey, out Outpoint, spendTx Hash) ([]byte, error) {
	msg := spendMessage(out, spendTx)
	sig, err := key.Sign(msg[:])
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
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

// alertDigest binds outpoint + full evidence + nonce into a single hash.
func alertDigest(a Alert) Hash {
	var b []byte
	b = append(b, a.Outpoint.TXID[:]...)
	var v [4]byte
	binary.LittleEndian.PutUint32(v[:], a.Outpoint.Vout)
	b = append(b, v[:]...)
	b = append(b, a.Evidence.OwnerPubKey...)
	b = append(b, a.Evidence.SpendA[:]...)
	b = append(b, a.Evidence.SigA...)
	b = append(b, a.Evidence.SpendB[:]...)
	b = append(b, a.Evidence.SigB...)
	b = append(b, a.AttesterPoW...)
	return commitment.DoubleSHA256(b)
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

// BuildEvidence assembles genuine, owner-signed double-spend evidence. It requires
// the owner's private key (i.e. only a party that can actually authorise the spends
// — the double-spender, or someone who observed both signed spends — can produce it).
func BuildEvidence(key *crypto.PrivateKey, out Outpoint, spendA, spendB Hash) (ConflictEvidence, error) {
	sigA, err := SignSpend(key, out, spendA)
	if err != nil {
		return ConflictEvidence{}, err
	}
	sigB, err := SignSpend(key, out, spendB)
	if err != nil {
		return ConflictEvidence{}, err
	}
	return ConflictEvidence{
		OwnerPubKey: key.Public().SerializeCompressed(),
		SpendA:      spendA, SigA: sigA,
		SpendB: spendB, SigB: sigB,
	}, nil
}

// Attest finds a nonce so the alert meets PoWBits (prior-work attestation) and
// returns the completed alert. Used by an honest attester relaying a conflict.
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
//   - two DISTINCT spends of the SAME outpoint;
//   - BOTH spends signed by the SAME owner key, with canonical (low-S) signatures
//     — i.e. cryptographic proof the key holder authorised a double-spend (RT-2);
//   - a valid prior-work attestation meeting PoWBits.
//
// An alert failing any check is dropped. Forging it requires the owner's private
// key, so it cannot be fabricated to flood/censor.
func VerifyAlert(a Alert) (ok bool) {
	ev := a.Evidence
	if ev.SpendA == ev.SpendB {
		return false // not a conflict: same transaction
	}
	if ev.SpendA == (Hash{}) || ev.SpendB == (Hash{}) {
		return false // empty evidence
	}
	pub, err := crypto.ParseCompressed(ev.OwnerPubKey)
	if err != nil {
		return false // no/invalid owner key
	}
	sigA, err := crypto.ParseSignature(ev.SigA)
	if err != nil || !sigA.IsLowS() {
		return false
	}
	sigB, err := crypto.ParseSignature(ev.SigB)
	if err != nil || !sigB.IsLowS() {
		return false
	}
	mA := spendMessage(a.Outpoint, ev.SpendA)
	mB := spendMessage(a.Outpoint, ev.SpendB)
	if !crypto.Verify(pub, mA[:], sigA) || !crypto.Verify(pub, mB[:], sigB) {
		return false // signatures do not prove the owner authorised both spends
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

// alertRec is one verified alert observation.
type alertRec struct {
	ts       time.Time
	ownerPub string // compressed owner pubkey that signed the conflict
}

// Bus is an in-process stand-in for the IPv6-multicast transport. It records
// verified alerts (with the signing owner key) so the merchant policy can be
// answered — including the owner-bound check that prevents third parties forging
// conflicts for outpoints they do not own (RT-7).
type Bus struct {
	mu   sync.Mutex
	subs []chan Alert
	seen map[Outpoint][]alertRec // verified alerts per outpoint
	now  func() time.Time
}

// NewBus creates an alert bus.
func NewBus() *Bus {
	return &Bus{seen: map[Outpoint][]alertRec{}, now: time.Now}
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
	b.seen[a.Outpoint] = append(b.seen[a.Outpoint], alertRec{ts: b.now(), ownerPub: string(a.Evidence.OwnerPubKey)})
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

// QuietFor reports whether NONE of the outpoints has ANY verified alert within the
// trailing window (advisory, owner-agnostic). For point-of-sale acceptance prefer
// QuietForOwners, which binds the alert to the spender's key (RT-7).
func (b *Bus) QuietFor(outpoints []Outpoint, window time.Duration) (quiet bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cutoff := b.now().Add(-window)
	for _, op := range outpoints {
		for _, rec := range b.seen[op] {
			if rec.ts.After(cutoff) {
				return false
			}
		}
	}
	return true
}

// QuietForOwners reports whether none of the (outpoint -> spender pubkey) pairs has
// a verified conflicting-spend alert SIGNED BY THAT SPENDER within the window.
//
// This is the point-of-sale check: only a double-spend authorised by the SAME key
// that is spending the output in the payment counts. A third party signing a bogus
// "conflict" for someone else's outpoint with their own key is ignored — closing
// the residual flood/censorship vector left by owner-agnostic checks (RT-7).
//
// owners maps each outpoint to the compressed pubkey used to spend it in the
// payment under evaluation. An outpoint absent from owners is treated owner-agnostic.
func (b *Bus) QuietForOwners(owners map[Outpoint][]byte, window time.Duration) (quiet bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cutoff := b.now().Add(-window)
	for op, pub := range owners {
		want := string(pub)
		for _, rec := range b.seen[op] {
			if !rec.ts.After(cutoff) {
				continue
			}
			if want == "" || rec.ownerPub == want {
				return false
			}
		}
	}
	return true
}
