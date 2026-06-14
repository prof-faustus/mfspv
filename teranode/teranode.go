// Package teranode is the read-only adapter layer over a pinned Teranode revision
// (02_MODULE_SPECS.md §teranode_adapter). It declares the interfaces the rest of
// MF-SPV consumes — ProofSource, HeaderChain, UTXOClient — and ships an in-memory
// reference implementation (MockNode) that builds REAL sealed blocks (subtree and
// block Merkle trees) and a REAL header accumulator, so the bundle and wallet
// layers can be exercised end-to-end without a live node.
//
// I-TA1 (no consensus mutation): every interface here is READ-ONLY. There is no
// method that proposes or mutates header/block format. This is enforced at the
// type level — see the compile-time assertions in teranode_test.go (T6.1).
//
// BSV only.
package teranode

import (
	"errors"
	"sync"

	"mfspv/accumulator"
	"mfspv/commitment"
)

type Hash = commitment.Hash
type PathElem = commitment.PathElem
type TxFields = commitment.TxFields

// Outpoint identifies a transaction output.
type Outpoint struct {
	TXID Hash
	Vout uint32
}

// ProofSource yields the L1/L2/header/L4 material for a confirmed transaction.
// All methods are read-only (I-TA1).
type ProofSource interface {
	// SubtreePathFor returns the Teranode subtree membership path for txid (I-TA2,
	// <= 20 elems) and the subtree root it folds to.
	SubtreePathFor(txid Hash) (path []PathElem, subtreeRoot Hash, err error)
	// BlockPathFor returns the path from a subtree root to the block Merkle root.
	BlockPathFor(subtreeRoot Hash, blockHash Hash) (path []PathElem, root Hash, err error)
	// HeaderFor returns the 80-byte header of a block.
	HeaderFor(blockHash Hash) ([80]byte, error)
	// LocateTx maps a confirmed txid to the block that contains it. (Added during
	// implementation to bind txid->block; confirm exact accessor against the pinned
	// Teranode source — 01_ARCHITECTURE.md §7 dependency #2.)
	LocateTx(txid Hash) (blockHash Hash, err error)
	// GenTxAccumulator returns the L4 accumulator root committed in a block's
	// generation transaction, plus that gen-tx's own L0–L2 inclusion (OPTIONAL).
	GenTxAccumulator(blockHash Hash) (accRoot Hash, fields TxFields, l0, l1, l2 []PathElem, err error)
}

// HeaderChain is Bob's view of the most-work header chain (the constant
// ~4.2 MB/year dataset, or a pruned view backed by the L4 anchor).
type HeaderChain interface {
	Contains(h [80]byte) bool
	BestTipHeight() uint64
}

// UTXOClient answers liveness queries against the Teranode utxo/asset service.
// This is the DOUBLE-SPEND axis, kept orthogonal to inclusion (§6.3).
type UTXOClient interface {
	IsUnspent(outpoint Outpoint) (bool, error)
}

var (
	ErrUnknownTx     = errors.New("teranode: unknown transaction")
	ErrUnknownBlock  = errors.New("teranode: unknown block")
	ErrNoAccumulator = errors.New("teranode: block carries no accumulator commitment")
)

// accRootFieldIndex is the gen-tx field that carries the L4 accumulator root.
const accRootFieldIndex = 1

// ---------------------------------------------------------------------------
// MockNode — in-memory reference node that builds real sealed blocks.
// ---------------------------------------------------------------------------

type txEntry struct {
	blockHash    Hash
	subtreeIndex int
	leafIndex    int
}

type sealedBlock struct {
	hash         Hash
	height       uint64
	header       [80]byte
	subtreeRoots []Hash
	subtreeTrees [][][]Hash
	blockLayers  [][]Hash
	blockRoot    Hash

	isCarrier bool
	accRoot   Hash     // L4 root committed by this block (over strictly-prior headers)
	accPrefix uint64   // number of prior headers the committed accRoot covers (== height)
	genFields TxFields // generation-tx fields (carry accRoot at accRootFieldIndex)
}

// MockNode implements ProofSource, HeaderChain and UTXOClient over in-memory blocks.
type MockNode struct {
	mu          sync.RWMutex
	blocks      map[Hash]*sealedBlock
	txIndex     map[Hash]txEntry
	chain       []Hash
	headers     [][80]byte // chain-ordered, for accumulator reconstruction
	onBest      map[Hash]bool
	spent       map[Outpoint]bool
	subtreeSize int
}

// NewMockNode creates an empty node. subtreeCap is the max txids per subtree
// (Teranode uses 2^20; tests use small values).
func NewMockNode(subtreeCap int) *MockNode {
	if subtreeCap < 1 {
		subtreeCap = 1
	}
	return &MockNode{
		blocks:      map[Hash]*sealedBlock{},
		txIndex:     map[Hash]txEntry{},
		onBest:      map[Hash]bool{},
		spent:       map[Outpoint]bool{},
		subtreeSize: subtreeCap,
	}
}

// mmrRootOfPrefix returns the accumulator root over the first p headers (locked by
// caller). p==0 yields the empty-MMR zero root.
func (n *MockNode) mmrRootOfPrefix(p uint64) Hash {
	m := accumulator.NewMMR()
	for i := uint64(0); i < p && i < uint64(len(n.headers)); i++ {
		m.Append(n.headers[i])
	}
	return m.Root()
}

// SealBlock partitions txids into subtrees, builds the subtree and block trees,
// assembles an 80-byte header binding the block root, appends to the best chain,
// and returns the block hash. When commitAccumulator is true the block is a
// "carrying" block: its generation transaction commits the L4 accumulator root
// over all STRICTLY-PRIOR headers (the gen tx becomes leaf 0 of subtree 0).
func (n *MockNode) SealBlock(txids []Hash, commitAccumulator bool) (Hash, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(txids) == 0 {
		return Hash{}, errors.New("teranode: cannot seal an empty block")
	}
	height := uint64(len(n.chain))
	sb := &sealedBlock{height: height}

	leafSet := txids
	if commitAccumulator {
		accRoot := n.mmrRootOfPrefix(height) // over headers 0..height-1
		sb.isCarrier = true
		sb.accRoot = accRoot
		sb.accPrefix = height
		sb.genFields = TxFields{
			{Index: 0, Bytes: []byte("coinbase-marker")},
			{Index: accRootFieldIndex, Bytes: append([]byte(nil), accRoot[:]...)},
		}
		genMtxid, _, err := commitment.BuildMTxID(sb.genFields)
		if err != nil {
			return Hash{}, err
		}
		// gen tx is the first transaction of the block (leaf 0 of subtree 0).
		leafSet = append([]Hash{genMtxid}, txids...)
	}

	for start := 0; start < len(leafSet); start += n.subtreeSize {
		end := start + n.subtreeSize
		if end > len(leafSet) {
			end = len(leafSet)
		}
		leaves := make([]Hash, end-start)
		copy(leaves, leafSet[start:end])
		root, layers, err := commitment.BuildMerkleTree(leaves)
		if err != nil {
			return Hash{}, err
		}
		sb.subtreeRoots = append(sb.subtreeRoots, root)
		sb.subtreeTrees = append(sb.subtreeTrees, layers)
	}

	blockRoot, blockLayers, err := commitment.BuildMerkleTree(sb.subtreeRoots)
	if err != nil {
		return Hash{}, err
	}
	sb.blockRoot = blockRoot
	sb.blockLayers = blockLayers

	// Header: version(4) ‖ prevhash(32) ‖ merkleroot(32) ‖ time(4) ‖ bits(4) ‖ nonce(4).
	var hdr [80]byte
	hdr[0] = 0x01
	if len(n.chain) > 0 {
		prev := n.blocks[n.chain[len(n.chain)-1]]
		copy(hdr[4:36], prev.hash[:])
	}
	copy(hdr[36:68], blockRoot[:])
	hdr[68] = byte(height)
	hdr[69] = byte(height >> 8)
	sb.header = hdr
	sb.hash = commitment.DoubleSHA256(hdr[:])

	for st, layers := range sb.subtreeTrees {
		for li, txid := range layers[0] {
			n.txIndex[txid] = txEntry{blockHash: sb.hash, subtreeIndex: st, leafIndex: li}
		}
	}
	n.blocks[sb.hash] = sb
	n.chain = append(n.chain, sb.hash)
	n.headers = append(n.headers, hdr)
	n.onBest[sb.hash] = true
	return sb.hash, nil
}

// --- ProofSource ---

func (n *MockNode) SubtreePathFor(txid Hash) ([]PathElem, Hash, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	e, ok := n.txIndex[txid]
	if !ok {
		return nil, Hash{}, ErrUnknownTx
	}
	sb := n.blocks[e.blockHash]
	path, err := commitment.MerklePath(sb.subtreeTrees[e.subtreeIndex], e.leafIndex)
	if err != nil {
		return nil, Hash{}, err
	}
	return path, sb.subtreeRoots[e.subtreeIndex], nil
}

func (n *MockNode) BlockPathFor(subtreeRoot Hash, blockHash Hash) ([]PathElem, Hash, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	sb, ok := n.blocks[blockHash]
	if !ok {
		return nil, Hash{}, ErrUnknownBlock
	}
	idx := -1
	for i, r := range sb.subtreeRoots {
		if r == subtreeRoot {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, Hash{}, errors.New("teranode: subtree root not in block")
	}
	path, err := commitment.MerklePath(sb.blockLayers, idx)
	if err != nil {
		return nil, Hash{}, err
	}
	return path, sb.blockRoot, nil
}

func (n *MockNode) HeaderFor(blockHash Hash) ([80]byte, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	sb, ok := n.blocks[blockHash]
	if !ok {
		return [80]byte{}, ErrUnknownBlock
	}
	return sb.header, nil
}

func (n *MockNode) LocateTx(txid Hash) (Hash, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	e, ok := n.txIndex[txid]
	if !ok {
		return Hash{}, ErrUnknownTx
	}
	return e.blockHash, nil
}

// GenTxAccumulator returns the L4 anchor material for a carrying block: the
// committed accRoot, the gen-tx fields, and the gen tx's REAL L0–L2 inclusion
// (accRoot field -> gen MTxID -> subtree0 root -> block root). The carrying block
// Merkle root the verifier checks against is read from HeaderFor(blockHash).
func (n *MockNode) GenTxAccumulator(blockHash Hash) (Hash, TxFields, []PathElem, []PathElem, []PathElem, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	sb, ok := n.blocks[blockHash]
	if !ok {
		return Hash{}, nil, nil, nil, nil, ErrUnknownBlock
	}
	if !sb.isCarrier {
		return Hash{}, nil, nil, nil, nil, ErrNoAccumulator
	}
	_, l0, _, err := commitment.MTxIDPath(sb.genFields, accRootFieldIndex)
	if err != nil {
		return Hash{}, nil, nil, nil, nil, err
	}
	l1, err := commitment.MerklePath(sb.subtreeTrees[0], 0) // gen tx is leaf 0
	if err != nil {
		return Hash{}, nil, nil, nil, nil, err
	}
	l2, err := commitment.MerklePath(sb.blockLayers, 0) // subtree 0 -> block root
	if err != nil {
		return Hash{}, nil, nil, nil, nil, err
	}
	return sb.accRoot, sb.genFields, l0, l1, l2, nil
}

// ProveHeaderInAccumulator proves that the target block's header is committed in
// the accRoot carried by carrierHash. It returns the MMR path and the accRoot, or
// an error if the target is not within the carrier's committed prefix (i.e. the
// carrier was sealed before the target — an absent-period / ordering failure).
func (n *MockNode) ProveHeaderInAccumulator(targetHash, carrierHash Hash) ([]PathElem, Hash, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	carrier, ok := n.blocks[carrierHash]
	if !ok || !carrier.isCarrier {
		return nil, Hash{}, ErrNoAccumulator
	}
	target, ok := n.blocks[targetHash]
	if !ok {
		return nil, Hash{}, ErrUnknownBlock
	}
	if target.height >= carrier.accPrefix {
		return nil, Hash{}, errors.New("teranode: target not within carrier's committed prefix")
	}
	m := accumulator.NewMMR()
	for i := uint64(0); i < carrier.accPrefix; i++ {
		m.Append(n.headers[i])
	}
	return m.ProveBlock(target.height)
}

// --- HeaderChain ---

func (n *MockNode) Contains(h [80]byte) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	bh := commitment.DoubleSHA256(h[:])
	sb, ok := n.blocks[bh]
	if !ok {
		return false
	}
	return n.onBest[sb.hash]
}

func (n *MockNode) BestTipHeight() uint64 {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return uint64(len(n.chain))
}

// --- UTXOClient ---

func (n *MockNode) IsUnspent(o Outpoint) (bool, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return !n.spent[o], nil
}

// MarkSpent records an outpoint as spent (double-spend simulation).
func (n *MockNode) MarkSpent(o Outpoint) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.spent[o] = true
}

// Orphan removes a block from the best chain (reorg simulation).
func (n *MockNode) Orphan(blockHash Hash) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.onBest[blockHash] = false
}

// Restore puts a block back on the best chain (reorg settle).
func (n *MockNode) Restore(blockHash Hash) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.onBest[blockHash] = true
}

// BlockRoot exposes a sealed block's Merkle root (test helper).
func (n *MockNode) BlockRoot(blockHash Hash) (Hash, bool) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	sb, ok := n.blocks[blockHash]
	if !ok {
		return Hash{}, false
	}
	return sb.blockRoot, true
}

// StaticHeaderChain is a HeaderChain over an explicit set of headers — the model
// of a header-PRUNED verifier that retains only a recent window of headers (e.g.
// the carrying block used by an L4 anchor) rather than the whole chain.
type StaticHeaderChain struct {
	headers map[Hash]bool
	tip     uint64
}

// NewStaticHeaderChain builds a pruned view from a set of headers it trusts.
func NewStaticHeaderChain(headers [][80]byte, tip uint64) *StaticHeaderChain {
	m := map[Hash]bool{}
	for _, h := range headers {
		m[commitment.DoubleSHA256(h[:])] = true
	}
	return &StaticHeaderChain{headers: m, tip: tip}
}

func (s *StaticHeaderChain) Contains(h [80]byte) bool {
	return s.headers[commitment.DoubleSHA256(h[:])]
}
func (s *StaticHeaderChain) BestTipHeight() uint64 { return s.tip }

// Compile-time guarantees that the types satisfy the read-only interfaces.
var (
	_ ProofSource = (*MockNode)(nil)
	_ HeaderChain = (*MockNode)(nil)
	_ UTXOClient  = (*MockNode)(nil)
	_ HeaderChain = (*StaticHeaderChain)(nil)
)
