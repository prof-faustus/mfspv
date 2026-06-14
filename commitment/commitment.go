// Package commitment builds and verifies levels L0–L2 of the MF-SPV commitment
// hierarchy (01_ARCHITECTURE.md §2, 02_MODULE_SPECS.md §commitment):
//
//	L0  field            -> MTxID = TXID   (Merkle tree over transaction FIELDS; US 2022/0216997)
//	L1  TXID             -> subtree root   (Teranode subtree, <= 2^20 TXIDs)
//	L2  subtree root     -> block root     (block Merkle root built over subtree roots)
//
// Hash: SHA-256d (double SHA-256), 32-byte digests. The package is PURE: it
// imports no client/transport package and never touches the network (I-C2).
//
// BSV only. No BTC parameters, no BTC code paths.
package commitment

import (
	"crypto/sha256"
	"errors"
	"math/bits"
)

// Hash is a 32-byte SHA-256d digest. It is the canonical digest type shared by
// every MF-SPV module.
type Hash [32]byte

// PathElem is one sibling on a Merkle path, ordered leaf->root.
//
// Right == true  means the sibling is the RIGHT child, so parent = H(node ‖ sibling).
// Right == false means the sibling is the LEFT child,  so parent = H(sibling ‖ node).
type PathElem struct {
	Sibling Hash
	Right   bool
}

// FieldLeaf is a single transaction field (an L0 leaf), per US 2022/0216997 Fig.6.
type FieldLeaf struct {
	Index uint8
	Bytes []byte
}

// TxFields is the ordered field list of a transaction (US 2022/0216997 Fig.6 layout).
type TxFields []FieldLeaf

// MaxDepth is the one-byte depth ceiling from Appendix_2_Merkle (max depth 255).
// A path longer than this is a hard error (I-C3); it cannot occur below 2^255 leaves.
const MaxDepth = 255

// ErrDepthOverflow is returned when a path exceeds MaxDepth (I-C3 / T1.6).
var ErrDepthOverflow = errors.New("commitment: path depth exceeds 255 (one-byte marker overflow)")

// ErrEmpty is returned when a tree is requested over zero leaves.
var ErrEmpty = errors.New("commitment: cannot build a Merkle tree over zero leaves")

// ---------------------------------------------------------------------------
// SHA-256d Merkle core
// ---------------------------------------------------------------------------

// DoubleSHA256 returns SHA-256d(b) = SHA-256(SHA-256(b)).
func DoubleSHA256(b []byte) Hash {
	first := sha256.Sum256(b)
	return Hash(sha256.Sum256(first[:]))
}

// HashPair returns SHA-256d(left ‖ right) — the internal-node hash.
func HashPair(left, right Hash) Hash {
	var buf [64]byte
	copy(buf[:32], left[:])
	copy(buf[32:], right[:])
	return DoubleSHA256(buf[:])
}

// leafHash binds a field's INDEX into its leaf digest so a field cannot be moved
// to another position without changing the root (a second-preimage / reordering
// guard on the L0 tree).
func leafHash(f FieldLeaf) Hash {
	buf := make([]byte, 1+len(f.Bytes))
	buf[0] = f.Index
	copy(buf[1:], f.Bytes)
	return DoubleSHA256(buf)
}

// BuildMerkleTree builds the full level structure of a SHA-256d Merkle tree using
// Bitcoin/Teranode's odd-node duplication rule (an odd final node is paired with
// itself). layers[0] is the leaf level; the last layer holds the single root.
func BuildMerkleTree(leaves []Hash) (root Hash, layers [][]Hash, err error) {
	if len(leaves) == 0 {
		return Hash{}, nil, ErrEmpty
	}
	level := make([]Hash, len(leaves))
	copy(level, leaves)
	layers = append(layers, level)
	for len(level) > 1 {
		next := make([]Hash, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left // duplicate the last node when the level is odd
			if i+1 < len(level) {
				right = level[i+1]
			}
			next = append(next, HashPair(left, right))
		}
		layers = append(layers, next)
		level = next
	}
	return layers[len(layers)-1][0], layers, nil
}

// MerkleRoot returns just the root of the leaves.
func MerkleRoot(leaves []Hash) (Hash, error) {
	root, _, err := BuildMerkleTree(leaves)
	return root, err
}

// MerklePath returns the leaf->root sibling path for the leaf at index, matching
// BuildMerkleTree's duplication rule.
func MerklePath(layers [][]Hash, index int) ([]PathElem, error) {
	if len(layers) == 0 || index < 0 || index >= len(layers[0]) {
		return nil, errors.New("commitment: leaf index out of range")
	}
	var path []PathElem
	idx := index
	for level := 0; level < len(layers)-1; level++ {
		cur := layers[level]
		if idx%2 == 0 {
			// node is a left child; sibling is the right child (or itself if odd tail).
			sib := idx
			if idx+1 < len(cur) {
				sib = idx + 1
			}
			path = append(path, PathElem{Sibling: cur[sib], Right: true})
		} else {
			// node is a right child; sibling is the left child.
			path = append(path, PathElem{Sibling: cur[idx-1], Right: false})
		}
		idx /= 2
	}
	return path, nil
}

// Fold collapses a leaf up its path to the implied root. It is the single
// verification primitive used everywhere.
func Fold(leaf Hash, path []PathElem) Hash {
	node := leaf
	for _, e := range path {
		if e.Right {
			node = HashPair(node, e.Sibling)
		} else {
			node = HashPair(e.Sibling, node)
		}
	}
	return node
}

// CeilLog2 returns ceil(log2(n)) for n >= 1, computed exactly on integers
// (no float rounding) — this is the inclusion depth law of 03_SCALING_MODEL.md.
func CeilLog2(n uint64) int {
	if n <= 1 {
		return 0
	}
	return bits.Len64(n - 1)
}

// ---------------------------------------------------------------------------
// L0 — field tree (MTxID == TXID, unified form)
// ---------------------------------------------------------------------------

// BuildMTxID builds the L0 field tree; root == MTxID == TXID (unified form).
//
// INVARIANT: re-running on identical fields yields the identical root (determinism).
// INVARIANT: storing only mtxid + fields suffices to rebuild layers (US 2022/0216997 [0166]).
func BuildMTxID(fields TxFields) (mtxid Hash, layers [][]Hash, err error) {
	if len(fields) == 0 {
		return Hash{}, nil, ErrEmpty
	}
	leaves := make([]Hash, len(fields))
	for i, f := range fields {
		leaves[i] = leafHash(f)
	}
	return BuildMerkleTree(leaves)
}

// MTxIDPath returns the L0 path for a single revealed field (privacy: one field,
// not the whole transaction — I-B3 / §6.6). fieldIndex is the slice position.
func MTxIDPath(fields TxFields, fieldIndex uint8) (leaf Hash, path []PathElem, mtxid Hash, err error) {
	if int(fieldIndex) >= len(fields) {
		return Hash{}, nil, Hash{}, errors.New("commitment: field index out of range")
	}
	root, layers, err := BuildMTxID(fields)
	if err != nil {
		return Hash{}, nil, Hash{}, err
	}
	path, err = MerklePath(layers, int(fieldIndex))
	if err != nil {
		return Hash{}, nil, Hash{}, err
	}
	return leafHash(fields[fieldIndex]), path, root, nil
}

// LeafForField recomputes the L0 leaf digest for a revealed field. A verifier that
// holds only the revealed field uses this to start the fold.
func LeafForField(f FieldLeaf) Hash { return leafHash(f) }

// VerifyMTxIDPath reports whether folding leaf along path equals mtxid.
// ok ⇔ fold(leaf,path)==mtxid, and the path is within the depth ceiling.
func VerifyMTxIDPath(leaf Hash, path []PathElem, mtxid Hash) (ok bool) {
	if len(path) > MaxDepth {
		return false
	}
	return Fold(leaf, path) == mtxid
}

// ---------------------------------------------------------------------------
// L1 — TXID -> subtree root
// ---------------------------------------------------------------------------

// VerifySubtreePath reports whether txid folds to subtreeRoot along path.
// CONDITION: |path| <= 20 for a <=2^20-leaf subtree; ok ⇔ fold(txid,path)==subtreeRoot.
func VerifySubtreePath(txid Hash, path []PathElem, subtreeRoot Hash) (ok bool) {
	if len(path) > 20 { // a Teranode subtree holds <= 2^20 TXIDs (I-TA2 / I-C3)
		return false
	}
	return Fold(txid, path) == subtreeRoot
}

// ---------------------------------------------------------------------------
// L2 — subtree root -> block Merkle root
// ---------------------------------------------------------------------------

// VerifyBlockPath reports whether subtreeRoot folds to blockMerkleRoot along path.
func VerifyBlockPath(subtreeRoot Hash, path []PathElem, blockMerkleRoot Hash) (ok bool) {
	if len(path) > MaxDepth {
		return false
	}
	return Fold(subtreeRoot, path) == blockMerkleRoot
}

// ---------------------------------------------------------------------------
// Composed core verification L0->L2 (the hot path Bob runs)
// ---------------------------------------------------------------------------

// VerifyToBlockRoot verifies a full L0->L2 inclusion in one call.
//
//	leaf : the revealed field's leaf digest (LeafForField). To verify from a known
//	       TXID directly, pass leaf=txid and l0=nil.
//	l0   : field -> mtxid(=TXID)
//	l1   : TXID  -> subtree root
//	l2   : subtree root -> block Merkle root
//
// depth == |l0|+|l1|+|l2|. For a block of T txs over 2^20-subtrees with l0 empty,
// depth == ceil(log2 T) (asserted by 04_TEST_PLAN §T1.3). A total depth > MaxDepth
// is a hard rejection (I-C3 / T1.6).
func VerifyToBlockRoot(leaf Hash, l0, l1, l2 []PathElem, blockMerkleRoot Hash) (ok bool, depth int) {
	depth = len(l0) + len(l1) + len(l2)
	if depth > MaxDepth || len(l1) > 20 {
		return false, depth
	}
	mtxid := Fold(leaf, l0) // L0: field -> MTxID == TXID
	sub := Fold(mtxid, l1)  // L1: TXID  -> subtree root
	root := Fold(sub, l2)   // L2: subtree root -> block root
	return root == blockMerkleRoot, depth
}
