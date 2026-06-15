package fabric

import "mfspv/teranode"

// Fetch is the PULL half of SPV (proof acquisition): given a transaction id, ask a
// node (ProofSource) for the Merkle path and the block that prove the tx is mined,
// and assemble a verifiable inclusion Proof. This is the classic SPV step — "Bob has
// a new tx and needs its block + path" — and it composes with VerifyOne/BatchVerify.
//
// Per 07 §5 the inclusion leaf is the consensus TXID, so no transaction fields are
// needed: the node supplies TXID->subtree (L1), subtree->block (L2), and the header.
// The returned Proof must then be checked against the verifier's most-work header
// chain (VerifyOne(..., chain)); Fetch only retrieves, it does not trust.
func Fetch(txid Hash, src teranode.ProofSource) (Proof, error) {
	l1, subRoot, err := src.SubtreePathFor(txid) // TXID -> subtree root (the Merkle path)
	if err != nil {
		return Proof{}, err
	}
	blockHash, err := src.LocateTx(txid) // which block contains the tx
	if err != nil {
		return Proof{}, err
	}
	l2, _, err := src.BlockPathFor(subRoot, blockHash) // subtree root -> block Merkle root
	if err != nil {
		return Proof{}, err
	}
	hdr, err := src.HeaderFor(blockHash) // the 80-byte block header
	if err != nil {
		return Proof{}, err
	}
	return Proof{Leaf: txid, L1: l1, SubtreeRoot: subRoot, L2: l2, Header: hdr}, nil
}
