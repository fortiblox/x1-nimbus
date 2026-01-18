package poh

import (
	"crypto/sha256"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// ComputeEntryHash computes the PoH hash for an entry given the previous hash,
// the number of hash iterations, and the transactions in the entry.
//
// For tick entries (no transactions): hash = SHA256^numHashes(prevHash)
// For transaction entries: hash = SHA256(prevHash || tx_merkle_root), then iterate numHashes-1 times
func ComputeEntryHash(prevHash types.Hash, numHashes uint64, transactions []types.Transaction) types.Hash {
	if numHashes == 0 {
		return prevHash
	}

	var hash types.Hash

	if len(transactions) == 0 {
		// Tick entry: iterate SHA256 numHashes times on the previous hash
		hash = prevHash
		for i := uint64(0); i < numHashes; i++ {
			hash = sha256.Sum256(hash[:])
		}
	} else {
		// Transaction entry: mix in the transaction merkle root first
		merkleRoot := computeTransactionMerkleRoot(transactions)

		// First hash: SHA256(prevHash || merkle_root)
		h := sha256.New()
		h.Write(prevHash[:])
		h.Write(merkleRoot[:])
		copy(hash[:], h.Sum(nil))

		// Iterate remaining numHashes-1 times
		for i := uint64(1); i < numHashes; i++ {
			hash = sha256.Sum256(hash[:])
		}
	}

	return hash
}

// computeTransactionMerkleRoot computes the merkle root of transaction signatures.
// This uses the first signature of each transaction as the leaf.
func computeTransactionMerkleRoot(transactions []types.Transaction) types.Hash {
	if len(transactions) == 0 {
		return types.ZeroHash
	}

	// Extract signature hashes as leaves
	leaves := make([]types.Hash, len(transactions))
	for i, tx := range transactions {
		if len(tx.Signatures) > 0 {
			// Use the first signature (transaction ID) as the leaf
			leaves[i] = sha256.Sum256(tx.Signatures[0][:])
		} else {
			leaves[i] = types.ZeroHash
		}
	}

	// Build merkle tree bottom-up
	return computeMerkleRoot(leaves)
}

// computeMerkleRoot computes the merkle root from a list of leaf hashes.
func computeMerkleRoot(leaves []types.Hash) types.Hash {
	if len(leaves) == 0 {
		return types.ZeroHash
	}
	if len(leaves) == 1 {
		return leaves[0]
	}

	// Copy leaves to avoid mutating the input
	current := make([]types.Hash, len(leaves))
	copy(current, leaves)

	// Build tree level by level
	for len(current) > 1 {
		next := make([]types.Hash, (len(current)+1)/2)

		for i := 0; i < len(current); i += 2 {
			if i+1 < len(current) {
				// Hash pair of nodes
				h := sha256.New()
				h.Write(current[i][:])
				h.Write(current[i+1][:])
				copy(next[i/2][:], h.Sum(nil))
			} else {
				// Odd node: promote to next level
				next[i/2] = current[i]
			}
		}

		current = next
	}

	return current[0]
}
