package accounts

import (
	"bytes"
	"sort"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

const (
	// merkleArity is the number of children per node in the Merkle tree.
	merkleArity = 16
)

// ComputeAccountsDeltaHash computes a 16-ary Merkle tree hash of the given accounts.
// Accounts are sorted by pubkey before computing the hash.
// This is used for computing the accounts delta hash in bank hashing.
func ComputeAccountsDeltaHash(accounts []types.AccountRef) types.Hash {
	if len(accounts) == 0 {
		return types.ZeroHash
	}

	// Sort accounts by pubkey
	sortedAccounts := make([]types.AccountRef, len(accounts))
	copy(sortedAccounts, accounts)
	sort.Slice(sortedAccounts, func(i, j int) bool {
		return bytes.Compare(sortedAccounts[i].Pubkey[:], sortedAccounts[j].Pubkey[:]) < 0
	})

	// Compute leaf hashes
	hashes := make([]types.Hash, len(sortedAccounts))
	for i, ref := range sortedAccounts {
		hashes[i] = ref.Account.Hash(ref.Pubkey)
	}

	// Build 16-ary Merkle tree from bottom up
	return computeMerkleRoot(hashes)
}

// computeMerkleRoot computes the root of a 16-ary Merkle tree.
func computeMerkleRoot(hashes []types.Hash) types.Hash {
	if len(hashes) == 0 {
		return types.ZeroHash
	}
	if len(hashes) == 1 {
		return hashes[0]
	}

	// Process level by level until we have a single root
	for len(hashes) > 1 {
		hashes = computeNextLevel(hashes)
	}

	return hashes[0]
}

// computeNextLevel computes the next level of the 16-ary Merkle tree.
func computeNextLevel(hashes []types.Hash) []types.Hash {
	numParents := (len(hashes) + merkleArity - 1) / merkleArity
	parents := make([]types.Hash, numParents)

	for i := 0; i < numParents; i++ {
		start := i * merkleArity
		end := start + merkleArity
		if end > len(hashes) {
			end = len(hashes)
		}

		parents[i] = hashChildren(hashes[start:end])
	}

	return parents
}

// hashChildren computes the hash of a group of child nodes.
func hashChildren(children []types.Hash) types.Hash {
	if len(children) == 0 {
		return types.ZeroHash
	}
	if len(children) == 1 {
		return children[0]
	}

	// Concatenate all child hashes and compute SHA256
	data := make([]byte, 0, len(children)*32)
	for _, child := range children {
		data = append(data, child[:]...)
	}

	return types.SHA256(data)
}
