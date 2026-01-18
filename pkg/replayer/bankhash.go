// Package replayer provides block replay and verification for X1-Nimbus.
//
// This package implements the bank hash computation and block verification
// logic necessary to validate blocks against the network's consensus state.
// The bank hash is the critical verification output - if our computed hash
// matches the network's hash, we have verified the block correctly.
package replayer

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"sync"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// ComputeBankHash computes the bank hash for a block.
//
// Formula: SHA256(parent_bankhash || accounts_delta_hash || signature_count_le || blockhash)
//
// Parameters:
//   - parentBankHash: The bank hash of the parent block
//   - accountsDeltaHash: Hash of all account changes in this block
//   - signatureCount: Total number of signatures in this block (little-endian)
//   - blockhash: The blockhash of this block
//
// Returns the computed bank hash.
func ComputeBankHash(parentBankHash, accountsDeltaHash types.Hash, signatureCount uint64, blockhash types.Hash) types.Hash {
	h := sha256.New()

	// Parent bank hash (32 bytes)
	h.Write(parentBankHash[:])

	// Accounts delta hash (32 bytes)
	h.Write(accountsDeltaHash[:])

	// Signature count (8 bytes, little-endian)
	var sigCountBuf [8]byte
	binary.LittleEndian.PutUint64(sigCountBuf[:], signatureCount)
	h.Write(sigCountBuf[:])

	// Blockhash (32 bytes)
	h.Write(blockhash[:])

	var result types.Hash
	copy(result[:], h.Sum(nil))
	return result
}

// AccountDeltaEntry represents a single account change for hashing.
type AccountDeltaEntry struct {
	Pubkey  types.Pubkey
	Account *types.Account
}

// ComputeAccountsDeltaHash computes the hash of all account deltas.
// This uses a Merkle-tree approach for deterministic hashing of account changes.
//
// The account deltas must be sorted by pubkey for determinism.
// Each account contributes: Hash(pubkey || account_hash)
func ComputeAccountsDeltaHash(deltas []AccountDeltaEntry) types.Hash {
	if len(deltas) == 0 {
		return types.ZeroHash
	}

	// Sort deltas by pubkey for determinism
	sorted := make([]AccountDeltaEntry, len(deltas))
	copy(sorted, deltas)
	sort.Slice(sorted, func(i, j int) bool {
		for k := 0; k < 32; k++ {
			if sorted[i].Pubkey[k] != sorted[j].Pubkey[k] {
				return sorted[i].Pubkey[k] < sorted[j].Pubkey[k]
			}
		}
		return false
	})

	// Compute individual account hashes
	leaves := make([]types.Hash, len(sorted))
	for i, delta := range sorted {
		leaves[i] = computeAccountDeltaLeaf(delta.Pubkey, delta.Account)
	}

	// Compute Merkle root
	return computeMerkleRoot(leaves)
}

// computeAccountDeltaLeaf computes the hash for a single account delta.
// Format: SHA256(pubkey || account_hash)
func computeAccountDeltaLeaf(pubkey types.Pubkey, account *types.Account) types.Hash {
	h := sha256.New()
	h.Write(pubkey[:])

	if account != nil {
		accountHash := account.Hash(pubkey)
		h.Write(accountHash[:])
	} else {
		// Deleted account - use zero hash
		h.Write(types.ZeroHash[:])
	}

	var result types.Hash
	copy(result[:], h.Sum(nil))
	return result
}

// computeMerkleRoot computes the Merkle root from a list of leaf hashes.
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

// BankHasher provides incremental computation of the bank hash.
// It collects account deltas and other block data, then computes
// the final bank hash when Compute() is called.
type BankHasher struct {
	mu sync.Mutex

	parentBankHash types.Hash
	deltas         []AccountDeltaEntry
	signatureCount uint64
	blockhash      types.Hash
	blockhashSet   bool
}

// NewBankHasher creates a new BankHasher starting from the parent bank hash.
func NewBankHasher(parentBankHash types.Hash) *BankHasher {
	return &BankHasher{
		parentBankHash: parentBankHash,
		deltas:         make([]AccountDeltaEntry, 0, 256),
	}
}

// AddAccountDelta adds an account delta to the hasher.
// The account can be nil to indicate a deleted account.
func (bh *BankHasher) AddAccountDelta(pubkey types.Pubkey, account *types.Account) {
	bh.mu.Lock()
	defer bh.mu.Unlock()

	bh.deltas = append(bh.deltas, AccountDeltaEntry{
		Pubkey:  pubkey,
		Account: account,
	})
}

// AddAccountDeltas adds multiple account deltas to the hasher.
func (bh *BankHasher) AddAccountDeltas(deltas []types.AccountDelta) {
	bh.mu.Lock()
	defer bh.mu.Unlock()

	for _, delta := range deltas {
		bh.deltas = append(bh.deltas, AccountDeltaEntry{
			Pubkey:  delta.Pubkey,
			Account: delta.NewAccount,
		})
	}
}

// IncrementSignatureCount increments the signature count by the given amount.
func (bh *BankHasher) IncrementSignatureCount(count uint64) {
	bh.mu.Lock()
	defer bh.mu.Unlock()
	bh.signatureCount += count
}

// SetSignatureCount sets the total signature count.
func (bh *BankHasher) SetSignatureCount(count uint64) {
	bh.mu.Lock()
	defer bh.mu.Unlock()
	bh.signatureCount = count
}

// SetBlockhash sets the blockhash.
func (bh *BankHasher) SetBlockhash(hash types.Hash) {
	bh.mu.Lock()
	defer bh.mu.Unlock()
	bh.blockhash = hash
	bh.blockhashSet = true
}

// GetSignatureCount returns the current signature count.
func (bh *BankHasher) GetSignatureCount() uint64 {
	bh.mu.Lock()
	defer bh.mu.Unlock()
	return bh.signatureCount
}

// GetDeltaCount returns the current number of account deltas.
func (bh *BankHasher) GetDeltaCount() int {
	bh.mu.Lock()
	defer bh.mu.Unlock()
	return len(bh.deltas)
}

// Compute computes and returns the final bank hash.
func (bh *BankHasher) Compute() types.Hash {
	bh.mu.Lock()
	defer bh.mu.Unlock()

	// Compute accounts delta hash
	accountsDeltaHash := ComputeAccountsDeltaHash(bh.deltas)

	// Compute the bank hash
	return ComputeBankHash(bh.parentBankHash, accountsDeltaHash, bh.signatureCount, bh.blockhash)
}

// ComputeAccountsDelta computes and returns just the accounts delta hash.
func (bh *BankHasher) ComputeAccountsDelta() types.Hash {
	bh.mu.Lock()
	defer bh.mu.Unlock()
	return ComputeAccountsDeltaHash(bh.deltas)
}

// Reset resets the hasher for a new block with a new parent bank hash.
func (bh *BankHasher) Reset(parentBankHash types.Hash) {
	bh.mu.Lock()
	defer bh.mu.Unlock()

	bh.parentBankHash = parentBankHash
	bh.deltas = bh.deltas[:0]
	bh.signatureCount = 0
	bh.blockhash = types.ZeroHash
	bh.blockhashSet = false
}

// Clone creates a copy of the current BankHasher state.
func (bh *BankHasher) Clone() *BankHasher {
	bh.mu.Lock()
	defer bh.mu.Unlock()

	clone := &BankHasher{
		parentBankHash: bh.parentBankHash,
		deltas:         make([]AccountDeltaEntry, len(bh.deltas)),
		signatureCount: bh.signatureCount,
		blockhash:      bh.blockhash,
		blockhashSet:   bh.blockhashSet,
	}

	for i, delta := range bh.deltas {
		clone.deltas[i] = AccountDeltaEntry{
			Pubkey:  delta.Pubkey,
			Account: delta.Account.Clone(),
		}
	}

	return clone
}
