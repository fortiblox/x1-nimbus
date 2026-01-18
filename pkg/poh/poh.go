// Package poh provides Proof of History verification for X1-Nimbus.
//
// Proof of History (PoH) is a cryptographic clock that provides a verifiable
// ordering of events. Each entry in the PoH chain contains a hash that is
// derived from the previous entry's hash through a series of SHA256 iterations.
//
// The PoH chain works as follows:
//   - Each entry has a NumHashes count and a Hash
//   - For tick entries (no transactions): hash = SHA256^numHashes(prevHash)
//   - For transaction entries: hash = SHA256(prevHash || tx_merkle_root), then iterate
package poh

import (
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// Verifier tracks and verifies the Proof of History chain.
type Verifier struct {
	// currentHash is the hash of the most recently verified entry (or initial hash).
	currentHash types.Hash

	// tickCount tracks the total number of ticks verified.
	tickCount uint64
}

// NewVerifier creates a new PoH verifier starting from the given initial hash.
// The initial hash is typically the previous blockhash or genesis hash.
func NewVerifier(initialHash types.Hash) *Verifier {
	return &Verifier{
		currentHash: initialHash,
		tickCount:   0,
	}
}

// VerifyEntry verifies a single PoH entry against the current state.
// It checks that the entry's hash matches the expected computed hash.
// On success, it advances the verifier state to this entry.
func (v *Verifier) VerifyEntry(entry *types.Entry) error {
	if entry == nil {
		return ErrInvalidEntry
	}

	if entry.NumHashes == 0 {
		return ErrInvalidNumHashes
	}

	// Compute the expected hash for this entry
	expectedHash := ComputeEntryHash(v.currentHash, entry.NumHashes, entry.Transactions)

	// Verify the entry hash matches
	if entry.Hash != expectedHash {
		return fmt.Errorf("%w: expected %s, got %s",
			ErrHashMismatch,
			expectedHash.String(),
			entry.Hash.String())
	}

	// Advance state
	v.currentHash = entry.Hash
	if entry.IsTick() {
		v.tickCount++
	}

	return nil
}

// VerifyEntries verifies a sequence of PoH entries.
// All entries must be valid and form a continuous chain from the current state.
// On success, the verifier state is advanced to the last entry.
// On failure, the verifier state remains at the last successfully verified entry.
func (v *Verifier) VerifyEntries(entries []types.Entry) error {
	for i := range entries {
		if err := v.VerifyEntry(&entries[i]); err != nil {
			return fmt.Errorf("entry %d: %w", i, err)
		}
	}
	return nil
}

// Reset resets the verifier to a new starting hash.
// This is useful when switching to verify a new block or starting from a checkpoint.
func (v *Verifier) Reset(hash types.Hash) {
	v.currentHash = hash
	v.tickCount = 0
}

// CurrentHash returns the current hash (the hash of the last verified entry).
func (v *Verifier) CurrentHash() types.Hash {
	return v.currentHash
}

// TickCount returns the total number of tick entries verified since creation or reset.
func (v *Verifier) TickCount() uint64 {
	return v.tickCount
}
