// Package geyser provides a Geyser gRPC client for streaming blocks, transactions, and accounts.
// Geyser is Solana's high-performance streaming interface for real-time blockchain data.
package geyser

import (
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// Commitment levels for subscription filters.
const (
	CommitmentProcessed = "processed"
	CommitmentConfirmed = "confirmed"
	CommitmentFinalized = "finalized"
)

// SlotStatus represents the status of a slot.
type SlotStatus int

const (
	SlotStatusProcessed SlotStatus = iota
	SlotStatusConfirmed
	SlotStatusFinalized
	SlotStatusRooted // Legacy, same as finalized
)

// String returns the string representation of SlotStatus.
func (s SlotStatus) String() string {
	switch s {
	case SlotStatusProcessed:
		return "processed"
	case SlotStatusConfirmed:
		return "confirmed"
	case SlotStatusFinalized, SlotStatusRooted:
		return "finalized"
	default:
		return "unknown"
	}
}

// ParseSlotStatus parses a slot status string.
func ParseSlotStatus(s string) SlotStatus {
	switch s {
	case "processed":
		return SlotStatusProcessed
	case "confirmed":
		return SlotStatusConfirmed
	case "finalized":
		return SlotStatusFinalized
	case "rooted":
		return SlotStatusRooted
	default:
		return SlotStatusProcessed
	}
}

// SlotUpdate represents an update to a slot's status.
type SlotUpdate struct {
	Slot       types.Slot // The slot number
	Parent     types.Slot // Parent slot number
	Status     SlotStatus // Current status of the slot
	Timestamp  int64      // Unix timestamp when the update was received
}

// IsConfirmed returns true if the slot is at least confirmed.
func (s *SlotUpdate) IsConfirmed() bool {
	return s.Status >= SlotStatusConfirmed
}

// IsFinalized returns true if the slot is finalized.
func (s *SlotUpdate) IsFinalized() bool {
	return s.Status >= SlotStatusFinalized
}

// BlockUpdate represents a block update from Geyser.
type BlockUpdate struct {
	Slot       types.Slot   // The slot containing this block
	Block      *types.Block // The block data
	Commitment string       // Commitment level at which this was received
	Timestamp  int64        // Unix timestamp when the update was received
}

// AccountUpdate represents an account update from Geyser.
type AccountUpdate struct {
	Pubkey    types.Pubkey   // The account's public key
	Account   *types.Account // The account data
	Slot      types.Slot     // Slot at which this update occurred
	WriteVersion uint64      // Write version for ordering updates
	Timestamp int64          // Unix timestamp when the update was received
}

// IsEmpty returns true if the account was deleted or is empty.
func (a *AccountUpdate) IsEmpty() bool {
	return a.Account == nil || a.Account.IsEmpty()
}

// TransactionUpdate represents a transaction update from Geyser.
type TransactionUpdate struct {
	Signature   types.Signature    // Transaction signature
	Slot        types.Slot         // Slot containing this transaction
	Transaction *types.Transaction // The transaction data
	IsVote      bool               // Whether this is a vote transaction
	Success     bool               // Whether the transaction succeeded
	Timestamp   int64              // Unix timestamp when the update was received
}

// SubscriptionFilter defines filters for subscriptions.
type SubscriptionFilter struct {
	// Accounts to watch (empty means all)
	Accounts []types.Pubkey

	// Programs to watch transactions for (empty means all)
	Programs []types.Pubkey

	// Whether to include vote transactions
	IncludeVotes bool

	// Whether to include failed transactions
	IncludeFailed bool

	// Commitment level
	Commitment string
}

// DefaultFilter returns a default subscription filter.
func DefaultFilter() *SubscriptionFilter {
	return &SubscriptionFilter{
		Commitment:    CommitmentConfirmed,
		IncludeVotes:  false,
		IncludeFailed: true,
	}
}

// WithAccounts adds account filters.
func (f *SubscriptionFilter) WithAccounts(accounts ...types.Pubkey) *SubscriptionFilter {
	f.Accounts = append(f.Accounts, accounts...)
	return f
}

// WithPrograms adds program filters.
func (f *SubscriptionFilter) WithPrograms(programs ...types.Pubkey) *SubscriptionFilter {
	f.Programs = append(f.Programs, programs...)
	return f
}

// WithVotes enables vote transaction inclusion.
func (f *SubscriptionFilter) WithVotes() *SubscriptionFilter {
	f.IncludeVotes = true
	return f
}

// WithCommitment sets the commitment level.
func (f *SubscriptionFilter) WithCommitment(commitment string) *SubscriptionFilter {
	f.Commitment = commitment
	return f
}

// StreamStats tracks statistics for a subscription stream.
type StreamStats struct {
	BlocksReceived       uint64
	TransactionsReceived uint64
	AccountsReceived     uint64
	SlotsReceived        uint64
	Reconnects           uint64
	Errors               uint64
	LastSlot             types.Slot
	LastBlockTime        int64
}

// SubscriptionError represents an error from a subscription.
type SubscriptionError struct {
	Message     string
	Code        int
	Recoverable bool
	Slot        types.Slot
}

// Error implements the error interface.
func (e *SubscriptionError) Error() string {
	return e.Message
}

// IsRecoverable returns true if the error can be recovered by reconnecting.
func (e *SubscriptionError) IsRecoverable() bool {
	return e.Recoverable
}
