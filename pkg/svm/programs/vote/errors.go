// Package vote implements the Solana Vote Program for X1-Nimbus.
package vote

import "errors"

// Vote Program errors
var (
	// ErrInvalidInstructionData indicates the instruction data is malformed.
	ErrInvalidInstructionData = errors.New("invalid instruction data")

	// ErrAccountNotSigner indicates a required signer is missing.
	ErrAccountNotSigner = errors.New("account is not a signer")

	// ErrAccountNotWritable indicates a required writable account is not writable.
	ErrAccountNotWritable = errors.New("account is not writable")

	// ErrInvalidAccountOwner indicates the account owner is invalid for this operation.
	ErrInvalidAccountOwner = errors.New("invalid account owner")

	// ErrVoteAccountNotInitialized indicates the vote account is not initialized.
	ErrVoteAccountNotInitialized = errors.New("vote account not initialized")

	// ErrVoteAccountAlreadyInitialized indicates the vote account is already initialized.
	ErrVoteAccountAlreadyInitialized = errors.New("vote account already initialized")

	// ErrInsufficientFunds indicates insufficient funds for the operation.
	ErrInsufficientFunds = errors.New("insufficient funds")

	// ErrUnauthorized indicates the signer is not authorized for this operation.
	ErrUnauthorized = errors.New("unauthorized")

	// ErrInvalidCommission indicates an invalid commission value (must be 0-100).
	ErrInvalidCommission = errors.New("invalid commission value")

	// ErrInvalidVote indicates the vote is invalid.
	ErrInvalidVote = errors.New("invalid vote")

	// ErrSlotHashMismatch indicates the slot hash does not match.
	ErrSlotHashMismatch = errors.New("slot hash mismatch")

	// ErrVoteTooOld indicates the vote is for a slot that is too old.
	ErrVoteTooOld = errors.New("vote too old")

	// ErrSlotsNotOrdered indicates vote slots are not properly ordered.
	ErrSlotsNotOrdered = errors.New("vote slots not ordered")

	// ErrConfirmationsNotOrdered indicates confirmations are not properly ordered.
	ErrConfirmationsNotOrdered = errors.New("confirmations not ordered")

	// ErrEmptySlots indicates no slots were provided in the vote.
	ErrEmptySlots = errors.New("empty slots")

	// ErrTooManyVotes indicates too many votes were provided.
	ErrTooManyVotes = errors.New("too many votes")

	// ErrInvalidAuthorizeType indicates an invalid authorization type.
	ErrInvalidAuthorizeType = errors.New("invalid authorize type")

	// ErrAccountNotRentExempt indicates the account would not be rent exempt.
	ErrAccountNotRentExempt = errors.New("account not rent exempt")

	// ErrVotesTooOldAllFiltered indicates all votes were filtered out as too old.
	ErrVotesTooOldAllFiltered = errors.New("all votes filtered out as too old")

	// ErrRootRollback indicates an attempted rollback of the root slot.
	ErrRootRollback = errors.New("root rollback")

	// ErrActiveVoteAccountClose indicates an attempt to close an active vote account.
	ErrActiveVoteAccountClose = errors.New("cannot close active vote account")

	// ErrTimestampTooOld indicates the timestamp is too old.
	ErrTimestampTooOld = errors.New("timestamp too old")

	// ErrZeroConfirmations indicates zero confirmations were provided.
	ErrZeroConfirmations = errors.New("zero confirmations")

	// ErrLockoutConflict indicates a lockout conflict.
	ErrLockoutConflict = errors.New("lockout conflict")
)
