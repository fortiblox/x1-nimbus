// Package stake implements the Solana Stake Program for X1-Nimbus.
package stake

import "errors"

// Stake Program errors
var (
	// ErrInsufficientFunds indicates insufficient lamports for the operation.
	ErrInsufficientFunds = errors.New("insufficient funds for stake operation")

	// ErrInvalidInstructionData indicates malformed instruction data.
	ErrInvalidInstructionData = errors.New("invalid instruction data")

	// ErrAccountNotSigner indicates a required signer is missing.
	ErrAccountNotSigner = errors.New("account is not a signer")

	// ErrAccountNotWritable indicates a required writable account is not writable.
	ErrAccountNotWritable = errors.New("account is not writable")

	// ErrInvalidAccountOwner indicates the account owner is invalid.
	ErrInvalidAccountOwner = errors.New("invalid account owner")

	// ErrInvalidStakeAccount indicates the stake account is invalid.
	ErrInvalidStakeAccount = errors.New("invalid stake account")

	// ErrStakeAccountNotInitialized indicates the stake account is not initialized.
	ErrStakeAccountNotInitialized = errors.New("stake account not initialized")

	// ErrStakeAccountAlreadyInitialized indicates the stake account is already initialized.
	ErrStakeAccountAlreadyInitialized = errors.New("stake account already initialized")

	// ErrStakeNotDelegated indicates the stake is not delegated.
	ErrStakeNotDelegated = errors.New("stake not delegated")

	// ErrStakeAlreadyDelegated indicates the stake is already delegated.
	ErrStakeAlreadyDelegated = errors.New("stake already delegated")

	// ErrStakeNotDeactivated indicates the stake is not deactivated.
	ErrStakeNotDeactivated = errors.New("stake not deactivated")

	// ErrStakeAlreadyDeactivated indicates the stake is already deactivated.
	ErrStakeAlreadyDeactivated = errors.New("stake already deactivated")

	// ErrInvalidAuthorization indicates an authorization error.
	ErrInvalidAuthorization = errors.New("invalid authorization")

	// ErrLockupInEffect indicates the lockup period is still in effect.
	ErrLockupInEffect = errors.New("lockup still in effect")

	// ErrInvalidLockup indicates invalid lockup parameters.
	ErrInvalidLockup = errors.New("invalid lockup parameters")

	// ErrInvalidVoteAccount indicates the vote account is invalid.
	ErrInvalidVoteAccount = errors.New("invalid vote account")

	// ErrStakeTooSmall indicates the stake amount is too small.
	ErrStakeTooSmall = errors.New("stake too small")

	// ErrMergeTransientStake indicates cannot merge transient stake.
	ErrMergeTransientStake = errors.New("cannot merge transient stake")

	// ErrMergeMismatch indicates stake accounts cannot be merged due to mismatch.
	ErrMergeMismatch = errors.New("stake accounts cannot be merged")

	// ErrCustodianMissing indicates the custodian signature is missing.
	ErrCustodianMissing = errors.New("custodian signature required")

	// ErrCustodianNotSigner indicates the custodian is not a signer.
	ErrCustodianNotSigner = errors.New("custodian is not a signer")

	// ErrInsufficientDelegation indicates insufficient stake for minimum delegation.
	ErrInsufficientDelegation = errors.New("insufficient stake for minimum delegation")

	// ErrInvalidStakeState indicates the stake account is in an invalid state.
	ErrInvalidStakeState = errors.New("invalid stake state for this operation")

	// ErrEpochRewardsActive indicates epoch rewards are currently active.
	ErrEpochRewardsActive = errors.New("epoch rewards active")

	// ErrInvalidStakeAuthorize indicates invalid stake authorize type.
	ErrInvalidStakeAuthorize = errors.New("invalid stake authorize type")

	// ErrRedelegateTransientOrInactiveStake indicates cannot redelegate transient or inactive stake.
	ErrRedelegateTransientOrInactiveStake = errors.New("cannot redelegate transient or inactive stake")

	// ErrRedelegateToSameVoteAccount indicates cannot redelegate to same vote account.
	ErrRedelegateToSameVoteAccount = errors.New("cannot redelegate to same vote account")
)
