// Package address_lookup_table implements the Address Lookup Table Program for X1-Nimbus.
package address_lookup_table

import "errors"

// Address Lookup Table Program errors
var (
	// ErrInvalidInstructionData indicates the instruction data is malformed.
	ErrInvalidInstructionData = errors.New("invalid instruction data")

	// ErrAccountNotSigner indicates a required signer is missing.
	ErrAccountNotSigner = errors.New("account is not a signer")

	// ErrAccountNotWritable indicates a required writable account is not writable.
	ErrAccountNotWritable = errors.New("account is not writable")

	// ErrInvalidAuthority indicates the authority is invalid for this operation.
	ErrInvalidAuthority = errors.New("invalid authority")

	// ErrTableFrozen indicates the lookup table has been frozen (authority removed).
	ErrTableFrozen = errors.New("lookup table is frozen")

	// ErrTableNotFrozen indicates the lookup table is not yet frozen.
	ErrTableNotFrozen = errors.New("lookup table is not frozen")

	// ErrTableNotDeactivated indicates the lookup table is not deactivated.
	ErrTableNotDeactivated = errors.New("lookup table is not deactivated")

	// ErrTableStillActive indicates the lookup table is still active (not ready to close).
	ErrTableStillActive = errors.New("lookup table is still active")

	// ErrDeactivationCooldownNotExpired indicates the deactivation cooldown has not expired.
	ErrDeactivationCooldownNotExpired = errors.New("deactivation cooldown not expired")

	// ErrTableAlreadyDeactivated indicates the lookup table is already deactivated.
	ErrTableAlreadyDeactivated = errors.New("lookup table already deactivated")

	// ErrMaxAddressesExceeded indicates the maximum number of addresses would be exceeded.
	ErrMaxAddressesExceeded = errors.New("maximum addresses exceeded (256 limit)")

	// ErrDuplicateAddress indicates a duplicate address was provided.
	ErrDuplicateAddress = errors.New("duplicate address in lookup table")

	// ErrInvalidAccountOwner indicates the account owner is invalid for this operation.
	ErrInvalidAccountOwner = errors.New("invalid account owner")

	// ErrInvalidDerivedAddress indicates the derived address does not match.
	ErrInvalidDerivedAddress = errors.New("invalid derived address")

	// ErrInsufficientFunds indicates insufficient lamports for the operation.
	ErrInsufficientFunds = errors.New("insufficient funds")

	// ErrAccountAlreadyExists indicates an account already exists at the address.
	ErrAccountAlreadyExists = errors.New("account already exists")

	// ErrInvalidSlot indicates an invalid slot was provided.
	ErrInvalidSlot = errors.New("invalid slot")

	// ErrInvalidBumpSeed indicates an invalid bump seed was provided.
	ErrInvalidBumpSeed = errors.New("invalid bump seed")

	// ErrNoAddressesToExtend indicates no addresses were provided to extend.
	ErrNoAddressesToExtend = errors.New("no addresses to extend")
)
