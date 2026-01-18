// Package token implements the SPL Token Program for X1-Nimbus.
package token

import "errors"

// Token Program errors
var (
	// ErrInsufficientFunds indicates insufficient token balance.
	ErrInsufficientFunds = errors.New("insufficient funds")

	// ErrInvalidMint indicates the mint account is invalid.
	ErrInvalidMint = errors.New("invalid mint")

	// ErrMintMismatch indicates a token account's mint doesn't match the expected mint.
	ErrMintMismatch = errors.New("mint mismatch")

	// ErrOwnerMismatch indicates the owner doesn't match.
	ErrOwnerMismatch = errors.New("owner mismatch")

	// ErrAccountFrozen indicates the token account is frozen.
	ErrAccountFrozen = errors.New("account is frozen")

	// ErrAlreadyInitialized indicates the account is already initialized.
	ErrAlreadyInitialized = errors.New("already initialized")

	// ErrNotInitialized indicates the account is not initialized.
	ErrNotInitialized = errors.New("not initialized")

	// ErrInvalidAccountData indicates the account data is malformed.
	ErrInvalidAccountData = errors.New("invalid account data")

	// ErrInvalidInstruction indicates the instruction is invalid.
	ErrInvalidInstruction = errors.New("invalid instruction")

	// ErrInvalidInstructionData indicates the instruction data is malformed.
	ErrInvalidInstructionData = errors.New("invalid instruction data")

	// ErrInvalidAccountOwner indicates the account is not owned by the Token Program.
	ErrInvalidAccountOwner = errors.New("invalid account owner")

	// ErrAccountNotSigner indicates a required signer is missing.
	ErrAccountNotSigner = errors.New("account is not a signer")

	// ErrAccountNotWritable indicates a required writable account is not writable.
	ErrAccountNotWritable = errors.New("account is not writable")

	// ErrMissingRequiredSignature indicates a required signature is missing.
	ErrMissingRequiredSignature = errors.New("missing required signature")

	// ErrDelegateNotFound indicates no delegate is set.
	ErrDelegateNotFound = errors.New("delegate not found")

	// ErrNoAuthority indicates no authority is set for the operation.
	ErrNoAuthority = errors.New("no authority")

	// ErrInvalidAuthority indicates the authority is invalid.
	ErrInvalidAuthority = errors.New("invalid authority")

	// ErrAuthorityMismatch indicates the authority doesn't match.
	ErrAuthorityMismatch = errors.New("authority mismatch")

	// ErrFixedSupply indicates the mint has a fixed supply (no mint authority).
	ErrFixedSupply = errors.New("fixed supply")

	// ErrMintCannotFreeze indicates the mint cannot freeze accounts (no freeze authority).
	ErrMintCannotFreeze = errors.New("mint cannot freeze")

	// ErrAccountHasBalance indicates the account still has a balance.
	ErrAccountHasBalance = errors.New("account has balance")

	// ErrNonNativeAccountHasBalance indicates a non-native account still has balance.
	ErrNonNativeAccountHasBalance = errors.New("non-native account has balance")

	// ErrNativeNotSupported indicates native token operations are not supported.
	ErrNativeNotSupported = errors.New("native not supported")

	// ErrNonNativeNotSupported indicates the operation only works on native accounts.
	ErrNonNativeNotSupported = errors.New("non-native not supported")

	// ErrInvalidNumberOfAccounts indicates an incorrect number of accounts were provided.
	ErrInvalidNumberOfAccounts = errors.New("invalid number of accounts")

	// ErrDecimalsMismatch indicates the decimals don't match.
	ErrDecimalsMismatch = errors.New("decimals mismatch")

	// ErrOverflow indicates an arithmetic overflow.
	ErrOverflow = errors.New("overflow")
)
