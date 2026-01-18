// Package system implements the Solana System Program for X1-Nimbus.
package system

import "errors"

// System Program errors
var (
	// ErrInsufficientFunds indicates the source account has insufficient lamports.
	ErrInsufficientFunds = errors.New("insufficient funds for operation")

	// ErrAccountAlreadyExists indicates an account already exists at the address.
	ErrAccountAlreadyExists = errors.New("account already exists")

	// ErrAccountNotRentExempt indicates the account would not be rent exempt.
	ErrAccountNotRentExempt = errors.New("account not rent exempt")

	// ErrInvalidAccountOwner indicates the account owner is invalid for this operation.
	ErrInvalidAccountOwner = errors.New("invalid account owner")

	// ErrInvalidInstructionData indicates the instruction data is malformed.
	ErrInvalidInstructionData = errors.New("invalid instruction data")

	// ErrAccountNotSigner indicates a required signer is missing.
	ErrAccountNotSigner = errors.New("account is not a signer")

	// ErrAccountNotWritable indicates a required writable account is not writable.
	ErrAccountNotWritable = errors.New("account is not writable")

	// ErrInvalidAccountDataLength indicates the account data length is invalid.
	ErrInvalidAccountDataLength = errors.New("invalid account data length")

	// ErrAccountDataTooSmall indicates the allocated space is too small.
	ErrAccountDataTooSmall = errors.New("account data too small")

	// ErrAccountDataTooLarge indicates the allocated space exceeds maximum.
	ErrAccountDataTooLarge = errors.New("account data too large")

	// ErrInvalidSeed indicates an invalid seed was provided.
	ErrInvalidSeed = errors.New("invalid seed")

	// ErrMissingRequiredSignature indicates a required signature is missing.
	ErrMissingRequiredSignature = errors.New("missing required signature")

	// ErrNonceAccountNotInitialized indicates the nonce account is not initialized.
	ErrNonceAccountNotInitialized = errors.New("nonce account not initialized")

	// ErrNonceBlockhashNotExpired indicates the nonce blockhash has not expired.
	ErrNonceBlockhashNotExpired = errors.New("nonce blockhash not expired")

	// ErrInvalidNonceAuthority indicates the nonce authority is invalid.
	ErrInvalidNonceAuthority = errors.New("invalid nonce authority")
)
