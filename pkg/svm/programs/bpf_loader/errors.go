// Package bpf_loader implements the BPF Loader Upgradeable program for X1-Nimbus.
package bpf_loader

import "errors"

// BPF Loader Upgradeable errors
var (
	// ErrInvalidAccountData indicates the account data is invalid or corrupted.
	ErrInvalidAccountData = errors.New("invalid account data")

	// ErrAccountNotExecutable indicates the account is not marked as executable.
	ErrAccountNotExecutable = errors.New("account is not executable")

	// ErrInvalidAuthority indicates the provided authority is invalid.
	ErrInvalidAuthority = errors.New("invalid authority")

	// ErrAuthorityMismatch indicates the authority does not match.
	ErrAuthorityMismatch = errors.New("authority mismatch")

	// ErrMissingAuthority indicates a required authority is missing.
	ErrMissingAuthority = errors.New("missing required authority")

	// ErrImmutable indicates the program is immutable (no upgrade authority).
	ErrImmutable = errors.New("program is immutable")

	// ErrInvalidInstructionData indicates the instruction data is malformed.
	ErrInvalidInstructionData = errors.New("invalid instruction data")

	// ErrAccountNotSigner indicates a required signer is missing.
	ErrAccountNotSigner = errors.New("account is not a signer")

	// ErrAccountNotWritable indicates a required writable account is not writable.
	ErrAccountNotWritable = errors.New("account is not writable")

	// ErrInsufficientFunds indicates insufficient funds for the operation.
	ErrInsufficientFunds = errors.New("insufficient funds")

	// ErrAccountNotRentExempt indicates the account would not be rent exempt.
	ErrAccountNotRentExempt = errors.New("account not rent exempt")

	// ErrInvalidProgramDataAccount indicates an invalid program data account.
	ErrInvalidProgramDataAccount = errors.New("invalid program data account")

	// ErrInvalidBufferAccount indicates an invalid buffer account.
	ErrInvalidBufferAccount = errors.New("invalid buffer account")

	// ErrInvalidProgramAccount indicates an invalid program account.
	ErrInvalidProgramAccount = errors.New("invalid program account")

	// ErrWriteOffsetOutOfBounds indicates the write offset is out of bounds.
	ErrWriteOffsetOutOfBounds = errors.New("write offset out of bounds")

	// ErrAccountAlreadyInitialized indicates the account is already initialized.
	ErrAccountAlreadyInitialized = errors.New("account already initialized")

	// ErrAccountNotInitialized indicates the account is not initialized.
	ErrAccountNotInitialized = errors.New("account not initialized")

	// ErrInvalidELF indicates the ELF binary is invalid.
	ErrInvalidELF = errors.New("invalid ELF binary")

	// ErrProgramNotUpgradeable indicates the program cannot be upgraded.
	ErrProgramNotUpgradeable = errors.New("program is not upgradeable")

	// ErrMaxDataLenExceeded indicates the max data length has been exceeded.
	ErrMaxDataLenExceeded = errors.New("max data length exceeded")

	// ErrDataLenTooSmall indicates the data length is too small.
	ErrDataLenTooSmall = errors.New("data length too small for program")

	// ErrAccountOwnerMismatch indicates the account owner does not match.
	ErrAccountOwnerMismatch = errors.New("account owner mismatch")

	// ErrInvalidRecipient indicates an invalid recipient account.
	ErrInvalidRecipient = errors.New("invalid recipient account")

	// ErrCannotCloseWhileExecuting indicates the account cannot be closed while executing.
	ErrCannotCloseWhileExecuting = errors.New("cannot close account while program is executing")

	// ErrExtendProgramFailed indicates extending the program failed.
	ErrExtendProgramFailed = errors.New("failed to extend program")
)
