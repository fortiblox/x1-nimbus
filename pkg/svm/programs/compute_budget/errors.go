// Package compute_budget implements the Solana Compute Budget Program for X1-Nimbus.
package compute_budget

import "errors"

// Compute Budget Program errors
var (
	// ErrInvalidInstructionData indicates the instruction data is malformed.
	ErrInvalidInstructionData = errors.New("invalid instruction data")

	// ErrInvalidHeapFrameSize indicates the heap frame size is not properly aligned.
	ErrInvalidHeapFrameSize = errors.New("invalid heap frame size: must be multiple of 1024 bytes")

	// ErrHeapFrameSizeTooLarge indicates the heap frame size exceeds maximum.
	ErrHeapFrameSizeTooLarge = errors.New("heap frame size too large: maximum is 256KB")

	// ErrComputeUnitLimitTooHigh indicates the compute unit limit exceeds maximum.
	ErrComputeUnitLimitTooHigh = errors.New("compute unit limit too high: maximum is 1,400,000")

	// ErrDuplicateInstruction indicates only one of each instruction type is allowed per transaction.
	ErrDuplicateInstruction = errors.New("duplicate compute budget instruction: only one of each type allowed per transaction")

	// ErrUnknownInstruction indicates an unknown instruction type was received.
	ErrUnknownInstruction = errors.New("unknown compute budget instruction")
)
