// Package compute_budget implements the Solana Compute Budget Program for X1-Nimbus.
//
// The Compute Budget Program allows transactions to:
//   - Request additional heap memory (RequestHeapFrame)
//   - Set compute unit limits (SetComputeUnitLimit)
//   - Set priority fees (SetComputeUnitPrice)
//   - Limit loaded account data size (SetLoadedAccountsDataSizeLimit)
//
// These instructions are processed during transaction loading, not during
// program execution. They configure the runtime environment for the transaction.
//
// Note: Unlike most programs, Compute Budget instructions don't modify state.
// They only set parameters that affect how the transaction is processed.
package compute_budget

import (
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/svm/syscall"
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// ComputeBudgetProgramID is the program ID for the Compute Budget Program.
var ComputeBudgetProgramID = types.MustPubkeyFromBase58("ComputeBudget111111111111111111111111111111")

// ComputeBudgetProgram implements the Solana Compute Budget Program.
type ComputeBudgetProgram struct {
	// ProgramID is the Compute Budget Program's public key
	ProgramID types.Pubkey

	// State holds the current compute budget parameters for the transaction
	State *ComputeBudgetState
}

// New creates a new ComputeBudgetProgram instance.
func New() *ComputeBudgetProgram {
	return &ComputeBudgetProgram{
		ProgramID: ComputeBudgetProgramID,
		State:     NewComputeBudgetState(),
	}
}

// NewWithState creates a new ComputeBudgetProgram instance with an existing state.
// This is useful for processing multiple compute budget instructions in a transaction.
func NewWithState(state *ComputeBudgetState) *ComputeBudgetProgram {
	return &ComputeBudgetProgram{
		ProgramID: ComputeBudgetProgramID,
		State:     state,
	}
}

// Execute executes a Compute Budget Program instruction.
// The instruction format is:
//   - First byte: instruction type
//   - Remaining bytes: instruction-specific data
//
// Note: Compute Budget instructions are typically processed during transaction
// loading/preparation, not during normal program execution. When executed,
// they validate parameters and update the compute budget state.
func (p *ComputeBudgetProgram) Execute(ctx *syscall.ExecutionContext, instruction []byte) error {
	// Parse the instruction type (first byte)
	instructionType, err := ParseInstructionType(instruction)
	if err != nil {
		return err
	}

	// Get instruction data (everything after the type byte)
	var instructionData []byte
	if len(instruction) > 1 {
		instructionData = instruction[1:]
	}

	// Route to the appropriate handler
	switch instructionType {
	case InstructionRequestHeapFrame:
		var inst RequestHeapFrameInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleRequestHeapFrame(ctx, p.State, &inst)

	case InstructionSetComputeUnitLimit:
		var inst SetComputeUnitLimitInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleSetComputeUnitLimit(ctx, p.State, &inst)

	case InstructionSetComputeUnitPrice:
		var inst SetComputeUnitPriceInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleSetComputeUnitPrice(ctx, p.State, &inst)

	case InstructionSetLoadedAccountsDataSizeLimit:
		var inst SetLoadedAccountsDataSizeLimitInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleSetLoadedAccountsDataSizeLimit(ctx, p.State, &inst)

	default:
		return fmt.Errorf("%w: %d", ErrUnknownInstruction, instructionType)
	}
}

// GetProgramID returns the Compute Budget Program's public key.
func (p *ComputeBudgetProgram) GetProgramID() types.Pubkey {
	return p.ProgramID
}

// GetState returns the current compute budget state.
func (p *ComputeBudgetProgram) GetState() *ComputeBudgetState {
	return p.State
}

// ResetState resets the compute budget state to defaults.
// This should be called between transactions.
func (p *ComputeBudgetProgram) ResetState() {
	p.State = NewComputeBudgetState()
}

// IsComputeBudgetProgram checks if a pubkey is the Compute Budget Program.
func IsComputeBudgetProgram(pubkey types.Pubkey) bool {
	return pubkey == ComputeBudgetProgramID
}

// ProcessTransactionInstructions processes all compute budget instructions in a transaction.
// This is typically called during transaction loading to extract budget parameters.
// Returns the aggregated compute budget state.
func ProcessTransactionInstructions(ctx *syscall.ExecutionContext, instructions [][]byte) (*ComputeBudgetState, error) {
	state := NewComputeBudgetState()
	program := NewWithState(state)

	for _, instruction := range instructions {
		if err := program.Execute(ctx, instruction); err != nil {
			return nil, err
		}
	}

	return state, nil
}

// ValidateAndExtractBudget validates compute budget instructions and extracts parameters.
// This is a convenience function for transaction preprocessing.
func ValidateAndExtractBudget(instructions [][]byte) (*ComputeBudgetState, error) {
	state := NewComputeBudgetState()

	for _, instruction := range instructions {
		if len(instruction) == 0 {
			continue
		}

		instructionType := instruction[0]
		var instructionData []byte
		if len(instruction) > 1 {
			instructionData = instruction[1:]
		}

		switch instructionType {
		case InstructionRequestHeapFrame:
			if state.hasRequestedHeapFrame {
				return nil, fmt.Errorf("%w: RequestHeapFrame", ErrDuplicateInstruction)
			}
			state.hasRequestedHeapFrame = true

			var inst RequestHeapFrameInstruction
			if err := inst.Decode(instructionData); err != nil {
				return nil, err
			}
			if inst.HeapFrameSize%HeapFrameAlignment != 0 {
				return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidHeapFrameSize, inst.HeapFrameSize)
			}
			if inst.HeapFrameSize > MaxHeapFrameSize {
				return nil, fmt.Errorf("%w: got %d bytes", ErrHeapFrameSizeTooLarge, inst.HeapFrameSize)
			}
			state.HeapFrameSize = inst.HeapFrameSize

		case InstructionSetComputeUnitLimit:
			if state.hasSetComputeUnitLimit {
				return nil, fmt.Errorf("%w: SetComputeUnitLimit", ErrDuplicateInstruction)
			}
			state.hasSetComputeUnitLimit = true

			var inst SetComputeUnitLimitInstruction
			if err := inst.Decode(instructionData); err != nil {
				return nil, err
			}
			if inst.ComputeUnitLimit > MaxComputeUnits {
				return nil, fmt.Errorf("%w: got %d", ErrComputeUnitLimitTooHigh, inst.ComputeUnitLimit)
			}
			state.ComputeUnitLimit = inst.ComputeUnitLimit

		case InstructionSetComputeUnitPrice:
			if state.hasSetComputeUnitPrice {
				return nil, fmt.Errorf("%w: SetComputeUnitPrice", ErrDuplicateInstruction)
			}
			state.hasSetComputeUnitPrice = true

			var inst SetComputeUnitPriceInstruction
			if err := inst.Decode(instructionData); err != nil {
				return nil, err
			}
			state.ComputeUnitPrice = inst.MicroLamportsPerComputeUnit

		case InstructionSetLoadedAccountsDataSizeLimit:
			if state.hasSetLoadedAccountsDataLimit {
				return nil, fmt.Errorf("%w: SetLoadedAccountsDataSizeLimit", ErrDuplicateInstruction)
			}
			state.hasSetLoadedAccountsDataLimit = true

			var inst SetLoadedAccountsDataSizeLimitInstruction
			if err := inst.Decode(instructionData); err != nil {
				return nil, err
			}
			state.LoadedAccountsDataSizeLimit = inst.DataSizeLimit

		default:
			return nil, fmt.Errorf("%w: %d", ErrUnknownInstruction, instructionType)
		}
	}

	return state, nil
}
