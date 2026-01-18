// Package system implements the Solana System Program for X1-Nimbus.
//
// The System Program is responsible for:
//   - Creating new accounts
//   - Allocating account data
//   - Assigning program ownership
//   - Transferring lamports
//   - Managing nonce accounts
//
// All accounts are initially owned by the System Program until assigned
// to another program.
package system

import (
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/svm/syscall"
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// SystemProgram implements the Solana System Program.
type SystemProgram struct {
	// ProgramID is the System Program's public key
	ProgramID types.Pubkey
}

// New creates a new SystemProgram instance.
func New() *SystemProgram {
	return &SystemProgram{
		ProgramID: types.SystemProgramID,
	}
}

// Execute executes a System Program instruction.
// The instruction format is:
//   - First 4 bytes: instruction discriminator (little-endian uint32)
//   - Remaining bytes: instruction-specific data
func (p *SystemProgram) Execute(ctx *syscall.ExecutionContext, instruction []byte) error {
	// Parse the instruction discriminator
	discriminator, err := ParseInstructionDiscriminator(instruction)
	if err != nil {
		return err
	}

	// Get instruction data (everything after the discriminator)
	var instructionData []byte
	if len(instruction) > 4 {
		instructionData = instruction[4:]
	}

	// Route to the appropriate handler
	switch discriminator {
	case InstructionCreateAccount:
		var inst CreateAccountInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleCreateAccount(ctx, &inst)

	case InstructionAssign:
		var inst AssignInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleAssign(ctx, &inst)

	case InstructionTransfer:
		var inst TransferInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleTransfer(ctx, &inst)

	case InstructionCreateAccountWithSeed:
		var inst CreateAccountWithSeedInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleCreateAccountWithSeed(ctx, &inst)

	case InstructionAdvanceNonceAccount:
		var inst AdvanceNonceAccountInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleAdvanceNonceAccount(ctx, &inst)

	case InstructionWithdrawNonceAccount:
		var inst WithdrawNonceAccountInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleWithdrawNonceAccount(ctx, &inst)

	case InstructionInitializeNonceAccount:
		var inst InitializeNonceAccountInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleInitializeNonceAccount(ctx, &inst)

	case InstructionAuthorizeNonceAccount:
		var inst AuthorizeNonceAccountInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleAuthorizeNonceAccount(ctx, &inst)

	case InstructionAllocate:
		var inst AllocateInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleAllocate(ctx, &inst)

	case InstructionAllocateWithSeed:
		var inst AllocateWithSeedInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleAllocateWithSeed(ctx, &inst)

	case InstructionAssignWithSeed:
		var inst AssignWithSeedInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleAssignWithSeed(ctx, &inst)

	case InstructionTransferWithSeed:
		var inst TransferWithSeedInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleTransferWithSeed(ctx, &inst)

	default:
		return fmt.Errorf("%w: unknown instruction %d", ErrInvalidInstructionData, discriminator)
	}
}

// GetProgramID returns the System Program's public key.
func (p *SystemProgram) GetProgramID() types.Pubkey {
	return p.ProgramID
}

// IsSystemProgram checks if a pubkey is the System Program.
func IsSystemProgram(pubkey types.Pubkey) bool {
	return pubkey == types.SystemProgramID
}
