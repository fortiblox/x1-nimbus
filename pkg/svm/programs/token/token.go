// Package token implements the SPL Token Program for X1-Nimbus.
//
// The Token Program handles fungible tokens on Solana:
//   - Creating and managing token mints
//   - Initializing token accounts
//   - Transferring tokens between accounts
//   - Minting and burning tokens
//   - Delegating and revoking token spending authority
//   - Freezing and thawing token accounts
//
// Program ID: TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
package token

import (
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/svm/syscall"
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// TokenProgram implements the SPL Token Program.
type TokenProgram struct {
	// ProgramID is the Token Program's public key
	ProgramID types.Pubkey
}

// New creates a new TokenProgram instance.
func New() *TokenProgram {
	return &TokenProgram{
		ProgramID: types.TokenProgramID,
	}
}

// Execute executes a Token Program instruction.
// The instruction format is:
//   - First byte: instruction discriminator
//   - Remaining bytes: instruction-specific data
func (p *TokenProgram) Execute(ctx *syscall.ExecutionContext, instruction *types.Instruction) error {
	if len(instruction.Data) < 1 {
		return fmt.Errorf("%w: instruction data too short", ErrInvalidInstructionData)
	}

	// Parse the instruction discriminator
	discriminator, err := ParseInstructionDiscriminator(instruction.Data)
	if err != nil {
		return err
	}

	// Get instruction data (everything after the discriminator)
	var instructionData []byte
	if len(instruction.Data) > 1 {
		instructionData = instruction.Data[1:]
	}

	// Route to the appropriate handler
	switch discriminator {
	case InstructionInitializeMint:
		var inst InitializeMintInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleInitializeMint(ctx, &inst)

	case InstructionInitializeAccount:
		var inst InitializeAccountInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleInitializeAccount(ctx)

	case InstructionInitializeMultisig:
		// Multisig is not fully implemented yet
		return fmt.Errorf("%w: InitializeMultisig not yet implemented", ErrInvalidInstruction)

	case InstructionTransfer:
		var inst TransferInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleTransfer(ctx, &inst)

	case InstructionApprove:
		var inst ApproveInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleApprove(ctx, &inst)

	case InstructionRevoke:
		var inst RevokeInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleRevoke(ctx)

	case InstructionSetAuthority:
		var inst SetAuthorityInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleSetAuthority(ctx, &inst)

	case InstructionMintTo:
		var inst MintToInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleMintTo(ctx, &inst)

	case InstructionBurn:
		var inst BurnInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleBurn(ctx, &inst)

	case InstructionCloseAccount:
		var inst CloseAccountInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleCloseAccount(ctx)

	case InstructionFreezeAccount:
		var inst FreezeAccountInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleFreezeAccount(ctx)

	case InstructionThawAccount:
		var inst ThawAccountInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleThawAccount(ctx)

	case InstructionTransferChecked:
		var inst TransferCheckedInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleTransferChecked(ctx, &inst)

	case InstructionApproveChecked:
		var inst ApproveCheckedInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleApproveChecked(ctx, &inst)

	case InstructionMintToChecked:
		var inst MintToCheckedInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleMintToChecked(ctx, &inst)

	case InstructionBurnChecked:
		var inst BurnCheckedInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleBurnChecked(ctx, &inst)

	case InstructionInitializeAccount2, InstructionInitializeAccount3:
		// These are variants of InitializeAccount
		return handleInitializeAccount(ctx)

	case InstructionSyncNative:
		// SyncNative updates native account balance
		return fmt.Errorf("%w: SyncNative not yet implemented", ErrInvalidInstruction)

	case InstructionInitializeMint2:
		// InitializeMint2 is similar to InitializeMint but without rent sysvar
		var inst InitializeMintInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleInitializeMint(ctx, &inst)

	default:
		return fmt.Errorf("%w: unknown instruction %d", ErrInvalidInstruction, discriminator)
	}
}

// GetProgramID returns the Token Program's public key.
func (p *TokenProgram) GetProgramID() types.Pubkey {
	return p.ProgramID
}

// IsTokenProgram checks if a pubkey is the Token Program.
func IsTokenProgram(pubkey types.Pubkey) bool {
	return pubkey == types.TokenProgramID
}

// IsToken2022Program checks if a pubkey is the Token-2022 Program.
func IsToken2022Program(pubkey types.Pubkey) bool {
	return pubkey == types.Token2022ProgramID
}
