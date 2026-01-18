// Package vote implements the Solana Vote Program for X1-Nimbus.
//
// The Vote Program is responsible for:
//   - Managing validator vote accounts
//   - Recording validator votes for consensus
//   - Tracking vote credits and rewards
//   - Managing authorized voters and withdrawers
//   - Commission configuration for stake rewards
//
// Vote accounts are used by validators to participate in consensus by
// submitting votes on the blockchain state.
package vote

import (
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/svm/syscall"
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// VoteProgram implements the Solana Vote Program.
type VoteProgram struct {
	// ProgramID is the Vote Program's public key
	ProgramID types.Pubkey
}

// New creates a new VoteProgram instance.
func New() *VoteProgram {
	return &VoteProgram{
		ProgramID: types.VoteProgramID,
	}
}

// Execute executes a Vote Program instruction.
// The instruction format is:
//   - First 4 bytes: instruction discriminator (little-endian uint32)
//   - Remaining bytes: instruction-specific data
func (p *VoteProgram) Execute(ctx *syscall.ExecutionContext, instruction []byte) error {
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
	case InstructionInitializeAccount:
		var inst InitializeAccountInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleInitializeAccount(ctx, &inst)

	case InstructionAuthorize:
		var inst AuthorizeInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleAuthorize(ctx, &inst)

	case InstructionVote:
		var inst VoteInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleVote(ctx, &inst)

	case InstructionWithdraw:
		var inst WithdrawInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleWithdraw(ctx, &inst)

	case InstructionUpdateValidatorIdentity:
		var inst UpdateValidatorIdentityInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleUpdateValidatorIdentity(ctx, &inst)

	case InstructionUpdateCommission:
		var inst UpdateCommissionInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleUpdateCommission(ctx, &inst)

	case InstructionVoteSwitch:
		var inst VoteSwitchInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleVoteSwitch(ctx, &inst)

	case InstructionAuthorizeChecked:
		var inst AuthorizeCheckedInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleAuthorizeChecked(ctx, &inst)

	case InstructionUpdateVoteState:
		var inst UpdateVoteStateInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleUpdateVoteState(ctx, &inst)

	case InstructionUpdateVoteStateSwitch:
		var inst UpdateVoteStateSwitchInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleUpdateVoteStateSwitch(ctx, &inst)

	case InstructionAuthorizeWithSeed:
		var inst AuthorizeWithSeedInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleAuthorizeWithSeed(ctx, &inst)

	case InstructionAuthorizeCheckedWithSeed:
		var inst AuthorizeCheckedWithSeedInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleAuthorizeCheckedWithSeed(ctx, &inst)

	case InstructionCompactUpdateVoteState:
		var inst CompactUpdateVoteStateInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleCompactUpdateVoteState(ctx, &inst)

	case InstructionCompactUpdateVoteStateSwitch:
		var inst CompactUpdateVoteStateSwitchInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleCompactUpdateVoteStateSwitch(ctx, &inst)

	case InstructionTowerSync:
		var inst TowerSyncInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleTowerSync(ctx, &inst)

	case InstructionTowerSyncSwitch:
		var inst TowerSyncSwitchInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleTowerSyncSwitch(ctx, &inst)

	default:
		return fmt.Errorf("%w: unknown instruction %d", ErrInvalidInstructionData, discriminator)
	}
}

// GetProgramID returns the Vote Program's public key.
func (p *VoteProgram) GetProgramID() types.Pubkey {
	return p.ProgramID
}

// IsVoteProgram checks if a pubkey is the Vote Program.
func IsVoteProgram(pubkey types.Pubkey) bool {
	return pubkey == types.VoteProgramID
}

// IsVoteAccount checks if an account is owned by the Vote Program.
func IsVoteAccount(owner types.Pubkey) bool {
	return owner == types.VoteProgramID
}
