// Package stake implements the Solana Stake Program for X1-Nimbus.
//
// The Stake Program is responsible for:
//   - Managing stake accounts
//   - Delegating stake to validators
//   - Handling stake activation and deactivation
//   - Processing stake rewards
//   - Managing stake lockup periods
//
// The Stake Program enables the proof-of-stake consensus mechanism
// by allowing token holders to delegate their stake to validators.
package stake

import (
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/svm/syscall"
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// StakeProgram implements the Solana Stake Program.
type StakeProgram struct {
	// ProgramID is the Stake Program's public key
	ProgramID types.Pubkey
}

// New creates a new StakeProgram instance.
func New() *StakeProgram {
	return &StakeProgram{
		ProgramID: types.StakeProgramID,
	}
}

// Execute executes a Stake Program instruction.
// The instruction format is:
//   - First 4 bytes: instruction discriminator (little-endian uint32)
//   - Remaining bytes: instruction-specific data
func (p *StakeProgram) Execute(ctx *syscall.ExecutionContext, instruction []byte) error {
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
	case InstructionInitialize:
		var inst InitializeInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleInitialize(ctx, &inst)

	case InstructionAuthorize:
		var inst AuthorizeInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleAuthorize(ctx, &inst)

	case InstructionDelegateStake:
		var inst DelegateStakeInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleDelegateStake(ctx, &inst)

	case InstructionSplit:
		var inst SplitInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleSplit(ctx, &inst)

	case InstructionWithdraw:
		var inst WithdrawInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleWithdraw(ctx, &inst)

	case InstructionDeactivate:
		var inst DeactivateInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleDeactivate(ctx, &inst)

	case InstructionSetLockup:
		var inst SetLockupInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleSetLockup(ctx, &inst)

	case InstructionMerge:
		var inst MergeInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleMerge(ctx, &inst)

	case InstructionAuthorizeWithSeed:
		var inst AuthorizeWithSeedInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleAuthorizeWithSeed(ctx, &inst)

	case InstructionInitializeChecked:
		var inst InitializeCheckedInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleInitializeChecked(ctx, &inst)

	case InstructionAuthorizeChecked:
		var inst AuthorizeCheckedInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleAuthorizeChecked(ctx, &inst)

	case InstructionAuthorizeCheckedWithSeed:
		var inst AuthorizeCheckedWithSeedInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleAuthorizeCheckedWithSeed(ctx, &inst)

	case InstructionSetLockupChecked:
		var inst SetLockupCheckedInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleSetLockupChecked(ctx, &inst)

	case InstructionGetMinimumDelegation:
		var inst GetMinimumDelegationInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleGetMinimumDelegation(ctx, &inst)

	case InstructionDeactivateDelinquent:
		var inst DeactivateDelinquentInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleDeactivateDelinquent(ctx, &inst)

	case InstructionRedelegate:
		var inst RedelegateInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleRedelegate(ctx, &inst)

	default:
		return fmt.Errorf("%w: unknown instruction %d", ErrInvalidInstructionData, discriminator)
	}
}

// GetProgramID returns the Stake Program's public key.
func (p *StakeProgram) GetProgramID() types.Pubkey {
	return p.ProgramID
}

// IsStakeProgram checks if a pubkey is the Stake Program.
func IsStakeProgram(pubkey types.Pubkey) bool {
	return pubkey == types.StakeProgramID
}

// handleAuthorizeWithSeed handles the AuthorizeWithSeed instruction.
// Authorizes with a derived key.
// Account layout:
//   [0] stake account (writable)
//   [1] base account (signer)
//   [2] clock sysvar
//   [3] (optional) lockup custodian (signer)
func handleAuthorizeWithSeed(ctx *syscall.ExecutionContext, inst *AuthorizeWithSeedInstruction) error {
	// Validate we have at least 3 accounts
	if ctx.AccountCount() < 3 {
		return fmt.Errorf("%w: AuthorizeWithSeed requires at least 3 accounts", ErrInvalidInstructionData)
	}

	// Get the stake account
	stakeAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !stakeAcc.IsWritable {
		return fmt.Errorf("%w: stake account", ErrAccountNotWritable)
	}

	// Verify stake account owner
	if stakeAcc.Owner != types.StakeProgramID {
		return fmt.Errorf("%w: stake account must be owned by Stake Program", ErrInvalidAccountOwner)
	}

	// Get the base account (signer)
	baseAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !baseAcc.IsSigner {
		return fmt.Errorf("%w: base account", ErrAccountNotSigner)
	}

	// Decode stake state
	var state StakeState
	if err := state.Decode(stakeAcc.Data); err != nil {
		return err
	}

	// Check if initialized
	if !state.IsInitialized() {
		return ErrStakeAccountNotInitialized
	}

	// TODO: Derive the expected authority from base + seed + owner
	// For now, we just verify the base account is a signer
	// In a full implementation, we would:
	// 1. Derive pubkey from CreateWithSeed(base, seed, owner)
	// 2. Verify derived pubkey matches current authority

	// Check lockup for withdrawer changes
	if inst.StakeAuthorize == StakeAuthorizeWithdrawer {
		var custodianPubkey *types.Pubkey
		if ctx.AccountCount() >= 4 {
			custodianAcc, err := ctx.GetAccountByIndex(3)
			if err == nil && custodianAcc.IsSigner {
				custodianPubkey = &custodianAcc.Pubkey
			}
		}
		if state.Meta.Lockup.IsInForce(ctx.UnixTimestamp, ctx.Epoch, custodianPubkey) {
			return ErrLockupInEffect
		}
	}

	// Update the authorization
	switch inst.StakeAuthorize {
	case StakeAuthorizeStaker:
		state.Meta.Authorized.Staker = inst.NewAuthority
	case StakeAuthorizeWithdrawer:
		state.Meta.Authorized.Withdrawer = inst.NewAuthority
	default:
		return ErrInvalidStakeAuthorize
	}

	// Write the updated state
	copy(stakeAcc.Data, state.Encode())

	return nil
}

// handleAuthorizeCheckedWithSeed handles the AuthorizeCheckedWithSeed instruction.
// Authorizes with a derived key and new authority as signer.
// Account layout:
//   [0] stake account (writable)
//   [1] base account (signer)
//   [2] clock sysvar
//   [3] new authorized (signer)
//   [4] (optional) lockup custodian (signer)
func handleAuthorizeCheckedWithSeed(ctx *syscall.ExecutionContext, inst *AuthorizeCheckedWithSeedInstruction) error {
	// Validate we have at least 4 accounts
	if ctx.AccountCount() < 4 {
		return fmt.Errorf("%w: AuthorizeCheckedWithSeed requires at least 4 accounts", ErrInvalidInstructionData)
	}

	// Get the new authority account (must be signer)
	newAuthorityAcc, err := ctx.GetAccountByIndex(3)
	if err != nil {
		return err
	}
	if !newAuthorityAcc.IsSigner {
		return fmt.Errorf("%w: new authority", ErrAccountNotSigner)
	}

	// Create AuthorizeWithSeed instruction with the new authority
	authInst := AuthorizeWithSeedInstruction{
		NewAuthority:   newAuthorityAcc.Pubkey,
		StakeAuthorize: inst.StakeAuthorize,
		AuthoritySeed:  inst.AuthoritySeed,
		AuthorityOwner: inst.AuthorityOwner,
	}

	return handleAuthorizeWithSeed(ctx, &authInst)
}

// handleSetLockupChecked handles the SetLockupChecked instruction.
// Sets lockup with the new custodian as a signer.
// Account layout:
//   [0] stake account (writable)
//   [1] current lockup custodian or withdrawer (signer)
//   [2] (optional) new custodian (signer)
func handleSetLockupChecked(ctx *syscall.ExecutionContext, inst *SetLockupCheckedInstruction) error {
	// Validate we have at least 2 accounts
	if ctx.AccountCount() < 2 {
		return fmt.Errorf("%w: SetLockupChecked requires at least 2 accounts", ErrInvalidInstructionData)
	}

	// Build LockupArgs
	args := LockupArgs{
		UnixTimestamp: inst.UnixTimestamp,
		Epoch:         inst.Epoch,
	}

	// If there's a new custodian account, use it
	if ctx.AccountCount() >= 3 {
		custodianAcc, err := ctx.GetAccountByIndex(2)
		if err == nil && custodianAcc.IsSigner {
			args.Custodian = &custodianAcc.Pubkey
		}
	}

	// Create SetLockup instruction
	setLockupInst := SetLockupInstruction{
		LockupArgs: args,
	}

	return handleSetLockup(ctx, &setLockupInst)
}
