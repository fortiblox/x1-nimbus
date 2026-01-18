package stake

import (
	"encoding/binary"
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/svm/syscall"
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// handleInitialize handles the Initialize instruction.
// Initializes a stake account with the given authorized and lockup.
// Account layout:
//   [0] stake account (writable)
//   [1] rent sysvar
func handleInitialize(ctx *syscall.ExecutionContext, inst *InitializeInstruction) error {
	// Validate we have at least 2 accounts
	if ctx.AccountCount() < 2 {
		return fmt.Errorf("%w: Initialize requires 2 accounts", ErrInvalidInstructionData)
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

	// Check if already initialized
	if len(stakeAcc.Data) >= 4 {
		stateType := StakeStateType(binary.LittleEndian.Uint32(stakeAcc.Data[0:4]))
		if stateType != StakeStateUninitialized {
			return ErrStakeAccountAlreadyInitialized
		}
	}

	// Calculate rent exempt reserve
	rentExemptReserve := uint64(types.RentExemptMinimum(uint64(len(stakeAcc.Data))))

	// Verify the account has enough lamports
	if *stakeAcc.Lamports < rentExemptReserve {
		return fmt.Errorf("%w: need %d lamports for rent exemption", ErrInsufficientFunds, rentExemptReserve)
	}

	// Initialize the stake state
	state := StakeState{
		Type: StakeStateInitialized,
		Meta: Meta{
			RentExemptReserve: rentExemptReserve,
			Authorized:        inst.Authorized,
			Lockup:            inst.Lockup,
		},
	}

	// Ensure the account has enough space
	if len(stakeAcc.Data) < StakeStateSize {
		stakeAcc.Data = make([]byte, StakeStateSize)
	}

	// Write the state
	copy(stakeAcc.Data, state.Encode())

	return nil
}

// handleAuthorize handles the Authorize instruction.
// Changes the authorized staker or withdrawer.
// Account layout:
//   [0] stake account (writable)
//   [1] clock sysvar
//   [2] current authorized (staker or withdrawer) (signer)
//   [3] (optional) lockup custodian (signer)
func handleAuthorize(ctx *syscall.ExecutionContext, inst *AuthorizeInstruction) error {
	// Validate we have at least 3 accounts
	if ctx.AccountCount() < 3 {
		return fmt.Errorf("%w: Authorize requires at least 3 accounts", ErrInvalidInstructionData)
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

	// Decode stake state
	var state StakeState
	if err := state.Decode(stakeAcc.Data); err != nil {
		return err
	}

	// Check if initialized
	if !state.IsInitialized() {
		return ErrStakeAccountNotInitialized
	}

	// Get the current authority account (signer)
	authorityAcc, err := ctx.GetAccountByIndex(2)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: authority", ErrAccountNotSigner)
	}

	// Verify authorization
	var expectedAuthority types.Pubkey
	switch inst.StakeAuthorize {
	case StakeAuthorizeStaker:
		expectedAuthority = state.Meta.Authorized.Staker
	case StakeAuthorizeWithdrawer:
		expectedAuthority = state.Meta.Authorized.Withdrawer
	default:
		return ErrInvalidStakeAuthorize
	}

	if authorityAcc.Pubkey != expectedAuthority {
		return ErrInvalidAuthorization
	}

	// Check lockup for withdrawer changes
	if inst.StakeAuthorize == StakeAuthorizeWithdrawer {
		// If lockup is in effect, require custodian signature
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
	}

	// Write the updated state
	copy(stakeAcc.Data, state.Encode())

	return nil
}

// handleDelegateStake handles the DelegateStake instruction.
// Delegates the stake to a validator vote account.
// Account layout:
//   [0] stake account (writable)
//   [1] vote account
//   [2] clock sysvar
//   [3] stake history sysvar
//   [4] stake config account
//   [5] stake authority (signer)
func handleDelegateStake(ctx *syscall.ExecutionContext, _ *DelegateStakeInstruction) error {
	// Validate we have at least 6 accounts
	if ctx.AccountCount() < 6 {
		return fmt.Errorf("%w: DelegateStake requires 6 accounts", ErrInvalidInstructionData)
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

	// Get the vote account
	voteAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}

	// Verify vote account owner
	if voteAcc.Owner != types.VoteProgramID {
		return fmt.Errorf("%w: vote account must be owned by Vote Program", ErrInvalidVoteAccount)
	}

	// Get the stake authority (signer)
	authorityAcc, err := ctx.GetAccountByIndex(5)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: stake authority", ErrAccountNotSigner)
	}

	// Decode stake state
	var state StakeState
	if err := state.Decode(stakeAcc.Data); err != nil {
		return err
	}

	// Verify the stake account is initialized but not already delegated
	if state.Type == StakeStateUninitialized {
		return ErrStakeAccountNotInitialized
	}
	if state.Type == StakeStateStake {
		return ErrStakeAlreadyDelegated
	}
	if state.Type != StakeStateInitialized {
		return ErrInvalidStakeState
	}

	// Verify authority
	if authorityAcc.Pubkey != state.Meta.Authorized.Staker {
		return ErrInvalidAuthorization
	}

	// Calculate the stake amount (lamports minus rent exempt reserve)
	stakeAmount := *stakeAcc.Lamports - state.Meta.RentExemptReserve
	if stakeAmount < MinimumDelegation {
		return ErrInsufficientDelegation
	}

	// Create the delegation
	state.Type = StakeStateStake
	state.Stake = Stake{
		Delegation: Delegation{
			VoterPubkey:        voteAcc.Pubkey,
			Stake:              stakeAmount,
			ActivationEpoch:    ctx.Epoch,
			DeactivationEpoch:  DeactivationEpochMax,
			WarmupCooldownRate: DefaultWarmupCooldownRate,
		},
		CreditsObserved: 0, // Will be updated when rewards are calculated
	}

	// Write the updated state
	copy(stakeAcc.Data, state.Encode())

	return nil
}

// handleDeactivate handles the Deactivate instruction.
// Deactivates a delegated stake.
// Account layout:
//   [0] stake account (writable)
//   [1] clock sysvar
//   [2] stake authority (signer)
func handleDeactivate(ctx *syscall.ExecutionContext, _ *DeactivateInstruction) error {
	// Validate we have at least 3 accounts
	if ctx.AccountCount() < 3 {
		return fmt.Errorf("%w: Deactivate requires 3 accounts", ErrInvalidInstructionData)
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

	// Get the stake authority (signer)
	authorityAcc, err := ctx.GetAccountByIndex(2)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: stake authority", ErrAccountNotSigner)
	}

	// Decode stake state
	var state StakeState
	if err := state.Decode(stakeAcc.Data); err != nil {
		return err
	}

	// Verify the stake is delegated
	if state.Type != StakeStateStake {
		return ErrStakeNotDelegated
	}

	// Verify authority
	if authorityAcc.Pubkey != state.Meta.Authorized.Staker {
		return ErrInvalidAuthorization
	}

	// Check if already deactivated
	if state.Stake.Delegation.DeactivationEpoch != DeactivationEpochMax {
		return ErrStakeAlreadyDeactivated
	}

	// Set the deactivation epoch
	state.Stake.Delegation.DeactivationEpoch = ctx.Epoch

	// Write the updated state
	copy(stakeAcc.Data, state.Encode())

	return nil
}

// handleWithdraw handles the Withdraw instruction.
// Withdraws lamports from a stake account.
// Account layout:
//   [0] stake account (writable)
//   [1] destination account (writable)
//   [2] clock sysvar
//   [3] stake history sysvar
//   [4] withdraw authority (signer)
//   [5] (optional) lockup custodian (signer)
func handleWithdraw(ctx *syscall.ExecutionContext, inst *WithdrawInstruction) error {
	// Validate we have at least 5 accounts
	if ctx.AccountCount() < 5 {
		return fmt.Errorf("%w: Withdraw requires at least 5 accounts", ErrInvalidInstructionData)
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

	// Get the destination account
	destAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !destAcc.IsWritable {
		return fmt.Errorf("%w: destination account", ErrAccountNotWritable)
	}

	// Get the withdraw authority (signer)
	authorityAcc, err := ctx.GetAccountByIndex(4)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: withdraw authority", ErrAccountNotSigner)
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

	// Verify authority
	if authorityAcc.Pubkey != state.Meta.Authorized.Withdrawer {
		return ErrInvalidAuthorization
	}

	// Check lockup
	var custodianPubkey *types.Pubkey
	if ctx.AccountCount() >= 6 {
		custodianAcc, err := ctx.GetAccountByIndex(5)
		if err == nil && custodianAcc.IsSigner {
			custodianPubkey = &custodianAcc.Pubkey
		}
	}
	if state.Meta.Lockup.IsInForce(ctx.UnixTimestamp, ctx.Epoch, custodianPubkey) {
		return ErrLockupInEffect
	}

	// Calculate withdrawable amount
	var withdrawable uint64
	if state.Type == StakeStateInitialized {
		// Can withdraw everything above rent exempt reserve
		if *stakeAcc.Lamports > state.Meta.RentExemptReserve {
			withdrawable = *stakeAcc.Lamports - state.Meta.RentExemptReserve
		}
	} else if state.Type == StakeStateStake {
		// Check if fully deactivated
		if state.Stake.Delegation.DeactivationEpoch == DeactivationEpochMax {
			// Still active, can only withdraw rewards (excess above stake + reserve)
			stakeAndReserve := state.Stake.Delegation.Stake + state.Meta.RentExemptReserve
			if *stakeAcc.Lamports > stakeAndReserve {
				withdrawable = *stakeAcc.Lamports - stakeAndReserve
			}
		} else {
			// Deactivated - check if cooldown is complete
			// For simplicity, we assume cooldown is complete if deactivation epoch < current epoch
			if state.Stake.Delegation.DeactivationEpoch < ctx.Epoch {
				// Fully cooled down, can withdraw everything above rent exempt reserve
				withdrawable = *stakeAcc.Lamports - state.Meta.RentExemptReserve
			} else {
				// Still cooling down, calculate based on cooldown rate
				// For now, allow withdrawing rewards only
				stakeAndReserve := state.Stake.Delegation.Stake + state.Meta.RentExemptReserve
				if *stakeAcc.Lamports > stakeAndReserve {
					withdrawable = *stakeAcc.Lamports - stakeAndReserve
				}
			}
		}
	}

	// Check withdrawal amount
	if inst.Lamports > withdrawable {
		return fmt.Errorf("%w: requested %d, withdrawable %d", ErrInsufficientFunds, inst.Lamports, withdrawable)
	}

	// Perform the withdrawal
	*stakeAcc.Lamports -= inst.Lamports
	*destAcc.Lamports += inst.Lamports

	// If stake account is now empty (only rent exempt reserve), reset to initialized
	if state.Type == StakeStateStake && *stakeAcc.Lamports <= state.Meta.RentExemptReserve {
		state.Type = StakeStateInitialized
		state.Stake = Stake{}
		copy(stakeAcc.Data, state.Encode())
	}

	return nil
}

// handleSplit handles the Split instruction.
// Splits a stake account into two.
// Account layout:
//   [0] source stake account (writable)
//   [1] destination stake account (writable)
//   [2] stake authority (signer)
func handleSplit(ctx *syscall.ExecutionContext, inst *SplitInstruction) error {
	// Validate we have at least 3 accounts
	if ctx.AccountCount() < 3 {
		return fmt.Errorf("%w: Split requires 3 accounts", ErrInvalidInstructionData)
	}

	// Get the source stake account
	sourceAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !sourceAcc.IsWritable {
		return fmt.Errorf("%w: source stake account", ErrAccountNotWritable)
	}

	// Verify source stake account owner
	if sourceAcc.Owner != types.StakeProgramID {
		return fmt.Errorf("%w: source stake account must be owned by Stake Program", ErrInvalidAccountOwner)
	}

	// Get the destination stake account
	destAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !destAcc.IsWritable {
		return fmt.Errorf("%w: destination stake account", ErrAccountNotWritable)
	}

	// Verify destination stake account owner
	if destAcc.Owner != types.StakeProgramID {
		return fmt.Errorf("%w: destination stake account must be owned by Stake Program", ErrInvalidAccountOwner)
	}

	// Get the stake authority (signer)
	authorityAcc, err := ctx.GetAccountByIndex(2)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: stake authority", ErrAccountNotSigner)
	}

	// Decode source stake state
	var sourceState StakeState
	if err := sourceState.Decode(sourceAcc.Data); err != nil {
		return err
	}

	// Check if source is initialized
	if !sourceState.IsInitialized() {
		return ErrStakeAccountNotInitialized
	}

	// Verify authority
	if authorityAcc.Pubkey != sourceState.Meta.Authorized.Staker {
		return ErrInvalidAuthorization
	}

	// Verify destination is uninitialized
	if len(destAcc.Data) >= 4 {
		destStateType := StakeStateType(binary.LittleEndian.Uint32(destAcc.Data[0:4]))
		if destStateType != StakeStateUninitialized {
			return ErrStakeAccountAlreadyInitialized
		}
	}

	// Calculate rent exempt reserve for destination
	destRentExemptReserve := uint64(types.RentExemptMinimum(uint64(len(destAcc.Data))))

	// Verify split amount
	if inst.Lamports < destRentExemptReserve+MinimumDelegation {
		return ErrStakeTooSmall
	}

	// Verify source has enough lamports
	remainingLamports := *sourceAcc.Lamports - inst.Lamports
	if remainingLamports < sourceState.Meta.RentExemptReserve+MinimumDelegation {
		return fmt.Errorf("%w: source would have insufficient stake after split", ErrStakeTooSmall)
	}

	// Transfer lamports
	*sourceAcc.Lamports -= inst.Lamports
	*destAcc.Lamports += inst.Lamports

	// Create destination state (copy from source)
	destState := StakeState{
		Type: sourceState.Type,
		Meta: Meta{
			RentExemptReserve: destRentExemptReserve,
			Authorized:        sourceState.Meta.Authorized,
			Lockup:            sourceState.Meta.Lockup,
		},
	}

	// If source is delegated, split the stake
	if sourceState.Type == StakeStateStake {
		// Calculate stake split ratio
		splitStake := inst.Lamports - destRentExemptReserve

		// Update source stake
		sourceState.Stake.Delegation.Stake -= splitStake

		// Set destination stake
		destState.Stake = Stake{
			Delegation: Delegation{
				VoterPubkey:        sourceState.Stake.Delegation.VoterPubkey,
				Stake:              splitStake,
				ActivationEpoch:    sourceState.Stake.Delegation.ActivationEpoch,
				DeactivationEpoch:  sourceState.Stake.Delegation.DeactivationEpoch,
				WarmupCooldownRate: sourceState.Stake.Delegation.WarmupCooldownRate,
			},
			CreditsObserved: sourceState.Stake.CreditsObserved,
		}
	}

	// Ensure destination has enough space
	if len(destAcc.Data) < StakeStateSize {
		destAcc.Data = make([]byte, StakeStateSize)
	}

	// Write states
	copy(sourceAcc.Data, sourceState.Encode())
	copy(destAcc.Data, destState.Encode())

	return nil
}

// handleMerge handles the Merge instruction.
// Merges two stake accounts.
// Account layout:
//   [0] destination stake account (writable)
//   [1] source stake account (writable)
//   [2] clock sysvar
//   [3] stake history sysvar
//   [4] stake authority (signer)
func handleMerge(ctx *syscall.ExecutionContext, _ *MergeInstruction) error {
	// Validate we have at least 5 accounts
	if ctx.AccountCount() < 5 {
		return fmt.Errorf("%w: Merge requires 5 accounts", ErrInvalidInstructionData)
	}

	// Get the destination stake account
	destAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !destAcc.IsWritable {
		return fmt.Errorf("%w: destination stake account", ErrAccountNotWritable)
	}

	// Verify destination stake account owner
	if destAcc.Owner != types.StakeProgramID {
		return fmt.Errorf("%w: destination stake account must be owned by Stake Program", ErrInvalidAccountOwner)
	}

	// Get the source stake account
	sourceAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !sourceAcc.IsWritable {
		return fmt.Errorf("%w: source stake account", ErrAccountNotWritable)
	}

	// Verify source stake account owner
	if sourceAcc.Owner != types.StakeProgramID {
		return fmt.Errorf("%w: source stake account must be owned by Stake Program", ErrInvalidAccountOwner)
	}

	// Get the stake authority (signer)
	authorityAcc, err := ctx.GetAccountByIndex(4)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: stake authority", ErrAccountNotSigner)
	}

	// Decode stake states
	var destState StakeState
	if err := destState.Decode(destAcc.Data); err != nil {
		return err
	}

	var sourceState StakeState
	if err := sourceState.Decode(sourceAcc.Data); err != nil {
		return err
	}

	// Check if both are initialized
	if !destState.IsInitialized() || !sourceState.IsInitialized() {
		return ErrStakeAccountNotInitialized
	}

	// Verify authority for both
	if authorityAcc.Pubkey != destState.Meta.Authorized.Staker {
		return ErrInvalidAuthorization
	}
	if authorityAcc.Pubkey != sourceState.Meta.Authorized.Staker {
		return ErrInvalidAuthorization
	}

	// Verify lockup matches
	if destState.Meta.Lockup != sourceState.Meta.Lockup {
		return fmt.Errorf("%w: lockup mismatch", ErrMergeMismatch)
	}

	// Verify authorized matches
	if destState.Meta.Authorized != sourceState.Meta.Authorized {
		return fmt.Errorf("%w: authorized mismatch", ErrMergeMismatch)
	}

	// Handle merge based on stake states
	if destState.Type == StakeStateInitialized && sourceState.Type == StakeStateInitialized {
		// Both initialized, just merge lamports
		// Nothing special to do
	} else if destState.Type == StakeStateStake && sourceState.Type == StakeStateStake {
		// Both delegated, verify they can be merged
		if destState.Stake.Delegation.VoterPubkey != sourceState.Stake.Delegation.VoterPubkey {
			return fmt.Errorf("%w: voter pubkey mismatch", ErrMergeMismatch)
		}

		// Check for transient stake (activating or deactivating)
		if destState.Stake.Delegation.ActivationEpoch > ctx.Epoch ||
			sourceState.Stake.Delegation.ActivationEpoch > ctx.Epoch {
			return ErrMergeTransientStake
		}
		if destState.Stake.Delegation.DeactivationEpoch != DeactivationEpochMax ||
			sourceState.Stake.Delegation.DeactivationEpoch != DeactivationEpochMax {
			return ErrMergeTransientStake
		}

		// Merge the stakes
		sourceStake := sourceState.Stake.Delegation.Stake
		destState.Stake.Delegation.Stake += sourceStake
	} else if destState.Type == StakeStateInitialized && sourceState.Type == StakeStateStake {
		// Destination initialized, source delegated - copy stake info to destination
		destState.Type = StakeStateStake
		destState.Stake = sourceState.Stake
	} else if destState.Type == StakeStateStake && sourceState.Type == StakeStateInitialized {
		// Destination delegated, source initialized - just add lamports to stake
		destState.Stake.Delegation.Stake += *sourceAcc.Lamports - sourceState.Meta.RentExemptReserve
	}

	// Transfer lamports from source to destination
	*destAcc.Lamports += *sourceAcc.Lamports
	*sourceAcc.Lamports = 0

	// Reset source to uninitialized
	sourceState.Type = StakeStateUninitialized
	sourceState.Meta = Meta{}
	sourceState.Stake = Stake{}

	// Write states
	copy(destAcc.Data, destState.Encode())
	copy(sourceAcc.Data, sourceState.Encode())

	return nil
}

// handleSetLockup handles the SetLockup instruction.
// Sets the lockup configuration.
// Account layout:
//   [0] stake account (writable)
//   [1] current lockup custodian or withdrawer (signer)
func handleSetLockup(ctx *syscall.ExecutionContext, inst *SetLockupInstruction) error {
	// Validate we have at least 2 accounts
	if ctx.AccountCount() < 2 {
		return fmt.Errorf("%w: SetLockup requires 2 accounts", ErrInvalidInstructionData)
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

	// Get the authority (signer)
	authorityAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: authority", ErrAccountNotSigner)
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

	// Verify authority (must be custodian or withdrawer)
	isWithdrawer := authorityAcc.Pubkey == state.Meta.Authorized.Withdrawer
	isCustodian := authorityAcc.Pubkey == state.Meta.Lockup.Custodian

	if !isWithdrawer && !isCustodian {
		return ErrInvalidAuthorization
	}

	// If lockup is in effect, only custodian can modify
	if state.Meta.Lockup.IsInForce(ctx.UnixTimestamp, ctx.Epoch, nil) {
		if !isCustodian {
			return ErrLockupInEffect
		}
	}

	// Apply lockup changes
	if inst.LockupArgs.UnixTimestamp != nil {
		state.Meta.Lockup.UnixTimestamp = *inst.LockupArgs.UnixTimestamp
	}
	if inst.LockupArgs.Epoch != nil {
		state.Meta.Lockup.Epoch = *inst.LockupArgs.Epoch
	}
	if inst.LockupArgs.Custodian != nil {
		state.Meta.Lockup.Custodian = *inst.LockupArgs.Custodian
	}

	// Write the updated state
	copy(stakeAcc.Data, state.Encode())

	return nil
}

// handleInitializeChecked handles the InitializeChecked instruction.
// Initializes a stake account with checked signers.
// Account layout:
//   [0] stake account (writable)
//   [1] rent sysvar
//   [2] staker (signer)
//   [3] withdrawer (signer)
func handleInitializeChecked(ctx *syscall.ExecutionContext, _ *InitializeCheckedInstruction) error {
	// Validate we have at least 4 accounts
	if ctx.AccountCount() < 4 {
		return fmt.Errorf("%w: InitializeChecked requires 4 accounts", ErrInvalidInstructionData)
	}

	// Get the staker and withdrawer accounts
	stakerAcc, err := ctx.GetAccountByIndex(2)
	if err != nil {
		return err
	}
	if !stakerAcc.IsSigner {
		return fmt.Errorf("%w: staker", ErrAccountNotSigner)
	}

	withdrawerAcc, err := ctx.GetAccountByIndex(3)
	if err != nil {
		return err
	}
	if !withdrawerAcc.IsSigner {
		return fmt.Errorf("%w: withdrawer", ErrAccountNotSigner)
	}

	// Create Initialize instruction with the authorities from accounts
	initInst := InitializeInstruction{
		Authorized: Authorized{
			Staker:     stakerAcc.Pubkey,
			Withdrawer: withdrawerAcc.Pubkey,
		},
		Lockup: Lockup{}, // Empty lockup
	}

	return handleInitialize(ctx, &initInst)
}

// handleAuthorizeChecked handles the AuthorizeChecked instruction.
// Changes authorization with the new authority as a signer.
// Account layout:
//   [0] stake account (writable)
//   [1] clock sysvar
//   [2] current authorized (signer)
//   [3] new authorized (signer)
//   [4] (optional) lockup custodian (signer)
func handleAuthorizeChecked(ctx *syscall.ExecutionContext, inst *AuthorizeCheckedInstruction) error {
	// Validate we have at least 4 accounts
	if ctx.AccountCount() < 4 {
		return fmt.Errorf("%w: AuthorizeChecked requires at least 4 accounts", ErrInvalidInstructionData)
	}

	// Get the new authority account (must be signer)
	newAuthorityAcc, err := ctx.GetAccountByIndex(3)
	if err != nil {
		return err
	}
	if !newAuthorityAcc.IsSigner {
		return fmt.Errorf("%w: new authority", ErrAccountNotSigner)
	}

	// Create Authorize instruction with the new authority
	authInst := AuthorizeInstruction{
		NewAuthority:   newAuthorityAcc.Pubkey,
		StakeAuthorize: inst.StakeAuthorize,
	}

	return handleAuthorize(ctx, &authInst)
}

// handleGetMinimumDelegation handles the GetMinimumDelegation instruction.
// Returns the minimum delegation amount via return data.
func handleGetMinimumDelegation(ctx *syscall.ExecutionContext, _ *GetMinimumDelegationInstruction) error {
	// Return the minimum delegation as return data
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, MinimumDelegation)
	return ctx.SetReturnData(types.StakeProgramID, data)
}

// handleDeactivateDelinquent handles the DeactivateDelinquent instruction.
// Deactivates stake delegated to a delinquent validator.
// Account layout:
//   [0] stake account (writable)
//   [1] vote account
//   [2] reference vote account
func handleDeactivateDelinquent(ctx *syscall.ExecutionContext, _ *DeactivateDelinquentInstruction) error {
	// Validate we have at least 3 accounts
	if ctx.AccountCount() < 3 {
		return fmt.Errorf("%w: DeactivateDelinquent requires 3 accounts", ErrInvalidInstructionData)
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

	// Get the vote account
	voteAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}

	// Verify vote account owner
	if voteAcc.Owner != types.VoteProgramID {
		return fmt.Errorf("%w: vote account must be owned by Vote Program", ErrInvalidVoteAccount)
	}

	// Decode stake state
	var state StakeState
	if err := state.Decode(stakeAcc.Data); err != nil {
		return err
	}

	// Verify the stake is delegated
	if state.Type != StakeStateStake {
		return ErrStakeNotDelegated
	}

	// Verify the stake is delegated to the provided vote account
	if state.Stake.Delegation.VoterPubkey != voteAcc.Pubkey {
		return fmt.Errorf("%w: stake not delegated to this vote account", ErrInvalidVoteAccount)
	}

	// Check if already deactivated
	if state.Stake.Delegation.DeactivationEpoch != DeactivationEpochMax {
		return ErrStakeAlreadyDeactivated
	}

	// TODO: Verify the validator is actually delinquent by comparing with reference vote account
	// For now, we'll just deactivate

	// Set the deactivation epoch
	state.Stake.Delegation.DeactivationEpoch = ctx.Epoch

	// Write the updated state
	copy(stakeAcc.Data, state.Encode())

	return nil
}

// handleRedelegate handles the Redelegate instruction.
// Redelegates stake to a different validator.
// Account layout:
//   [0] stake account (writable)
//   [1] uninitialized stake account (writable)
//   [2] vote account
//   [3] stake config account
//   [4] stake authority (signer)
func handleRedelegate(ctx *syscall.ExecutionContext, _ *RedelegateInstruction) error {
	// Validate we have at least 5 accounts
	if ctx.AccountCount() < 5 {
		return fmt.Errorf("%w: Redelegate requires 5 accounts", ErrInvalidInstructionData)
	}

	// Get the source stake account
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

	// Get the uninitialized stake account
	uninitAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !uninitAcc.IsWritable {
		return fmt.Errorf("%w: uninitialized stake account", ErrAccountNotWritable)
	}

	// Verify uninitialized stake account owner
	if uninitAcc.Owner != types.StakeProgramID {
		return fmt.Errorf("%w: uninitialized stake account must be owned by Stake Program", ErrInvalidAccountOwner)
	}

	// Get the vote account
	voteAcc, err := ctx.GetAccountByIndex(2)
	if err != nil {
		return err
	}

	// Verify vote account owner
	if voteAcc.Owner != types.VoteProgramID {
		return fmt.Errorf("%w: vote account must be owned by Vote Program", ErrInvalidVoteAccount)
	}

	// Get the stake authority (signer)
	authorityAcc, err := ctx.GetAccountByIndex(4)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: stake authority", ErrAccountNotSigner)
	}

	// Decode stake state
	var state StakeState
	if err := state.Decode(stakeAcc.Data); err != nil {
		return err
	}

	// Verify the stake is delegated
	if state.Type != StakeStateStake {
		return ErrStakeNotDelegated
	}

	// Verify authority
	if authorityAcc.Pubkey != state.Meta.Authorized.Staker {
		return ErrInvalidAuthorization
	}

	// Cannot redelegate to the same vote account
	if state.Stake.Delegation.VoterPubkey == voteAcc.Pubkey {
		return ErrRedelegateToSameVoteAccount
	}

	// Check for transient stake
	if state.Stake.Delegation.ActivationEpoch > ctx.Epoch ||
		state.Stake.Delegation.DeactivationEpoch != DeactivationEpochMax {
		return ErrRedelegateTransientOrInactiveStake
	}

	// Verify uninitialized stake account is actually uninitialized
	if len(uninitAcc.Data) >= 4 {
		uninitStateType := StakeStateType(binary.LittleEndian.Uint32(uninitAcc.Data[0:4]))
		if uninitStateType != StakeStateUninitialized {
			return ErrStakeAccountAlreadyInitialized
		}
	}

	// Calculate rent exempt reserve for new stake account
	newRentExemptReserve := uint64(types.RentExemptMinimum(uint64(len(uninitAcc.Data))))

	// Deactivate the current stake
	state.Stake.Delegation.DeactivationEpoch = ctx.Epoch

	// Create new stake state for the new account
	newState := StakeState{
		Type: StakeStateStake,
		Meta: Meta{
			RentExemptReserve: newRentExemptReserve,
			Authorized:        state.Meta.Authorized,
			Lockup:            state.Meta.Lockup,
		},
		Stake: Stake{
			Delegation: Delegation{
				VoterPubkey:        voteAcc.Pubkey,
				Stake:              state.Stake.Delegation.Stake,
				ActivationEpoch:    ctx.Epoch,
				DeactivationEpoch:  DeactivationEpochMax,
				WarmupCooldownRate: DefaultWarmupCooldownRate,
			},
			CreditsObserved: 0,
		},
	}

	// Ensure new account has enough space
	if len(uninitAcc.Data) < StakeStateSize {
		uninitAcc.Data = make([]byte, StakeStateSize)
	}

	// Write states
	copy(stakeAcc.Data, state.Encode())
	copy(uninitAcc.Data, newState.Encode())

	return nil
}
