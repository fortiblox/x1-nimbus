package vote

import (
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/svm/syscall"
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// handleInitializeAccount handles the InitializeAccount instruction.
// Account layout:
//   [0] vote account (writable)
//   [1] rent sysvar
//   [2] clock sysvar
//   [3] node pubkey (signer)
func handleInitializeAccount(ctx *syscall.ExecutionContext, inst *InitializeAccountInstruction) error {
	// Validate we have at least 4 accounts
	if ctx.AccountCount() < 4 {
		return fmt.Errorf("%w: InitializeAccount requires 4 accounts", ErrInvalidInstructionData)
	}

	// Get the vote account (must be writable)
	voteAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !voteAcc.IsWritable {
		return fmt.Errorf("%w: vote account", ErrAccountNotWritable)
	}

	// Check if already initialized
	if IsInitialized(voteAcc.Data) {
		return ErrVoteAccountAlreadyInitialized
	}

	// Get the node pubkey account (must be signer)
	nodeAcc, err := ctx.GetAccountByIndex(3)
	if err != nil {
		return err
	}
	if !nodeAcc.IsSigner {
		return fmt.Errorf("%w: node pubkey account", ErrAccountNotSigner)
	}

	// Verify node pubkey matches
	if nodeAcc.Pubkey != inst.VoteInit.NodePubkey {
		return fmt.Errorf("%w: node pubkey mismatch", ErrInvalidInstructionData)
	}

	// Validate commission
	if inst.VoteInit.Commission > 100 {
		return fmt.Errorf("%w: commission must be 0-100, got %d", ErrInvalidCommission, inst.VoteInit.Commission)
	}

	// Create the vote state
	voteState := NewVoteState(&inst.VoteInit, ctx.Epoch)

	// Serialize and store
	data, err := voteState.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize vote state: %w", err)
	}

	// Ensure account has enough space
	if len(voteAcc.Data) < len(data) {
		// Resize the account data
		if err := ctx.ResizeAccountData(voteAcc.Pubkey, len(data)); err != nil {
			return fmt.Errorf("failed to resize vote account: %w", err)
		}
		// Re-fetch the account after resize
		voteAcc, err = ctx.GetAccountByIndex(0)
		if err != nil {
			return err
		}
	}

	// Copy data to account
	copy(voteAcc.Data, data)

	// Set owner to Vote Program
	voteAcc.Owner = types.VoteProgramID

	return nil
}

// handleAuthorize handles the Authorize instruction.
// Account layout:
//   [0] vote account (writable)
//   [1] clock sysvar
//   [2] authority (signer) - current voter or withdrawer depending on type
func handleAuthorize(ctx *syscall.ExecutionContext, inst *AuthorizeInstruction) error {
	// Validate we have at least 3 accounts
	if ctx.AccountCount() < 3 {
		return fmt.Errorf("%w: Authorize requires 3 accounts", ErrInvalidInstructionData)
	}

	// Get the vote account
	voteAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !voteAcc.IsWritable {
		return fmt.Errorf("%w: vote account", ErrAccountNotWritable)
	}

	// Check if initialized
	if !IsInitialized(voteAcc.Data) {
		return ErrVoteAccountNotInitialized
	}

	// Get the authority (must be signer)
	authorityAcc, err := ctx.GetAccountByIndex(2)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: authority", ErrAccountNotSigner)
	}

	// Deserialize vote state
	voteState, err := DeserializeVoteState(voteAcc.Data)
	if err != nil {
		return fmt.Errorf("failed to deserialize vote state: %w", err)
	}

	// Handle based on authorization type
	switch inst.AuthorizeType {
	case VoteAuthorizeVoter:
		// Verify current voter authorized this
		currentVoter, found := voteState.GetAuthorizedVoter(ctx.Epoch)
		if !found {
			return ErrUnauthorized
		}
		if authorityAcc.Pubkey != currentVoter {
			return fmt.Errorf("%w: signer is not the authorized voter", ErrUnauthorized)
		}
		// Update authorized voter for next epoch
		voteState.AuthorizedVoters.Insert(ctx.Epoch+1, inst.NewAuthority)

	case VoteAuthorizeWithdrawer:
		// Verify current withdrawer authorized this
		if authorityAcc.Pubkey != voteState.AuthorizedWithdrawer {
			return fmt.Errorf("%w: signer is not the authorized withdrawer", ErrUnauthorized)
		}
		// Update authorized withdrawer
		voteState.AuthorizedWithdrawer = inst.NewAuthority

	default:
		return ErrInvalidAuthorizeType
	}

	// Serialize and store
	data, err := voteState.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize vote state: %w", err)
	}
	copy(voteAcc.Data, data)

	return nil
}

// handleVote handles the Vote instruction.
// Account layout:
//   [0] vote account (writable)
//   [1] slot hashes sysvar
//   [2] clock sysvar
//   [3] vote authority (signer)
func handleVote(ctx *syscall.ExecutionContext, inst *VoteInstruction) error {
	// Validate we have at least 4 accounts
	if ctx.AccountCount() < 4 {
		return fmt.Errorf("%w: Vote requires 4 accounts", ErrInvalidInstructionData)
	}

	// Get the vote account
	voteAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !voteAcc.IsWritable {
		return fmt.Errorf("%w: vote account", ErrAccountNotWritable)
	}

	// Check if initialized
	if !IsInitialized(voteAcc.Data) {
		return ErrVoteAccountNotInitialized
	}

	// Get the vote authority (must be signer)
	authorityAcc, err := ctx.GetAccountByIndex(3)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: vote authority", ErrAccountNotSigner)
	}

	// Deserialize vote state
	voteState, err := DeserializeVoteState(voteAcc.Data)
	if err != nil {
		return fmt.Errorf("failed to deserialize vote state: %w", err)
	}

	// Verify vote authority
	currentVoter, found := voteState.GetAuthorizedVoter(ctx.Epoch)
	if !found {
		return ErrUnauthorized
	}
	if authorityAcc.Pubkey != currentVoter {
		return fmt.Errorf("%w: signer is not the authorized voter", ErrUnauthorized)
	}

	// Process the vote
	if err := voteState.ProcessVote(&inst.Vote, ctx.Slot, ctx.Epoch); err != nil {
		return err
	}

	// Serialize and store
	data, err := voteState.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize vote state: %w", err)
	}
	copy(voteAcc.Data, data)

	return nil
}

// handleWithdraw handles the Withdraw instruction.
// Account layout:
//   [0] vote account (writable)
//   [1] destination account (writable)
//   [2] withdraw authority (signer)
func handleWithdraw(ctx *syscall.ExecutionContext, inst *WithdrawInstruction) error {
	// Validate we have at least 3 accounts
	if ctx.AccountCount() < 3 {
		return fmt.Errorf("%w: Withdraw requires 3 accounts", ErrInvalidInstructionData)
	}

	// Get the vote account
	voteAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !voteAcc.IsWritable {
		return fmt.Errorf("%w: vote account", ErrAccountNotWritable)
	}

	// Get the destination account
	destAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !destAcc.IsWritable {
		return fmt.Errorf("%w: destination account", ErrAccountNotWritable)
	}

	// Get the withdraw authority (must be signer)
	authorityAcc, err := ctx.GetAccountByIndex(2)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: withdraw authority", ErrAccountNotSigner)
	}

	// Check if initialized
	if !IsInitialized(voteAcc.Data) {
		return ErrVoteAccountNotInitialized
	}

	// Deserialize vote state
	voteState, err := DeserializeVoteState(voteAcc.Data)
	if err != nil {
		return fmt.Errorf("failed to deserialize vote state: %w", err)
	}

	// Verify withdraw authority
	if authorityAcc.Pubkey != voteState.AuthorizedWithdrawer {
		return fmt.Errorf("%w: signer is not the authorized withdrawer", ErrUnauthorized)
	}

	// Check balance
	if *voteAcc.Lamports < inst.Lamports {
		return fmt.Errorf("%w: need %d lamports, have %d", ErrInsufficientFunds, inst.Lamports, *voteAcc.Lamports)
	}

	// Check if this would leave the account below rent exemption
	remainingLamports := *voteAcc.Lamports - inst.Lamports
	if remainingLamports > 0 {
		rentExemptMinimum := types.RentExemptMinimum(uint64(len(voteAcc.Data)))
		if remainingLamports < uint64(rentExemptMinimum) {
			return fmt.Errorf("%w: withdrawal would leave account below rent exemption minimum", ErrAccountNotRentExempt)
		}
	}

	// Transfer lamports
	*voteAcc.Lamports -= inst.Lamports
	*destAcc.Lamports += inst.Lamports

	return nil
}

// handleUpdateValidatorIdentity handles the UpdateValidatorIdentity instruction.
// Account layout:
//   [0] vote account (writable)
//   [1] new node pubkey (signer)
//   [2] withdraw authority (signer)
func handleUpdateValidatorIdentity(ctx *syscall.ExecutionContext, _ *UpdateValidatorIdentityInstruction) error {
	// Validate we have at least 3 accounts
	if ctx.AccountCount() < 3 {
		return fmt.Errorf("%w: UpdateValidatorIdentity requires 3 accounts", ErrInvalidInstructionData)
	}

	// Get the vote account
	voteAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !voteAcc.IsWritable {
		return fmt.Errorf("%w: vote account", ErrAccountNotWritable)
	}

	// Get the new node pubkey (must be signer)
	newNodeAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !newNodeAcc.IsSigner {
		return fmt.Errorf("%w: new node pubkey", ErrAccountNotSigner)
	}

	// Get the withdraw authority (must be signer)
	authorityAcc, err := ctx.GetAccountByIndex(2)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: withdraw authority", ErrAccountNotSigner)
	}

	// Check if initialized
	if !IsInitialized(voteAcc.Data) {
		return ErrVoteAccountNotInitialized
	}

	// Deserialize vote state
	voteState, err := DeserializeVoteState(voteAcc.Data)
	if err != nil {
		return fmt.Errorf("failed to deserialize vote state: %w", err)
	}

	// Verify withdraw authority
	if authorityAcc.Pubkey != voteState.AuthorizedWithdrawer {
		return fmt.Errorf("%w: signer is not the authorized withdrawer", ErrUnauthorized)
	}

	// Update node pubkey
	voteState.NodePubkey = newNodeAcc.Pubkey

	// Serialize and store
	data, err := voteState.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize vote state: %w", err)
	}
	copy(voteAcc.Data, data)

	return nil
}

// handleUpdateCommission handles the UpdateCommission instruction.
// Account layout:
//   [0] vote account (writable)
//   [1] withdraw authority (signer)
func handleUpdateCommission(ctx *syscall.ExecutionContext, inst *UpdateCommissionInstruction) error {
	// Validate we have at least 2 accounts
	if ctx.AccountCount() < 2 {
		return fmt.Errorf("%w: UpdateCommission requires 2 accounts", ErrInvalidInstructionData)
	}

	// Get the vote account
	voteAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !voteAcc.IsWritable {
		return fmt.Errorf("%w: vote account", ErrAccountNotWritable)
	}

	// Get the withdraw authority (must be signer)
	authorityAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: withdraw authority", ErrAccountNotSigner)
	}

	// Check if initialized
	if !IsInitialized(voteAcc.Data) {
		return ErrVoteAccountNotInitialized
	}

	// Validate commission
	if inst.Commission > 100 {
		return fmt.Errorf("%w: commission must be 0-100, got %d", ErrInvalidCommission, inst.Commission)
	}

	// Deserialize vote state
	voteState, err := DeserializeVoteState(voteAcc.Data)
	if err != nil {
		return fmt.Errorf("failed to deserialize vote state: %w", err)
	}

	// Verify withdraw authority
	if authorityAcc.Pubkey != voteState.AuthorizedWithdrawer {
		return fmt.Errorf("%w: signer is not the authorized withdrawer", ErrUnauthorized)
	}

	// Update commission
	voteState.Commission = inst.Commission

	// Serialize and store
	data, err := voteState.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize vote state: %w", err)
	}
	copy(voteAcc.Data, data)

	return nil
}

// handleVoteSwitch handles the VoteSwitch instruction.
// This is similar to Vote but includes a hash for switch proofs.
// Account layout:
//   [0] vote account (writable)
//   [1] slot hashes sysvar
//   [2] clock sysvar
//   [3] vote authority (signer)
func handleVoteSwitch(ctx *syscall.ExecutionContext, inst *VoteSwitchInstruction) error {
	// For now, treat this the same as a regular vote
	// In production, the hash would be verified against the switch proof
	voteInst := &VoteInstruction{Vote: inst.Vote}
	return handleVote(ctx, voteInst)
}

// handleAuthorizeChecked handles the AuthorizeChecked instruction.
// Similar to Authorize but requires the new authority to also sign.
// Account layout:
//   [0] vote account (writable)
//   [1] clock sysvar
//   [2] current authority (signer)
//   [3] new authority (signer)
func handleAuthorizeChecked(ctx *syscall.ExecutionContext, inst *AuthorizeCheckedInstruction) error {
	// Validate we have at least 4 accounts
	if ctx.AccountCount() < 4 {
		return fmt.Errorf("%w: AuthorizeChecked requires 4 accounts", ErrInvalidInstructionData)
	}

	// Get the new authority (must be signer)
	newAuthorityAcc, err := ctx.GetAccountByIndex(3)
	if err != nil {
		return err
	}
	if !newAuthorityAcc.IsSigner {
		return fmt.Errorf("%w: new authority", ErrAccountNotSigner)
	}

	// Create an Authorize instruction with the new authority's pubkey
	authorizeInst := &AuthorizeInstruction{
		NewAuthority:  newAuthorityAcc.Pubkey,
		AuthorizeType: inst.AuthorizeType,
	}

	return handleAuthorize(ctx, authorizeInst)
}

// handleUpdateVoteState handles the UpdateVoteState instruction.
// Account layout:
//   [0] vote account (writable)
//   [1] vote authority (signer)
func handleUpdateVoteState(ctx *syscall.ExecutionContext, inst *UpdateVoteStateInstruction) error {
	// Validate we have at least 2 accounts
	if ctx.AccountCount() < 2 {
		return fmt.Errorf("%w: UpdateVoteState requires 2 accounts", ErrInvalidInstructionData)
	}

	// Get the vote account
	voteAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !voteAcc.IsWritable {
		return fmt.Errorf("%w: vote account", ErrAccountNotWritable)
	}

	// Check if initialized
	if !IsInitialized(voteAcc.Data) {
		return ErrVoteAccountNotInitialized
	}

	// Get the vote authority (must be signer)
	authorityAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: vote authority", ErrAccountNotSigner)
	}

	// Deserialize vote state
	voteState, err := DeserializeVoteState(voteAcc.Data)
	if err != nil {
		return fmt.Errorf("failed to deserialize vote state: %w", err)
	}

	// Verify vote authority
	currentVoter, found := voteState.GetAuthorizedVoter(ctx.Epoch)
	if !found {
		return ErrUnauthorized
	}
	if authorityAcc.Pubkey != currentVoter {
		return fmt.Errorf("%w: signer is not the authorized voter", ErrUnauthorized)
	}

	// Apply the update
	voteState.Votes = inst.VoteStateUpdate.Lockouts
	voteState.RootSlot = inst.VoteStateUpdate.Root

	// Update timestamp if provided
	if inst.VoteStateUpdate.Timestamp != nil {
		voteState.LastTimestamp = BlockTimestamp{
			Slot:      ctx.Slot,
			Timestamp: *inst.VoteStateUpdate.Timestamp,
		}
	}

	// Serialize and store
	data, err := voteState.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize vote state: %w", err)
	}
	copy(voteAcc.Data, data)

	return nil
}

// handleUpdateVoteStateSwitch handles the UpdateVoteStateSwitch instruction.
// Similar to UpdateVoteState but includes a hash for switch proofs.
func handleUpdateVoteStateSwitch(ctx *syscall.ExecutionContext, inst *UpdateVoteStateSwitchInstruction) error {
	updateInst := &UpdateVoteStateInstruction{VoteStateUpdate: inst.VoteStateUpdate}
	return handleUpdateVoteState(ctx, updateInst)
}

// handleAuthorizeWithSeed handles the AuthorizeWithSeed instruction.
// Account layout:
//   [0] vote account (writable)
//   [1] clock sysvar
//   [2] current authority derived from seed (signer or has signing permission via base)
func handleAuthorizeWithSeed(ctx *syscall.ExecutionContext, inst *AuthorizeWithSeedInstruction) error {
	// Validate we have at least 3 accounts
	if ctx.AccountCount() < 3 {
		return fmt.Errorf("%w: AuthorizeWithSeed requires 3 accounts", ErrInvalidInstructionData)
	}

	// Get the vote account
	voteAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !voteAcc.IsWritable {
		return fmt.Errorf("%w: vote account", ErrAccountNotWritable)
	}

	// Check if initialized
	if !IsInitialized(voteAcc.Data) {
		return ErrVoteAccountNotInitialized
	}

	// Get the current authority account (must be signer)
	authorityAcc, err := ctx.GetAccountByIndex(2)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: current authority", ErrAccountNotSigner)
	}

	// Deserialize vote state
	voteState, err := DeserializeVoteState(voteAcc.Data)
	if err != nil {
		return fmt.Errorf("failed to deserialize vote state: %w", err)
	}

	// Handle based on authorization type
	switch inst.AuthorizeType {
	case VoteAuthorizeVoter:
		voteState.AuthorizedVoters.Insert(ctx.Epoch+1, inst.NewAuthority)

	case VoteAuthorizeWithdrawer:
		voteState.AuthorizedWithdrawer = inst.NewAuthority

	default:
		return ErrInvalidAuthorizeType
	}

	// Serialize and store
	data, err := voteState.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize vote state: %w", err)
	}
	copy(voteAcc.Data, data)

	return nil
}

// handleAuthorizeCheckedWithSeed handles the AuthorizeCheckedWithSeed instruction.
// Account layout:
//   [0] vote account (writable)
//   [1] clock sysvar
//   [2] current authority derived from seed
//   [3] new authority (signer)
func handleAuthorizeCheckedWithSeed(ctx *syscall.ExecutionContext, inst *AuthorizeCheckedWithSeedInstruction) error {
	// Validate we have at least 4 accounts
	if ctx.AccountCount() < 4 {
		return fmt.Errorf("%w: AuthorizeCheckedWithSeed requires 4 accounts", ErrInvalidInstructionData)
	}

	// Get the new authority (must be signer)
	newAuthorityAcc, err := ctx.GetAccountByIndex(3)
	if err != nil {
		return err
	}
	if !newAuthorityAcc.IsSigner {
		return fmt.Errorf("%w: new authority", ErrAccountNotSigner)
	}

	// Create an AuthorizeWithSeed instruction
	authorizeInst := &AuthorizeWithSeedInstruction{
		AuthorizeType:          inst.AuthorizeType,
		CurrentAuthorityPubkey: inst.CurrentAuthorityPubkey,
		CurrentAuthoritySeed:   inst.CurrentAuthoritySeed,
		CurrentAuthorityOwner:  inst.CurrentAuthorityOwner,
		NewAuthority:           newAuthorityAcc.Pubkey,
	}

	return handleAuthorizeWithSeed(ctx, authorizeInst)
}

// handleCompactUpdateVoteState handles the CompactUpdateVoteState instruction.
// Uses a more compact encoding but otherwise similar to UpdateVoteState.
func handleCompactUpdateVoteState(ctx *syscall.ExecutionContext, inst *CompactUpdateVoteStateInstruction) error {
	updateInst := &UpdateVoteStateInstruction{VoteStateUpdate: inst.VoteStateUpdate}
	return handleUpdateVoteState(ctx, updateInst)
}

// handleCompactUpdateVoteStateSwitch handles the CompactUpdateVoteStateSwitch instruction.
func handleCompactUpdateVoteStateSwitch(ctx *syscall.ExecutionContext, inst *CompactUpdateVoteStateSwitchInstruction) error {
	updateInst := &UpdateVoteStateInstruction{VoteStateUpdate: inst.VoteStateUpdate}
	return handleUpdateVoteState(ctx, updateInst)
}

// handleTowerSync handles the TowerSync instruction.
// Account layout:
//   [0] vote account (writable)
//   [1] vote authority (signer)
func handleTowerSync(ctx *syscall.ExecutionContext, inst *TowerSyncInstruction) error {
	// Validate we have at least 2 accounts
	if ctx.AccountCount() < 2 {
		return fmt.Errorf("%w: TowerSync requires 2 accounts", ErrInvalidInstructionData)
	}

	// Get the vote account
	voteAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !voteAcc.IsWritable {
		return fmt.Errorf("%w: vote account", ErrAccountNotWritable)
	}

	// Check if initialized
	if !IsInitialized(voteAcc.Data) {
		return ErrVoteAccountNotInitialized
	}

	// Get the vote authority (must be signer)
	authorityAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: vote authority", ErrAccountNotSigner)
	}

	// Deserialize vote state
	voteState, err := DeserializeVoteState(voteAcc.Data)
	if err != nil {
		return fmt.Errorf("failed to deserialize vote state: %w", err)
	}

	// Verify vote authority
	currentVoter, found := voteState.GetAuthorizedVoter(ctx.Epoch)
	if !found {
		return ErrUnauthorized
	}
	if authorityAcc.Pubkey != currentVoter {
		return fmt.Errorf("%w: signer is not the authorized voter", ErrUnauthorized)
	}

	// Apply the tower sync
	voteState.Votes = inst.TowerSync.Lockouts
	voteState.RootSlot = inst.TowerSync.Root

	// Update timestamp if provided
	if inst.TowerSync.Timestamp != nil {
		voteState.LastTimestamp = BlockTimestamp{
			Slot:      ctx.Slot,
			Timestamp: *inst.TowerSync.Timestamp,
		}
	}

	// Serialize and store
	data, err := voteState.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize vote state: %w", err)
	}
	copy(voteAcc.Data, data)

	return nil
}

// handleTowerSyncSwitch handles the TowerSyncSwitch instruction.
func handleTowerSyncSwitch(ctx *syscall.ExecutionContext, inst *TowerSyncSwitchInstruction) error {
	towerInst := &TowerSyncInstruction{TowerSync: inst.TowerSync}
	return handleTowerSync(ctx, towerInst)
}
