package system

import (
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/svm/syscall"
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// Maximum account data size allowed
const MaxAccountDataSize = 10 * 1024 * 1024 // 10 MB

// handleCreateAccount handles the CreateAccount instruction.
// Account layout:
//   [0] funding account (signer, writable)
//   [1] new account (signer, writable)
func handleCreateAccount(ctx *syscall.ExecutionContext, inst *CreateAccountInstruction) error {
	// Validate we have at least 2 accounts
	if ctx.AccountCount() < 2 {
		return fmt.Errorf("%w: CreateAccount requires 2 accounts", ErrInvalidInstructionData)
	}

	// Get the funding account (must be signer and writable)
	fundingAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !fundingAcc.IsSigner {
		return fmt.Errorf("%w: funding account", ErrAccountNotSigner)
	}
	if !fundingAcc.IsWritable {
		return fmt.Errorf("%w: funding account", ErrAccountNotWritable)
	}

	// Get the new account (must be signer and writable)
	newAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !newAcc.IsSigner {
		return fmt.Errorf("%w: new account", ErrAccountNotSigner)
	}
	if !newAcc.IsWritable {
		return fmt.Errorf("%w: new account", ErrAccountNotWritable)
	}

	// Check if the new account already has lamports or data (already exists)
	if *newAcc.Lamports > 0 || len(newAcc.Data) > 0 {
		return ErrAccountAlreadyExists
	}

	// Validate space
	if inst.Space > MaxAccountDataSize {
		return ErrAccountDataTooLarge
	}

	// Check if the new account will be rent exempt
	rentExemptMinimum := types.RentExemptMinimum(inst.Space)
	if inst.Lamports < uint64(rentExemptMinimum) {
		return fmt.Errorf("%w: need %d lamports for rent exemption", ErrAccountNotRentExempt, rentExemptMinimum)
	}

	// Check if funding account has enough lamports
	if *fundingAcc.Lamports < inst.Lamports {
		return fmt.Errorf("%w: need %d lamports, have %d", ErrInsufficientFunds, inst.Lamports, *fundingAcc.Lamports)
	}

	// Transfer lamports from funding account to new account
	*fundingAcc.Lamports -= inst.Lamports
	*newAcc.Lamports += inst.Lamports

	// Allocate space for the new account
	newAcc.Data = make([]byte, inst.Space)

	// Set the owner
	newAcc.Owner = inst.Owner

	return nil
}

// handleAssign handles the Assign instruction.
// Changes the owner of an account.
// Account layout:
//   [0] account to assign (signer, writable)
func handleAssign(ctx *syscall.ExecutionContext, inst *AssignInstruction) error {
	// Validate we have at least 1 account
	if ctx.AccountCount() < 1 {
		return fmt.Errorf("%w: Assign requires 1 account", ErrInvalidInstructionData)
	}

	// Get the account to assign
	acc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !acc.IsSigner {
		return fmt.Errorf("%w: account to assign", ErrAccountNotSigner)
	}
	if !acc.IsWritable {
		return fmt.Errorf("%w: account to assign", ErrAccountNotWritable)
	}

	// Only the System Program can assign ownership
	// (account must currently be owned by System Program)
	if acc.Owner != types.SystemProgramID {
		return fmt.Errorf("%w: account must be owned by System Program", ErrInvalidAccountOwner)
	}

	// Set the new owner
	acc.Owner = inst.Owner

	return nil
}

// handleTransfer handles the Transfer instruction.
// Transfers lamports between accounts.
// Account layout:
//   [0] source account (signer, writable)
//   [1] destination account (writable)
func handleTransfer(ctx *syscall.ExecutionContext, inst *TransferInstruction) error {
	// Validate we have at least 2 accounts
	if ctx.AccountCount() < 2 {
		return fmt.Errorf("%w: Transfer requires 2 accounts", ErrInvalidInstructionData)
	}

	// Get the source account (must be signer and writable)
	sourceAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !sourceAcc.IsSigner {
		return fmt.Errorf("%w: source account", ErrAccountNotSigner)
	}
	if !sourceAcc.IsWritable {
		return fmt.Errorf("%w: source account", ErrAccountNotWritable)
	}

	// Get the destination account (must be writable)
	destAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !destAcc.IsWritable {
		return fmt.Errorf("%w: destination account", ErrAccountNotWritable)
	}

	// Check if source account has enough lamports
	if *sourceAcc.Lamports < inst.Lamports {
		return fmt.Errorf("%w: need %d lamports, have %d", ErrInsufficientFunds, inst.Lamports, *sourceAcc.Lamports)
	}

	// Transfer lamports
	*sourceAcc.Lamports -= inst.Lamports
	*destAcc.Lamports += inst.Lamports

	return nil
}

// handleCreateAccountWithSeed handles the CreateAccountWithSeed instruction.
// Creates a new account at a derived address.
// Account layout:
//   [0] funding account (signer, writable)
//   [1] created account (writable)
//   [2] base account (signer, optional - required if base != funding)
func handleCreateAccountWithSeed(ctx *syscall.ExecutionContext, inst *CreateAccountWithSeedInstruction) error {
	// Validate we have at least 2 accounts
	if ctx.AccountCount() < 2 {
		return fmt.Errorf("%w: CreateAccountWithSeed requires at least 2 accounts", ErrInvalidInstructionData)
	}

	// Get the funding account
	fundingAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !fundingAcc.IsSigner {
		return fmt.Errorf("%w: funding account", ErrAccountNotSigner)
	}
	if !fundingAcc.IsWritable {
		return fmt.Errorf("%w: funding account", ErrAccountNotWritable)
	}

	// Get the new account
	newAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !newAcc.IsWritable {
		return fmt.Errorf("%w: new account", ErrAccountNotWritable)
	}

	// Check if the new account already exists
	if *newAcc.Lamports > 0 || len(newAcc.Data) > 0 {
		return ErrAccountAlreadyExists
	}

	// Validate seed length
	if len(inst.Seed) > 32 {
		return ErrInvalidSeed
	}

	// Validate space
	if inst.Space > MaxAccountDataSize {
		return ErrAccountDataTooLarge
	}

	// Check rent exemption
	rentExemptMinimum := types.RentExemptMinimum(inst.Space)
	if inst.Lamports < uint64(rentExemptMinimum) {
		return fmt.Errorf("%w: need %d lamports for rent exemption", ErrAccountNotRentExempt, rentExemptMinimum)
	}

	// Check if funding account has enough lamports
	if *fundingAcc.Lamports < inst.Lamports {
		return fmt.Errorf("%w: need %d lamports, have %d", ErrInsufficientFunds, inst.Lamports, *fundingAcc.Lamports)
	}

	// Verify the base account signed if different from funding account
	if inst.Base != fundingAcc.Pubkey {
		if ctx.AccountCount() < 3 {
			return fmt.Errorf("%w: base account required when different from funding", ErrMissingRequiredSignature)
		}
		baseAcc, err := ctx.GetAccountByIndex(2)
		if err != nil {
			return err
		}
		if baseAcc.Pubkey != inst.Base {
			return fmt.Errorf("%w: base account mismatch", ErrInvalidInstructionData)
		}
		if !baseAcc.IsSigner {
			return fmt.Errorf("%w: base account", ErrAccountNotSigner)
		}
	}

	// Transfer lamports
	*fundingAcc.Lamports -= inst.Lamports
	*newAcc.Lamports += inst.Lamports

	// Allocate space
	newAcc.Data = make([]byte, inst.Space)

	// Set owner
	newAcc.Owner = inst.Owner

	return nil
}

// handleAllocate handles the Allocate instruction.
// Allocates space in an account's data.
// Account layout:
//   [0] account to allocate (signer, writable)
func handleAllocate(ctx *syscall.ExecutionContext, inst *AllocateInstruction) error {
	// Validate we have at least 1 account
	if ctx.AccountCount() < 1 {
		return fmt.Errorf("%w: Allocate requires 1 account", ErrInvalidInstructionData)
	}

	// Get the account
	acc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !acc.IsSigner {
		return fmt.Errorf("%w: account to allocate", ErrAccountNotSigner)
	}
	if !acc.IsWritable {
		return fmt.Errorf("%w: account to allocate", ErrAccountNotWritable)
	}

	// Account must be owned by System Program
	if acc.Owner != types.SystemProgramID {
		return fmt.Errorf("%w: account must be owned by System Program", ErrInvalidAccountOwner)
	}

	// Check if already allocated
	if len(acc.Data) > 0 {
		return fmt.Errorf("%w: account already has data", ErrAccountAlreadyExists)
	}

	// Validate space
	if inst.Space > MaxAccountDataSize {
		return ErrAccountDataTooLarge
	}

	// Allocate space
	acc.Data = make([]byte, inst.Space)

	return nil
}

// handleAllocateWithSeed handles the AllocateWithSeed instruction.
// Allocates space in an account derived from a base pubkey and seed.
// Account layout:
//   [0] account to allocate (writable)
//   [1] base account (signer)
func handleAllocateWithSeed(ctx *syscall.ExecutionContext, inst *AllocateWithSeedInstruction) error {
	// Validate we have at least 2 accounts
	if ctx.AccountCount() < 2 {
		return fmt.Errorf("%w: AllocateWithSeed requires 2 accounts", ErrInvalidInstructionData)
	}

	// Get the account to allocate
	acc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !acc.IsWritable {
		return fmt.Errorf("%w: account to allocate", ErrAccountNotWritable)
	}

	// Get the base account
	baseAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !baseAcc.IsSigner {
		return fmt.Errorf("%w: base account", ErrAccountNotSigner)
	}
	if baseAcc.Pubkey != inst.Base {
		return fmt.Errorf("%w: base account mismatch", ErrInvalidInstructionData)
	}

	// Account must be owned by System Program
	if acc.Owner != types.SystemProgramID {
		return fmt.Errorf("%w: account must be owned by System Program", ErrInvalidAccountOwner)
	}

	// Check if already allocated
	if len(acc.Data) > 0 {
		return fmt.Errorf("%w: account already has data", ErrAccountAlreadyExists)
	}

	// Validate seed length
	if len(inst.Seed) > 32 {
		return ErrInvalidSeed
	}

	// Validate space
	if inst.Space > MaxAccountDataSize {
		return ErrAccountDataTooLarge
	}

	// Allocate space
	acc.Data = make([]byte, inst.Space)

	// Assign owner
	acc.Owner = inst.Owner

	return nil
}

// handleAssignWithSeed handles the AssignWithSeed instruction.
// Assigns an owner to an account derived from a base pubkey and seed.
// Account layout:
//   [0] account to assign (writable)
//   [1] base account (signer)
func handleAssignWithSeed(ctx *syscall.ExecutionContext, inst *AssignWithSeedInstruction) error {
	// Validate we have at least 2 accounts
	if ctx.AccountCount() < 2 {
		return fmt.Errorf("%w: AssignWithSeed requires 2 accounts", ErrInvalidInstructionData)
	}

	// Get the account to assign
	acc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !acc.IsWritable {
		return fmt.Errorf("%w: account to assign", ErrAccountNotWritable)
	}

	// Get the base account
	baseAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !baseAcc.IsSigner {
		return fmt.Errorf("%w: base account", ErrAccountNotSigner)
	}
	if baseAcc.Pubkey != inst.Base {
		return fmt.Errorf("%w: base account mismatch", ErrInvalidInstructionData)
	}

	// Account must be owned by System Program
	if acc.Owner != types.SystemProgramID {
		return fmt.Errorf("%w: account must be owned by System Program", ErrInvalidAccountOwner)
	}

	// Validate seed length
	if len(inst.Seed) > 32 {
		return ErrInvalidSeed
	}

	// Assign owner
	acc.Owner = inst.Owner

	return nil
}

// handleTransferWithSeed handles the TransferWithSeed instruction.
// Transfers lamports from an account derived from a base pubkey and seed.
// Account layout:
//   [0] source account (writable)
//   [1] base account (signer)
//   [2] destination account (writable)
func handleTransferWithSeed(ctx *syscall.ExecutionContext, inst *TransferWithSeedInstruction) error {
	// Validate we have at least 3 accounts
	if ctx.AccountCount() < 3 {
		return fmt.Errorf("%w: TransferWithSeed requires 3 accounts", ErrInvalidInstructionData)
	}

	// Get the source account
	sourceAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !sourceAcc.IsWritable {
		return fmt.Errorf("%w: source account", ErrAccountNotWritable)
	}

	// Get the base account (must be signer)
	baseAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !baseAcc.IsSigner {
		return fmt.Errorf("%w: base account", ErrAccountNotSigner)
	}

	// Get the destination account
	destAcc, err := ctx.GetAccountByIndex(2)
	if err != nil {
		return err
	}
	if !destAcc.IsWritable {
		return fmt.Errorf("%w: destination account", ErrAccountNotWritable)
	}

	// Verify the source account owner matches
	if sourceAcc.Owner != inst.FromOwner {
		return fmt.Errorf("%w: source account owner mismatch", ErrInvalidAccountOwner)
	}

	// Validate seed length
	if len(inst.FromSeed) > 32 {
		return ErrInvalidSeed
	}

	// Check if source account has enough lamports
	if *sourceAcc.Lamports < inst.Lamports {
		return fmt.Errorf("%w: need %d lamports, have %d", ErrInsufficientFunds, inst.Lamports, *sourceAcc.Lamports)
	}

	// Transfer lamports
	*sourceAcc.Lamports -= inst.Lamports
	*destAcc.Lamports += inst.Lamports

	return nil
}

// Nonce account handlers (stubs for now)

// handleAdvanceNonceAccount handles the AdvanceNonceAccount instruction.
// Advances the nonce account to a new blockhash.
// Account layout:
//   [0] nonce account (writable)
//   [1] recent blockhashes sysvar
//   [2] nonce authority (signer)
func handleAdvanceNonceAccount(ctx *syscall.ExecutionContext, _ *AdvanceNonceAccountInstruction) error {
	// Stub implementation - nonce accounts require additional state tracking
	if ctx.AccountCount() < 3 {
		return fmt.Errorf("%w: AdvanceNonceAccount requires 3 accounts", ErrInvalidInstructionData)
	}

	// Get nonce account
	nonceAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !nonceAcc.IsWritable {
		return fmt.Errorf("%w: nonce account", ErrAccountNotWritable)
	}

	// Get authority
	authorityAcc, err := ctx.GetAccountByIndex(2)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: nonce authority", ErrAccountNotSigner)
	}

	// TODO: Implement full nonce account logic
	// - Verify account is initialized as nonce
	// - Verify authority matches
	// - Update stored blockhash
	return nil
}

// handleWithdrawNonceAccount handles the WithdrawNonceAccount instruction.
// Withdraws lamports from a nonce account.
// Account layout:
//   [0] nonce account (writable)
//   [1] destination account (writable)
//   [2] recent blockhashes sysvar
//   [3] rent sysvar
//   [4] nonce authority (signer)
func handleWithdrawNonceAccount(ctx *syscall.ExecutionContext, inst *WithdrawNonceAccountInstruction) error {
	// Stub implementation
	if ctx.AccountCount() < 5 {
		return fmt.Errorf("%w: WithdrawNonceAccount requires 5 accounts", ErrInvalidInstructionData)
	}

	// Get nonce account
	nonceAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !nonceAcc.IsWritable {
		return fmt.Errorf("%w: nonce account", ErrAccountNotWritable)
	}

	// Get destination account
	destAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !destAcc.IsWritable {
		return fmt.Errorf("%w: destination account", ErrAccountNotWritable)
	}

	// Get authority
	authorityAcc, err := ctx.GetAccountByIndex(4)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: nonce authority", ErrAccountNotSigner)
	}

	// Check balance
	if *nonceAcc.Lamports < inst.Lamports {
		return fmt.Errorf("%w: need %d lamports, have %d", ErrInsufficientFunds, inst.Lamports, *nonceAcc.Lamports)
	}

	// Transfer lamports
	*nonceAcc.Lamports -= inst.Lamports
	*destAcc.Lamports += inst.Lamports

	return nil
}

// handleInitializeNonceAccount handles the InitializeNonceAccount instruction.
// Initializes a nonce account with the given authority.
// Account layout:
//   [0] nonce account (writable)
//   [1] recent blockhashes sysvar
//   [2] rent sysvar
func handleInitializeNonceAccount(ctx *syscall.ExecutionContext, inst *InitializeNonceAccountInstruction) error {
	// Stub implementation
	if ctx.AccountCount() < 3 {
		return fmt.Errorf("%w: InitializeNonceAccount requires 3 accounts", ErrInvalidInstructionData)
	}

	// Get nonce account
	nonceAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !nonceAcc.IsWritable {
		return fmt.Errorf("%w: nonce account", ErrAccountNotWritable)
	}

	// TODO: Implement full nonce account initialization
	// - Check account is not already initialized
	// - Set nonce account state with authority and blockhash
	_ = inst.Authority

	return nil
}

// handleAuthorizeNonceAccount handles the AuthorizeNonceAccount instruction.
// Changes the authority of a nonce account.
// Account layout:
//   [0] nonce account (writable)
//   [1] current nonce authority (signer)
func handleAuthorizeNonceAccount(ctx *syscall.ExecutionContext, inst *AuthorizeNonceAccountInstruction) error {
	// Stub implementation
	if ctx.AccountCount() < 2 {
		return fmt.Errorf("%w: AuthorizeNonceAccount requires 2 accounts", ErrInvalidInstructionData)
	}

	// Get nonce account
	nonceAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !nonceAcc.IsWritable {
		return fmt.Errorf("%w: nonce account", ErrAccountNotWritable)
	}

	// Get current authority
	authorityAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: current nonce authority", ErrAccountNotSigner)
	}

	// TODO: Implement full authority change
	// - Verify current authority matches
	// - Update to new authority
	_ = inst.Authority

	return nil
}
