package token

import (
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/svm/syscall"
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// handleInitializeMint handles the InitializeMint instruction.
// Initializes a new token mint.
// Account layout:
//   [0] mint (writable) - The mint to initialize
//   [1] rent sysvar
func handleInitializeMint(ctx *syscall.ExecutionContext, inst *InitializeMintInstruction) error {
	if ctx.AccountCount() < 2 {
		return fmt.Errorf("%w: InitializeMint requires 2 accounts, got %d",
			ErrInvalidNumberOfAccounts, ctx.AccountCount())
	}

	// Get the mint account
	mintAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !mintAcc.IsWritable {
		return fmt.Errorf("%w: mint account", ErrAccountNotWritable)
	}

	// Verify mint is not already initialized
	if len(mintAcc.Data) >= MintSize {
		existing, err := DeserializeMint(mintAcc.Data)
		if err == nil && existing.IsInitialized {
			return ErrAlreadyInitialized
		}
	}

	// Ensure the account has the correct size
	if len(mintAcc.Data) < MintSize {
		return fmt.Errorf("%w: mint account data too small, expected %d bytes",
			ErrInvalidAccountData, MintSize)
	}

	// Create the mint
	var freezeAuth *types.Pubkey
	if inst.FreezeAuthority != nil {
		freezeAuth = inst.FreezeAuthority
	}

	mint := NewMint(inst.Decimals, &inst.MintAuthority, freezeAuth)

	// Serialize and write to account
	copy(mintAcc.Data, mint.Serialize())

	return nil
}

// handleInitializeAccount handles the InitializeAccount instruction.
// Initializes a new token account.
// Account layout:
//   [0] account (writable) - The account to initialize
//   [1] mint - The mint for this account
//   [2] owner - The owner of the new account
//   [3] rent sysvar
func handleInitializeAccount(ctx *syscall.ExecutionContext) error {
	if ctx.AccountCount() < 4 {
		return fmt.Errorf("%w: InitializeAccount requires 4 accounts, got %d",
			ErrInvalidNumberOfAccounts, ctx.AccountCount())
	}

	// Get the token account
	tokenAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !tokenAcc.IsWritable {
		return fmt.Errorf("%w: token account", ErrAccountNotWritable)
	}

	// Get the mint account
	mintAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}

	// Get the owner
	ownerAcc, err := ctx.GetAccountByIndex(2)
	if err != nil {
		return err
	}

	// Verify token account is not already initialized
	if len(tokenAcc.Data) >= TokenAccountSize {
		existing, err := DeserializeTokenAccount(tokenAcc.Data)
		if err == nil && existing.State != AccountStateUninitialized {
			return ErrAlreadyInitialized
		}
	}

	// Ensure the account has the correct size
	if len(tokenAcc.Data) < TokenAccountSize {
		return fmt.Errorf("%w: token account data too small, expected %d bytes",
			ErrInvalidAccountData, TokenAccountSize)
	}

	// Verify mint is initialized
	if len(mintAcc.Data) < MintSize {
		return fmt.Errorf("%w: mint account data too small", ErrInvalidMint)
	}
	mint, err := DeserializeMint(mintAcc.Data)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidMint, err)
	}
	if !mint.IsInitialized {
		return fmt.Errorf("%w: mint not initialized", ErrInvalidMint)
	}

	// Create the token account
	account := NewTokenAccount(mintAcc.Pubkey, ownerAcc.Pubkey)

	// Serialize and write to account
	copy(tokenAcc.Data, account.Serialize())

	return nil
}

// handleTransfer handles the Transfer instruction.
// Transfers tokens between accounts.
// Account layout:
//   [0] source (writable) - The source token account
//   [1] destination (writable) - The destination token account
//   [2] authority (signer) - The source account owner or delegate
func handleTransfer(ctx *syscall.ExecutionContext, inst *TransferInstruction) error {
	if ctx.AccountCount() < 3 {
		return fmt.Errorf("%w: Transfer requires 3 accounts, got %d",
			ErrInvalidNumberOfAccounts, ctx.AccountCount())
	}

	// Get the source account
	sourceAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !sourceAcc.IsWritable {
		return fmt.Errorf("%w: source account", ErrAccountNotWritable)
	}

	// Get the destination account
	destAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !destAcc.IsWritable {
		return fmt.Errorf("%w: destination account", ErrAccountNotWritable)
	}

	// Get the authority
	authorityAcc, err := ctx.GetAccountByIndex(2)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: authority", ErrAccountNotSigner)
	}

	// Deserialize accounts
	source, err := DeserializeTokenAccount(sourceAcc.Data)
	if err != nil {
		return fmt.Errorf("source: %w", err)
	}
	dest, err := DeserializeTokenAccount(destAcc.Data)
	if err != nil {
		return fmt.Errorf("destination: %w", err)
	}

	// Verify accounts are initialized
	if source.State == AccountStateUninitialized {
		return fmt.Errorf("source: %w", ErrNotInitialized)
	}
	if dest.State == AccountStateUninitialized {
		return fmt.Errorf("destination: %w", ErrNotInitialized)
	}

	// Verify accounts are not frozen
	if source.IsFrozen() {
		return fmt.Errorf("source: %w", ErrAccountFrozen)
	}
	if dest.IsFrozen() {
		return fmt.Errorf("destination: %w", ErrAccountFrozen)
	}

	// Verify mints match
	if source.Mint != dest.Mint {
		return ErrMintMismatch
	}

	// Verify authority
	isOwner := source.Owner == authorityAcc.Pubkey
	isDelegate := source.Delegate.IsSome && source.Delegate.Value == authorityAcc.Pubkey

	if !isOwner && !isDelegate {
		return ErrOwnerMismatch
	}

	// Check for sufficient funds
	var availableAmount uint64
	if isDelegate {
		availableAmount = source.DelegatedAmount
	} else {
		availableAmount = source.Amount
	}

	if inst.Amount > availableAmount {
		return ErrInsufficientFunds
	}

	// Perform the transfer
	source.Amount -= inst.Amount
	dest.Amount += inst.Amount

	// Update delegated amount if using delegate
	if isDelegate {
		source.DelegatedAmount -= inst.Amount
	}

	// Serialize and write back
	copy(sourceAcc.Data, source.Serialize())
	copy(destAcc.Data, dest.Serialize())

	return nil
}

// handleMintTo handles the MintTo instruction.
// Mints new tokens to an account.
// Account layout:
//   [0] mint (writable) - The mint
//   [1] destination (writable) - The account to mint to
//   [2] mint_authority (signer) - The mint authority
func handleMintTo(ctx *syscall.ExecutionContext, inst *MintToInstruction) error {
	if ctx.AccountCount() < 3 {
		return fmt.Errorf("%w: MintTo requires 3 accounts, got %d",
			ErrInvalidNumberOfAccounts, ctx.AccountCount())
	}

	// Get the mint account
	mintAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !mintAcc.IsWritable {
		return fmt.Errorf("%w: mint account", ErrAccountNotWritable)
	}

	// Get the destination account
	destAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !destAcc.IsWritable {
		return fmt.Errorf("%w: destination account", ErrAccountNotWritable)
	}

	// Get the authority
	authorityAcc, err := ctx.GetAccountByIndex(2)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: mint authority", ErrAccountNotSigner)
	}

	// Deserialize accounts
	mint, err := DeserializeMint(mintAcc.Data)
	if err != nil {
		return fmt.Errorf("mint: %w", err)
	}
	dest, err := DeserializeTokenAccount(destAcc.Data)
	if err != nil {
		return fmt.Errorf("destination: %w", err)
	}

	// Verify mint is initialized
	if !mint.IsInitialized {
		return fmt.Errorf("mint: %w", ErrNotInitialized)
	}

	// Verify destination is initialized
	if dest.State == AccountStateUninitialized {
		return fmt.Errorf("destination: %w", ErrNotInitialized)
	}

	// Verify destination is not frozen
	if dest.IsFrozen() {
		return fmt.Errorf("destination: %w", ErrAccountFrozen)
	}

	// Verify destination mint matches
	if dest.Mint != mintAcc.Pubkey {
		return ErrMintMismatch
	}

	// Verify mint authority
	if !mint.MintAuthority.IsSome {
		return ErrFixedSupply
	}
	if mint.MintAuthority.Value != authorityAcc.Pubkey {
		return ErrAuthorityMismatch
	}

	// Check for overflow
	if mint.Supply > ^uint64(0)-inst.Amount {
		return ErrOverflow
	}
	if dest.Amount > ^uint64(0)-inst.Amount {
		return ErrOverflow
	}

	// Mint tokens
	mint.Supply += inst.Amount
	dest.Amount += inst.Amount

	// Serialize and write back
	copy(mintAcc.Data, mint.Serialize())
	copy(destAcc.Data, dest.Serialize())

	return nil
}

// handleBurn handles the Burn instruction.
// Burns tokens from an account.
// Account layout:
//   [0] source (writable) - The token account to burn from
//   [1] mint (writable) - The mint
//   [2] authority (signer) - The account owner or delegate
func handleBurn(ctx *syscall.ExecutionContext, inst *BurnInstruction) error {
	if ctx.AccountCount() < 3 {
		return fmt.Errorf("%w: Burn requires 3 accounts, got %d",
			ErrInvalidNumberOfAccounts, ctx.AccountCount())
	}

	// Get the source account
	sourceAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !sourceAcc.IsWritable {
		return fmt.Errorf("%w: source account", ErrAccountNotWritable)
	}

	// Get the mint account
	mintAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !mintAcc.IsWritable {
		return fmt.Errorf("%w: mint account", ErrAccountNotWritable)
	}

	// Get the authority
	authorityAcc, err := ctx.GetAccountByIndex(2)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: authority", ErrAccountNotSigner)
	}

	// Deserialize accounts
	source, err := DeserializeTokenAccount(sourceAcc.Data)
	if err != nil {
		return fmt.Errorf("source: %w", err)
	}
	mint, err := DeserializeMint(mintAcc.Data)
	if err != nil {
		return fmt.Errorf("mint: %w", err)
	}

	// Verify source is initialized
	if source.State == AccountStateUninitialized {
		return fmt.Errorf("source: %w", ErrNotInitialized)
	}

	// Verify mint is initialized
	if !mint.IsInitialized {
		return fmt.Errorf("mint: %w", ErrNotInitialized)
	}

	// Verify source is not frozen
	if source.IsFrozen() {
		return fmt.Errorf("source: %w", ErrAccountFrozen)
	}

	// Verify source mint matches
	if source.Mint != mintAcc.Pubkey {
		return ErrMintMismatch
	}

	// Verify authority
	isOwner := source.Owner == authorityAcc.Pubkey
	isDelegate := source.Delegate.IsSome && source.Delegate.Value == authorityAcc.Pubkey

	if !isOwner && !isDelegate {
		return ErrOwnerMismatch
	}

	// Check for sufficient funds
	var availableAmount uint64
	if isDelegate {
		availableAmount = source.DelegatedAmount
	} else {
		availableAmount = source.Amount
	}

	if inst.Amount > availableAmount {
		return ErrInsufficientFunds
	}

	// Burn tokens
	source.Amount -= inst.Amount
	mint.Supply -= inst.Amount

	// Update delegated amount if using delegate
	if isDelegate {
		source.DelegatedAmount -= inst.Amount
	}

	// Serialize and write back
	copy(sourceAcc.Data, source.Serialize())
	copy(mintAcc.Data, mint.Serialize())

	return nil
}

// handleApprove handles the Approve instruction.
// Approves a delegate to transfer tokens.
// Account layout:
//   [0] source (writable) - The token account to delegate
//   [1] delegate - The delegate account
//   [2] owner (signer) - The source account owner
func handleApprove(ctx *syscall.ExecutionContext, inst *ApproveInstruction) error {
	if ctx.AccountCount() < 3 {
		return fmt.Errorf("%w: Approve requires 3 accounts, got %d",
			ErrInvalidNumberOfAccounts, ctx.AccountCount())
	}

	// Get the source account
	sourceAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !sourceAcc.IsWritable {
		return fmt.Errorf("%w: source account", ErrAccountNotWritable)
	}

	// Get the delegate
	delegateAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}

	// Get the owner
	ownerAcc, err := ctx.GetAccountByIndex(2)
	if err != nil {
		return err
	}
	if !ownerAcc.IsSigner {
		return fmt.Errorf("%w: owner", ErrAccountNotSigner)
	}

	// Deserialize source account
	source, err := DeserializeTokenAccount(sourceAcc.Data)
	if err != nil {
		return fmt.Errorf("source: %w", err)
	}

	// Verify source is initialized
	if source.State == AccountStateUninitialized {
		return fmt.Errorf("source: %w", ErrNotInitialized)
	}

	// Verify owner
	if source.Owner != ownerAcc.Pubkey {
		return ErrOwnerMismatch
	}

	// Set delegate
	source.Delegate = COption{IsSome: true, Value: delegateAcc.Pubkey}
	source.DelegatedAmount = inst.Amount

	// Serialize and write back
	copy(sourceAcc.Data, source.Serialize())

	return nil
}

// handleRevoke handles the Revoke instruction.
// Revokes the delegate.
// Account layout:
//   [0] source (writable) - The token account
//   [1] owner (signer) - The source account owner
func handleRevoke(ctx *syscall.ExecutionContext) error {
	if ctx.AccountCount() < 2 {
		return fmt.Errorf("%w: Revoke requires 2 accounts, got %d",
			ErrInvalidNumberOfAccounts, ctx.AccountCount())
	}

	// Get the source account
	sourceAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !sourceAcc.IsWritable {
		return fmt.Errorf("%w: source account", ErrAccountNotWritable)
	}

	// Get the owner
	ownerAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !ownerAcc.IsSigner {
		return fmt.Errorf("%w: owner", ErrAccountNotSigner)
	}

	// Deserialize source account
	source, err := DeserializeTokenAccount(sourceAcc.Data)
	if err != nil {
		return fmt.Errorf("source: %w", err)
	}

	// Verify source is initialized
	if source.State == AccountStateUninitialized {
		return fmt.Errorf("source: %w", ErrNotInitialized)
	}

	// Verify owner
	if source.Owner != ownerAcc.Pubkey {
		return ErrOwnerMismatch
	}

	// Clear delegate
	source.Delegate = COption{IsSome: false}
	source.DelegatedAmount = 0

	// Serialize and write back
	copy(sourceAcc.Data, source.Serialize())

	return nil
}

// handleCloseAccount handles the CloseAccount instruction.
// Closes a token account and transfers remaining lamports.
// Account layout:
//   [0] account (writable) - The account to close
//   [1] destination (writable) - The account to receive remaining lamports
//   [2] authority (signer) - The account owner or close authority
func handleCloseAccount(ctx *syscall.ExecutionContext) error {
	if ctx.AccountCount() < 3 {
		return fmt.Errorf("%w: CloseAccount requires 3 accounts, got %d",
			ErrInvalidNumberOfAccounts, ctx.AccountCount())
	}

	// Get the account to close
	closeAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !closeAcc.IsWritable {
		return fmt.Errorf("%w: account to close", ErrAccountNotWritable)
	}

	// Get the destination account
	destAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !destAcc.IsWritable {
		return fmt.Errorf("%w: destination account", ErrAccountNotWritable)
	}

	// Get the authority
	authorityAcc, err := ctx.GetAccountByIndex(2)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: authority", ErrAccountNotSigner)
	}

	// Deserialize account
	account, err := DeserializeTokenAccount(closeAcc.Data)
	if err != nil {
		return fmt.Errorf("account: %w", err)
	}

	// Verify account is initialized
	if account.State == AccountStateUninitialized {
		return fmt.Errorf("account: %w", ErrNotInitialized)
	}

	// Check if account has remaining balance (only native accounts can have remaining balance)
	if account.Amount > 0 && !account.IsNativeAccount() {
		return ErrNonNativeAccountHasBalance
	}

	// Verify authority (owner or close authority)
	isOwner := account.Owner == authorityAcc.Pubkey
	isCloseAuth := account.CloseAuthority.IsSome && account.CloseAuthority.Value == authorityAcc.Pubkey

	if !isOwner && !isCloseAuth {
		return ErrOwnerMismatch
	}

	// Transfer remaining lamports
	*destAcc.Lamports += *closeAcc.Lamports
	*closeAcc.Lamports = 0

	// Clear account data
	for i := range closeAcc.Data {
		closeAcc.Data[i] = 0
	}

	return nil
}

// handleSetAuthority handles the SetAuthority instruction.
// Changes an authority on a mint or token account.
// Account layout:
//   [0] account (writable) - The mint or token account
//   [1] current_authority (signer) - The current authority
func handleSetAuthority(ctx *syscall.ExecutionContext, inst *SetAuthorityInstruction) error {
	if ctx.AccountCount() < 2 {
		return fmt.Errorf("%w: SetAuthority requires 2 accounts, got %d",
			ErrInvalidNumberOfAccounts, ctx.AccountCount())
	}

	// Get the account
	acc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !acc.IsWritable {
		return fmt.Errorf("%w: account", ErrAccountNotWritable)
	}

	// Get the current authority
	authorityAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: current authority", ErrAccountNotSigner)
	}

	// Determine if this is a mint or token account based on data size and authority type
	switch inst.AuthorityType {
	case AuthorityTypeMintTokens, AuthorityTypeFreezeAccount:
		// Mint authority types
		return handleSetMintAuthority(acc, authorityAcc, inst)
	case AuthorityTypeAccountOwner, AuthorityTypeCloseAccount:
		// Token account authority types
		return handleSetTokenAccountAuthority(acc, authorityAcc, inst)
	default:
		return fmt.Errorf("%w: unknown authority type %d", ErrInvalidInstruction, inst.AuthorityType)
	}
}

func handleSetMintAuthority(acc *syscall.AccountInfo, authorityAcc *syscall.AccountInfo, inst *SetAuthorityInstruction) error {
	mint, err := DeserializeMint(acc.Data)
	if err != nil {
		return fmt.Errorf("mint: %w", err)
	}

	if !mint.IsInitialized {
		return fmt.Errorf("mint: %w", ErrNotInitialized)
	}

	switch inst.AuthorityType {
	case AuthorityTypeMintTokens:
		if !mint.MintAuthority.IsSome {
			return ErrNoAuthority
		}
		if mint.MintAuthority.Value != authorityAcc.Pubkey {
			return ErrAuthorityMismatch
		}
		if inst.NewAuthority != nil {
			mint.MintAuthority = COption{IsSome: true, Value: *inst.NewAuthority}
		} else {
			mint.MintAuthority = COption{IsSome: false}
		}

	case AuthorityTypeFreezeAccount:
		if !mint.FreezeAuthority.IsSome {
			return ErrNoAuthority
		}
		if mint.FreezeAuthority.Value != authorityAcc.Pubkey {
			return ErrAuthorityMismatch
		}
		if inst.NewAuthority != nil {
			mint.FreezeAuthority = COption{IsSome: true, Value: *inst.NewAuthority}
		} else {
			mint.FreezeAuthority = COption{IsSome: false}
		}
	}

	copy(acc.Data, mint.Serialize())
	return nil
}

func handleSetTokenAccountAuthority(acc *syscall.AccountInfo, authorityAcc *syscall.AccountInfo, inst *SetAuthorityInstruction) error {
	account, err := DeserializeTokenAccount(acc.Data)
	if err != nil {
		return fmt.Errorf("token account: %w", err)
	}

	if account.State == AccountStateUninitialized {
		return fmt.Errorf("token account: %w", ErrNotInitialized)
	}

	switch inst.AuthorityType {
	case AuthorityTypeAccountOwner:
		if account.Owner != authorityAcc.Pubkey {
			return ErrOwnerMismatch
		}
		if inst.NewAuthority == nil {
			return fmt.Errorf("%w: cannot remove account owner", ErrInvalidInstruction)
		}
		account.Owner = *inst.NewAuthority
		// Clear delegate when owner changes
		account.Delegate = COption{IsSome: false}
		account.DelegatedAmount = 0

	case AuthorityTypeCloseAccount:
		// Verify current close authority or owner
		hasCloseAuth := account.CloseAuthority.IsSome && account.CloseAuthority.Value == authorityAcc.Pubkey
		isOwner := account.Owner == authorityAcc.Pubkey

		if !hasCloseAuth && !isOwner {
			return ErrOwnerMismatch
		}

		if inst.NewAuthority != nil {
			account.CloseAuthority = COption{IsSome: true, Value: *inst.NewAuthority}
		} else {
			account.CloseAuthority = COption{IsSome: false}
		}
	}

	copy(acc.Data, account.Serialize())
	return nil
}

// handleFreezeAccount handles the FreezeAccount instruction.
// Freezes a token account.
// Account layout:
//   [0] account (writable) - The token account to freeze
//   [1] mint - The mint
//   [2] freeze_authority (signer) - The freeze authority
func handleFreezeAccount(ctx *syscall.ExecutionContext) error {
	if ctx.AccountCount() < 3 {
		return fmt.Errorf("%w: FreezeAccount requires 3 accounts, got %d",
			ErrInvalidNumberOfAccounts, ctx.AccountCount())
	}

	// Get the token account
	tokenAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !tokenAcc.IsWritable {
		return fmt.Errorf("%w: token account", ErrAccountNotWritable)
	}

	// Get the mint account
	mintAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}

	// Get the freeze authority
	authorityAcc, err := ctx.GetAccountByIndex(2)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: freeze authority", ErrAccountNotSigner)
	}

	// Deserialize accounts
	account, err := DeserializeTokenAccount(tokenAcc.Data)
	if err != nil {
		return fmt.Errorf("token account: %w", err)
	}
	mint, err := DeserializeMint(mintAcc.Data)
	if err != nil {
		return fmt.Errorf("mint: %w", err)
	}

	// Verify account is initialized
	if account.State == AccountStateUninitialized {
		return fmt.Errorf("token account: %w", ErrNotInitialized)
	}

	// Verify mint matches
	if account.Mint != mintAcc.Pubkey {
		return ErrMintMismatch
	}

	// Verify freeze authority
	if !mint.FreezeAuthority.IsSome {
		return ErrMintCannotFreeze
	}
	if mint.FreezeAuthority.Value != authorityAcc.Pubkey {
		return ErrAuthorityMismatch
	}

	// Freeze the account
	account.State = AccountStateFrozen

	// Serialize and write back
	copy(tokenAcc.Data, account.Serialize())

	return nil
}

// handleThawAccount handles the ThawAccount instruction.
// Thaws a frozen token account.
// Account layout:
//   [0] account (writable) - The token account to thaw
//   [1] mint - The mint
//   [2] freeze_authority (signer) - The freeze authority
func handleThawAccount(ctx *syscall.ExecutionContext) error {
	if ctx.AccountCount() < 3 {
		return fmt.Errorf("%w: ThawAccount requires 3 accounts, got %d",
			ErrInvalidNumberOfAccounts, ctx.AccountCount())
	}

	// Get the token account
	tokenAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !tokenAcc.IsWritable {
		return fmt.Errorf("%w: token account", ErrAccountNotWritable)
	}

	// Get the mint account
	mintAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}

	// Get the freeze authority
	authorityAcc, err := ctx.GetAccountByIndex(2)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: freeze authority", ErrAccountNotSigner)
	}

	// Deserialize accounts
	account, err := DeserializeTokenAccount(tokenAcc.Data)
	if err != nil {
		return fmt.Errorf("token account: %w", err)
	}
	mint, err := DeserializeMint(mintAcc.Data)
	if err != nil {
		return fmt.Errorf("mint: %w", err)
	}

	// Verify account is frozen
	if account.State != AccountStateFrozen {
		return fmt.Errorf("token account: %w", ErrNotInitialized)
	}

	// Verify mint matches
	if account.Mint != mintAcc.Pubkey {
		return ErrMintMismatch
	}

	// Verify freeze authority
	if !mint.FreezeAuthority.IsSome {
		return ErrMintCannotFreeze
	}
	if mint.FreezeAuthority.Value != authorityAcc.Pubkey {
		return ErrAuthorityMismatch
	}

	// Thaw the account
	account.State = AccountStateInitialized

	// Serialize and write back
	copy(tokenAcc.Data, account.Serialize())

	return nil
}

// handleTransferChecked handles the TransferChecked instruction.
// Transfers tokens between accounts with decimal verification.
// Account layout:
//   [0] source (writable) - The source token account
//   [1] mint - The mint
//   [2] destination (writable) - The destination token account
//   [3] authority (signer) - The source account owner or delegate
func handleTransferChecked(ctx *syscall.ExecutionContext, inst *TransferCheckedInstruction) error {
	if ctx.AccountCount() < 4 {
		return fmt.Errorf("%w: TransferChecked requires 4 accounts, got %d",
			ErrInvalidNumberOfAccounts, ctx.AccountCount())
	}

	// Get the mint account first to verify decimals
	mintAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}

	mint, err := DeserializeMint(mintAcc.Data)
	if err != nil {
		return fmt.Errorf("mint: %w", err)
	}

	// Verify decimals match
	if mint.Decimals != inst.Decimals {
		return ErrDecimalsMismatch
	}

	// Get the source account
	sourceAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !sourceAcc.IsWritable {
		return fmt.Errorf("%w: source account", ErrAccountNotWritable)
	}

	// Get the destination account
	destAcc, err := ctx.GetAccountByIndex(2)
	if err != nil {
		return err
	}
	if !destAcc.IsWritable {
		return fmt.Errorf("%w: destination account", ErrAccountNotWritable)
	}

	// Get the authority
	authorityAcc, err := ctx.GetAccountByIndex(3)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: authority", ErrAccountNotSigner)
	}

	// Deserialize accounts
	source, err := DeserializeTokenAccount(sourceAcc.Data)
	if err != nil {
		return fmt.Errorf("source: %w", err)
	}
	dest, err := DeserializeTokenAccount(destAcc.Data)
	if err != nil {
		return fmt.Errorf("destination: %w", err)
	}

	// Verify accounts are initialized
	if source.State == AccountStateUninitialized {
		return fmt.Errorf("source: %w", ErrNotInitialized)
	}
	if dest.State == AccountStateUninitialized {
		return fmt.Errorf("destination: %w", ErrNotInitialized)
	}

	// Verify accounts are not frozen
	if source.IsFrozen() {
		return fmt.Errorf("source: %w", ErrAccountFrozen)
	}
	if dest.IsFrozen() {
		return fmt.Errorf("destination: %w", ErrAccountFrozen)
	}

	// Verify mints match
	if source.Mint != mintAcc.Pubkey || dest.Mint != mintAcc.Pubkey {
		return ErrMintMismatch
	}

	// Verify authority
	isOwner := source.Owner == authorityAcc.Pubkey
	isDelegate := source.Delegate.IsSome && source.Delegate.Value == authorityAcc.Pubkey

	if !isOwner && !isDelegate {
		return ErrOwnerMismatch
	}

	// Check for sufficient funds
	var availableAmount uint64
	if isDelegate {
		availableAmount = source.DelegatedAmount
	} else {
		availableAmount = source.Amount
	}

	if inst.Amount > availableAmount {
		return ErrInsufficientFunds
	}

	// Perform the transfer
	source.Amount -= inst.Amount
	dest.Amount += inst.Amount

	// Update delegated amount if using delegate
	if isDelegate {
		source.DelegatedAmount -= inst.Amount
	}

	// Serialize and write back
	copy(sourceAcc.Data, source.Serialize())
	copy(destAcc.Data, dest.Serialize())

	return nil
}

// handleMintToChecked handles the MintToChecked instruction.
// Mints new tokens to an account with decimal verification.
// Account layout:
//   [0] mint (writable) - The mint
//   [1] destination (writable) - The account to mint to
//   [2] mint_authority (signer) - The mint authority
func handleMintToChecked(ctx *syscall.ExecutionContext, inst *MintToCheckedInstruction) error {
	if ctx.AccountCount() < 3 {
		return fmt.Errorf("%w: MintToChecked requires 3 accounts, got %d",
			ErrInvalidNumberOfAccounts, ctx.AccountCount())
	}

	// Get the mint account
	mintAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !mintAcc.IsWritable {
		return fmt.Errorf("%w: mint account", ErrAccountNotWritable)
	}

	// Deserialize mint to verify decimals
	mint, err := DeserializeMint(mintAcc.Data)
	if err != nil {
		return fmt.Errorf("mint: %w", err)
	}

	// Verify decimals match
	if mint.Decimals != inst.Decimals {
		return ErrDecimalsMismatch
	}

	// Call the regular MintTo handler
	mintToInst := &MintToInstruction{Amount: inst.Amount}
	return handleMintTo(ctx, mintToInst)
}

// handleBurnChecked handles the BurnChecked instruction.
// Burns tokens from an account with decimal verification.
// Account layout:
//   [0] source (writable) - The token account to burn from
//   [1] mint (writable) - The mint
//   [2] authority (signer) - The account owner or delegate
func handleBurnChecked(ctx *syscall.ExecutionContext, inst *BurnCheckedInstruction) error {
	if ctx.AccountCount() < 3 {
		return fmt.Errorf("%w: BurnChecked requires 3 accounts, got %d",
			ErrInvalidNumberOfAccounts, ctx.AccountCount())
	}

	// Get the mint account
	mintAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}

	// Deserialize mint to verify decimals
	mint, err := DeserializeMint(mintAcc.Data)
	if err != nil {
		return fmt.Errorf("mint: %w", err)
	}

	// Verify decimals match
	if mint.Decimals != inst.Decimals {
		return ErrDecimalsMismatch
	}

	// Call the regular Burn handler
	burnInst := &BurnInstruction{Amount: inst.Amount}
	return handleBurn(ctx, burnInst)
}

// handleApproveChecked handles the ApproveChecked instruction.
// Approves a delegate with decimal verification.
// Account layout:
//   [0] source (writable) - The token account
//   [1] mint - The mint
//   [2] delegate - The delegate account
//   [3] owner (signer) - The source account owner
func handleApproveChecked(ctx *syscall.ExecutionContext, inst *ApproveCheckedInstruction) error {
	if ctx.AccountCount() < 4 {
		return fmt.Errorf("%w: ApproveChecked requires 4 accounts, got %d",
			ErrInvalidNumberOfAccounts, ctx.AccountCount())
	}

	// Get the mint account
	mintAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}

	// Deserialize mint to verify decimals
	mint, err := DeserializeMint(mintAcc.Data)
	if err != nil {
		return fmt.Errorf("mint: %w", err)
	}

	// Verify decimals match
	if mint.Decimals != inst.Decimals {
		return ErrDecimalsMismatch
	}

	// Get the source account
	sourceAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !sourceAcc.IsWritable {
		return fmt.Errorf("%w: source account", ErrAccountNotWritable)
	}

	// Get the delegate
	delegateAcc, err := ctx.GetAccountByIndex(2)
	if err != nil {
		return err
	}

	// Get the owner
	ownerAcc, err := ctx.GetAccountByIndex(3)
	if err != nil {
		return err
	}
	if !ownerAcc.IsSigner {
		return fmt.Errorf("%w: owner", ErrAccountNotSigner)
	}

	// Deserialize source account
	source, err := DeserializeTokenAccount(sourceAcc.Data)
	if err != nil {
		return fmt.Errorf("source: %w", err)
	}

	// Verify source is initialized
	if source.State == AccountStateUninitialized {
		return fmt.Errorf("source: %w", ErrNotInitialized)
	}

	// Verify mint matches
	if source.Mint != mintAcc.Pubkey {
		return ErrMintMismatch
	}

	// Verify owner
	if source.Owner != ownerAcc.Pubkey {
		return ErrOwnerMismatch
	}

	// Set delegate
	source.Delegate = COption{IsSome: true, Value: delegateAcc.Pubkey}
	source.DelegatedAmount = inst.Amount

	// Serialize and write back
	copy(sourceAcc.Data, source.Serialize())

	return nil
}
