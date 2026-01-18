package address_lookup_table

import (
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/svm/syscall"
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// handleCreateLookupTable handles the CreateLookupTable instruction.
// Creates a new address lookup table at a derived address.
//
// Account layout:
//   [0] lookup table account (writable) - PDA to create
//   [1] authority (signer, writable) - authority for the table
//   [2] payer (signer, writable) - account paying for creation
//   [3] system program
func handleCreateLookupTable(ctx *syscall.ExecutionContext, inst *CreateLookupTableInstruction) error {
	// Validate we have at least 4 accounts
	if ctx.AccountCount() < 4 {
		return fmt.Errorf("%w: CreateLookupTable requires 4 accounts", ErrInvalidInstructionData)
	}

	// Get the lookup table account (must be writable)
	tableAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !tableAcc.IsWritable {
		return fmt.Errorf("%w: lookup table account", ErrAccountNotWritable)
	}

	// Get the authority account (must be signer)
	authorityAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: authority account", ErrAccountNotSigner)
	}

	// Get the payer account (must be signer and writable)
	payerAcc, err := ctx.GetAccountByIndex(2)
	if err != nil {
		return err
	}
	if !payerAcc.IsSigner {
		return fmt.Errorf("%w: payer account", ErrAccountNotSigner)
	}
	if !payerAcc.IsWritable {
		return fmt.Errorf("%w: payer account", ErrAccountNotWritable)
	}

	// Verify the derived address
	if !VerifyDerivedAddress(tableAcc.Pubkey, authorityAcc.Pubkey, inst.RecentSlot, inst.BumpSeed) {
		return fmt.Errorf("%w: table address does not match derived PDA", ErrInvalidDerivedAddress)
	}

	// Verify the slot is not too old (must be within slot hashes)
	// In production, this would check against the SlotHashes sysvar
	if inst.RecentSlot > ctx.Slot {
		return fmt.Errorf("%w: recent_slot is in the future", ErrInvalidSlot)
	}

	// Check if the account already exists (has data or lamports)
	if *tableAcc.Lamports > 0 || len(tableAcc.Data) > 0 {
		return ErrAccountAlreadyExists
	}

	// Create a new empty lookup table
	lookupTable := NewAddressLookupTable(authorityAcc.Pubkey)

	// Serialize the lookup table
	tableData := lookupTable.Serialize()

	// Calculate rent-exempt minimum
	rentExemptMinimum := types.RentExemptMinimum(uint64(len(tableData)))

	// Check if payer has enough lamports
	if *payerAcc.Lamports < uint64(rentExemptMinimum) {
		return fmt.Errorf("%w: need %d lamports for rent exemption, have %d",
			ErrInsufficientFunds, rentExemptMinimum, *payerAcc.Lamports)
	}

	// Transfer lamports from payer to table account
	*payerAcc.Lamports -= uint64(rentExemptMinimum)
	*tableAcc.Lamports += uint64(rentExemptMinimum)

	// Initialize the account data
	tableAcc.Data = tableData

	// Set the owner to the Address Lookup Table Program
	tableAcc.Owner = types.AddressLookupTableProgramID

	return nil
}

// handleFreezeLookupTable handles the FreezeLookupTable instruction.
// Freezes a lookup table by removing the authority (makes it immutable).
//
// Account layout:
//   [0] lookup table account (writable)
//   [1] authority (signer)
func handleFreezeLookupTable(ctx *syscall.ExecutionContext, _ *FreezeLookupTableInstruction) error {
	// Validate we have at least 2 accounts
	if ctx.AccountCount() < 2 {
		return fmt.Errorf("%w: FreezeLookupTable requires 2 accounts", ErrInvalidInstructionData)
	}

	// Get the lookup table account
	tableAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !tableAcc.IsWritable {
		return fmt.Errorf("%w: lookup table account", ErrAccountNotWritable)
	}

	// Verify ownership
	if tableAcc.Owner != types.AddressLookupTableProgramID {
		return fmt.Errorf("%w: account not owned by Address Lookup Table Program", ErrInvalidAccountOwner)
	}

	// Get the authority account
	authorityAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: authority account", ErrAccountNotSigner)
	}

	// Deserialize the lookup table
	lookupTable, err := DeserializeAddressLookupTable(tableAcc.Data)
	if err != nil {
		return err
	}

	// Check if already frozen
	if lookupTable.Meta.IsFrozen() {
		return ErrTableFrozen
	}

	// Verify the authority
	if *lookupTable.Meta.Authority != authorityAcc.Pubkey {
		return fmt.Errorf("%w: signer does not match table authority", ErrInvalidAuthority)
	}

	// Remove the authority (freeze the table)
	lookupTable.Meta.Authority = nil

	// Serialize and save
	tableAcc.Data = lookupTable.Serialize()

	return nil
}

// handleExtendLookupTable handles the ExtendLookupTable instruction.
// Adds new addresses to an existing lookup table.
//
// Account layout:
//   [0] lookup table account (writable)
//   [1] authority (signer)
//   [2] payer (signer, writable) - pays for increased rent
//   [3] system program (optional)
func handleExtendLookupTable(ctx *syscall.ExecutionContext, inst *ExtendLookupTableInstruction) error {
	// Validate we have at least 3 accounts
	if ctx.AccountCount() < 3 {
		return fmt.Errorf("%w: ExtendLookupTable requires at least 3 accounts", ErrInvalidInstructionData)
	}

	// Validate we have addresses to add
	if len(inst.NewAddresses) == 0 {
		return ErrNoAddressesToExtend
	}

	// Get the lookup table account
	tableAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !tableAcc.IsWritable {
		return fmt.Errorf("%w: lookup table account", ErrAccountNotWritable)
	}

	// Verify ownership
	if tableAcc.Owner != types.AddressLookupTableProgramID {
		return fmt.Errorf("%w: account not owned by Address Lookup Table Program", ErrInvalidAccountOwner)
	}

	// Get the authority account
	authorityAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: authority account", ErrAccountNotSigner)
	}

	// Get the payer account
	payerAcc, err := ctx.GetAccountByIndex(2)
	if err != nil {
		return err
	}
	if !payerAcc.IsSigner {
		return fmt.Errorf("%w: payer account", ErrAccountNotSigner)
	}
	if !payerAcc.IsWritable {
		return fmt.Errorf("%w: payer account", ErrAccountNotWritable)
	}

	// Deserialize the lookup table
	lookupTable, err := DeserializeAddressLookupTable(tableAcc.Data)
	if err != nil {
		return err
	}

	// Check if frozen
	if lookupTable.Meta.IsFrozen() {
		return ErrTableFrozen
	}

	// Check if deactivated
	if !lookupTable.Meta.IsActive() {
		return ErrTableAlreadyDeactivated
	}

	// Verify the authority
	if *lookupTable.Meta.Authority != authorityAcc.Pubkey {
		return fmt.Errorf("%w: signer does not match table authority", ErrInvalidAuthority)
	}

	// Check if we can add the new addresses
	if !lookupTable.CanAddAddresses(len(inst.NewAddresses)) {
		return fmt.Errorf("%w: cannot add %d addresses, table has %d, max is %d",
			ErrMaxAddressesExceeded, len(inst.NewAddresses), len(lookupTable.Addresses), MaxAddresses)
	}

	// Track the start index for addresses added in this slot
	currentSlot := ctx.Slot
	if lookupTable.Meta.LastExtendedSlot < currentSlot {
		// New slot, reset the start index
		lookupTable.Meta.LastExtendedSlot = currentSlot
		lookupTable.Meta.LastExtendedSlotStartIndex = uint8(len(lookupTable.Addresses))
	}

	// Add the new addresses
	lookupTable.Addresses = append(lookupTable.Addresses, inst.NewAddresses...)

	// Calculate new size and rent
	oldSize := len(tableAcc.Data)
	newData := lookupTable.Serialize()
	newSize := len(newData)

	// Calculate additional rent needed
	oldRent := types.RentExemptMinimum(uint64(oldSize))
	newRent := types.RentExemptMinimum(uint64(newSize))
	additionalRent := uint64(0)
	if newRent > oldRent {
		additionalRent = uint64(newRent - oldRent)
	}

	// Transfer additional lamports if needed
	if additionalRent > 0 {
		if *payerAcc.Lamports < additionalRent {
			return fmt.Errorf("%w: need %d additional lamports for rent, have %d",
				ErrInsufficientFunds, additionalRent, *payerAcc.Lamports)
		}
		*payerAcc.Lamports -= additionalRent
		*tableAcc.Lamports += additionalRent
	}

	// Save the updated data
	tableAcc.Data = newData

	return nil
}

// handleDeactivateLookupTable handles the DeactivateLookupTable instruction.
// Begins the deactivation process for a lookup table.
//
// Account layout:
//   [0] lookup table account (writable)
//   [1] authority (signer)
func handleDeactivateLookupTable(ctx *syscall.ExecutionContext, _ *DeactivateLookupTableInstruction) error {
	// Validate we have at least 2 accounts
	if ctx.AccountCount() < 2 {
		return fmt.Errorf("%w: DeactivateLookupTable requires 2 accounts", ErrInvalidInstructionData)
	}

	// Get the lookup table account
	tableAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !tableAcc.IsWritable {
		return fmt.Errorf("%w: lookup table account", ErrAccountNotWritable)
	}

	// Verify ownership
	if tableAcc.Owner != types.AddressLookupTableProgramID {
		return fmt.Errorf("%w: account not owned by Address Lookup Table Program", ErrInvalidAccountOwner)
	}

	// Get the authority account
	authorityAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: authority account", ErrAccountNotSigner)
	}

	// Deserialize the lookup table
	lookupTable, err := DeserializeAddressLookupTable(tableAcc.Data)
	if err != nil {
		return err
	}

	// Check if frozen
	if lookupTable.Meta.IsFrozen() {
		return ErrTableFrozen
	}

	// Check if already deactivated
	if !lookupTable.Meta.IsActive() {
		return ErrTableAlreadyDeactivated
	}

	// Verify the authority
	if *lookupTable.Meta.Authority != authorityAcc.Pubkey {
		return fmt.Errorf("%w: signer does not match table authority", ErrInvalidAuthority)
	}

	// Set the deactivation slot to current slot
	lookupTable.Meta.DeactivationSlot = ctx.Slot

	// Serialize and save
	tableAcc.Data = lookupTable.Serialize()

	return nil
}

// handleCloseLookupTable handles the CloseLookupTable instruction.
// Closes a deactivated lookup table and reclaims lamports.
//
// Account layout:
//   [0] lookup table account (writable)
//   [1] authority (signer)
//   [2] recipient (writable) - receives the lamports
func handleCloseLookupTable(ctx *syscall.ExecutionContext, _ *CloseLookupTableInstruction) error {
	// Validate we have at least 3 accounts
	if ctx.AccountCount() < 3 {
		return fmt.Errorf("%w: CloseLookupTable requires 3 accounts", ErrInvalidInstructionData)
	}

	// Get the lookup table account
	tableAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !tableAcc.IsWritable {
		return fmt.Errorf("%w: lookup table account", ErrAccountNotWritable)
	}

	// Verify ownership
	if tableAcc.Owner != types.AddressLookupTableProgramID {
		return fmt.Errorf("%w: account not owned by Address Lookup Table Program", ErrInvalidAccountOwner)
	}

	// Get the authority account
	authorityAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: authority account", ErrAccountNotSigner)
	}

	// Get the recipient account
	recipientAcc, err := ctx.GetAccountByIndex(2)
	if err != nil {
		return err
	}
	if !recipientAcc.IsWritable {
		return fmt.Errorf("%w: recipient account", ErrAccountNotWritable)
	}

	// Deserialize the lookup table
	lookupTable, err := DeserializeAddressLookupTable(tableAcc.Data)
	if err != nil {
		return err
	}

	// Check if the table is still active
	if lookupTable.Meta.IsActive() {
		return ErrTableStillActive
	}

	// Verify the authority (if table is not frozen)
	if !lookupTable.Meta.IsFrozen() {
		if *lookupTable.Meta.Authority != authorityAcc.Pubkey {
			return fmt.Errorf("%w: signer does not match table authority", ErrInvalidAuthority)
		}
	}

	// Check cooldown period
	// The table must have been deactivated for at least DeactivationCooldownSlots
	slotsSinceDeactivation := ctx.Slot - lookupTable.Meta.DeactivationSlot
	if slotsSinceDeactivation < DeactivationCooldownSlots {
		return fmt.Errorf("%w: %d slots remaining",
			ErrDeactivationCooldownNotExpired,
			DeactivationCooldownSlots-slotsSinceDeactivation)
	}

	// Transfer all lamports to recipient
	lamportsToTransfer := *tableAcc.Lamports
	*tableAcc.Lamports = 0
	*recipientAcc.Lamports += lamportsToTransfer

	// Clear the account data
	tableAcc.Data = nil

	// Reset owner to system program (account is now closed)
	tableAcc.Owner = types.SystemProgramID

	return nil
}
