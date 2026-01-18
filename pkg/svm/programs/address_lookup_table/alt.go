// Package address_lookup_table implements the Address Lookup Table Program for X1-Nimbus.
//
// The Address Lookup Table Program allows users to create lookup tables that store
// lists of addresses. These tables can be used with versioned transactions (v0)
// to compress transaction size by replacing 32-byte addresses with 1-byte indices.
//
// Key features:
//   - Create lookup tables with up to 256 addresses
//   - Extend tables by adding more addresses
//   - Freeze tables to make them immutable
//   - Deactivate and close tables to reclaim lamports
//
// The program supports the following instructions:
//   - CreateLookupTable: Create a new lookup table at a derived address
//   - FreezeLookupTable: Remove authority to make the table immutable
//   - ExtendLookupTable: Add new addresses to the table
//   - DeactivateLookupTable: Begin the deactivation process
//   - CloseLookupTable: Close a deactivated table and reclaim lamports
package address_lookup_table

import (
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/svm/syscall"
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// AddressLookupTableProgram implements the Address Lookup Table Program.
type AddressLookupTableProgram struct {
	// ProgramID is the Address Lookup Table Program's public key
	ProgramID types.Pubkey
}

// New creates a new AddressLookupTableProgram instance.
func New() *AddressLookupTableProgram {
	return &AddressLookupTableProgram{
		ProgramID: types.AddressLookupTableProgramID,
	}
}

// Execute executes an Address Lookup Table Program instruction.
// The instruction format is:
//   - First 4 bytes: instruction discriminator (little-endian uint32)
//   - Remaining bytes: instruction-specific data
func (p *AddressLookupTableProgram) Execute(ctx *syscall.ExecutionContext, instruction []byte) error {
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
	case InstructionCreateLookupTable:
		var inst CreateLookupTableInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleCreateLookupTable(ctx, &inst)

	case InstructionFreezeLookupTable:
		var inst FreezeLookupTableInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleFreezeLookupTable(ctx, &inst)

	case InstructionExtendLookupTable:
		var inst ExtendLookupTableInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleExtendLookupTable(ctx, &inst)

	case InstructionDeactivateLookupTable:
		var inst DeactivateLookupTableInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleDeactivateLookupTable(ctx, &inst)

	case InstructionCloseLookupTable:
		var inst CloseLookupTableInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleCloseLookupTable(ctx, &inst)

	default:
		return fmt.Errorf("%w: unknown instruction %d", ErrInvalidInstructionData, discriminator)
	}
}

// GetProgramID returns the Address Lookup Table Program's public key.
func (p *AddressLookupTableProgram) GetProgramID() types.Pubkey {
	return p.ProgramID
}

// IsAddressLookupTableProgram checks if a pubkey is the Address Lookup Table Program.
func IsAddressLookupTableProgram(pubkey types.Pubkey) bool {
	return pubkey == types.AddressLookupTableProgramID
}

// LookupAddress looks up an address in a lookup table account's data.
// This is a utility function for transaction processing.
func LookupAddress(tableData []byte, index uint8) (types.Pubkey, error) {
	table, err := DeserializeAddressLookupTable(tableData)
	if err != nil {
		return types.ZeroPubkey, err
	}
	return table.GetAddress(index)
}

// GetTableStatus returns the status of a lookup table.
// Returns: "active", "deactivated", or "frozen"
func GetTableStatus(tableData []byte) (string, error) {
	table, err := DeserializeAddressLookupTable(tableData)
	if err != nil {
		return "", err
	}

	if table.Meta.IsFrozen() {
		if table.Meta.IsActive() {
			return "frozen", nil
		}
		return "frozen-deactivated", nil
	}

	if table.Meta.IsActive() {
		return "active", nil
	}
	return "deactivated", nil
}

// GetTableAuthority returns the authority of a lookup table, if any.
func GetTableAuthority(tableData []byte) (*types.Pubkey, error) {
	table, err := DeserializeAddressLookupTable(tableData)
	if err != nil {
		return nil, err
	}
	return table.Meta.Authority, nil
}

// GetTableAddressCount returns the number of addresses in a lookup table.
func GetTableAddressCount(tableData []byte) (int, error) {
	table, err := DeserializeAddressLookupTable(tableData)
	if err != nil {
		return 0, err
	}
	return table.AddressCount(), nil
}
