package address_lookup_table

import (
	"encoding/binary"
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// Instruction discriminators (first 4 bytes of instruction data)
const (
	InstructionCreateLookupTable     uint32 = 0
	InstructionFreezeLookupTable     uint32 = 1
	InstructionExtendLookupTable     uint32 = 2
	InstructionDeactivateLookupTable uint32 = 3
	InstructionCloseLookupTable      uint32 = 4
)

// CreateLookupTableInstruction represents a CreateLookupTable instruction.
// Creates a new address lookup table at a derived address.
//
// Account layout:
//   [0] lookup table account (writable) - PDA to create
//   [1] authority (signer, writable) - payer and authority
//   [2] payer (signer, writable) - account paying for creation
//   [3] system program
type CreateLookupTableInstruction struct {
	// RecentSlot is a recent slot used to derive the lookup table address.
	RecentSlot uint64

	// BumpSeed is the PDA bump seed.
	BumpSeed uint8
}

// Decode decodes a CreateLookupTable instruction from bytes.
func (inst *CreateLookupTableInstruction) Decode(data []byte) error {
	// Data layout: recent_slot (8 bytes) + bump_seed (1 byte) = 9 bytes
	if len(data) < 9 {
		return fmt.Errorf("%w: CreateLookupTable requires 9 bytes, got %d",
			ErrInvalidInstructionData, len(data))
	}
	inst.RecentSlot = binary.LittleEndian.Uint64(data[0:8])
	inst.BumpSeed = data[8]
	return nil
}

// Encode encodes a CreateLookupTable instruction to bytes.
func (inst *CreateLookupTableInstruction) Encode() []byte {
	data := make([]byte, 4+9) // discriminator + instruction data
	binary.LittleEndian.PutUint32(data[0:4], InstructionCreateLookupTable)
	binary.LittleEndian.PutUint64(data[4:12], inst.RecentSlot)
	data[12] = inst.BumpSeed
	return data
}

// FreezeLookupTableInstruction represents a FreezeLookupTable instruction.
// Freezes a lookup table by removing the authority (makes it immutable).
//
// Account layout:
//   [0] lookup table account (writable)
//   [1] authority (signer)
type FreezeLookupTableInstruction struct {
	// No additional data required
}

// Decode decodes a FreezeLookupTable instruction from bytes.
func (inst *FreezeLookupTableInstruction) Decode(data []byte) error {
	// No additional data to decode
	return nil
}

// Encode encodes a FreezeLookupTable instruction to bytes.
func (inst *FreezeLookupTableInstruction) Encode() []byte {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data[0:4], InstructionFreezeLookupTable)
	return data
}

// ExtendLookupTableInstruction represents an ExtendLookupTable instruction.
// Adds new addresses to an existing lookup table.
//
// Account layout:
//   [0] lookup table account (writable)
//   [1] authority (signer)
//   [2] payer (signer, writable) - pays for increased rent
//   [3] system program (optional, if reallocation needed)
type ExtendLookupTableInstruction struct {
	// NewAddresses is the list of addresses to add.
	NewAddresses []types.Pubkey
}

// Decode decodes an ExtendLookupTable instruction from bytes.
func (inst *ExtendLookupTableInstruction) Decode(data []byte) error {
	// Data layout: num_addresses (8 bytes) + addresses (32 * n bytes)
	if len(data) < 8 {
		return fmt.Errorf("%w: ExtendLookupTable too short", ErrInvalidInstructionData)
	}

	numAddresses := binary.LittleEndian.Uint64(data[0:8])
	expectedLen := 8 + int(numAddresses)*32
	if len(data) < expectedLen {
		return fmt.Errorf("%w: ExtendLookupTable requires %d bytes, got %d",
			ErrInvalidInstructionData, expectedLen, len(data))
	}

	inst.NewAddresses = make([]types.Pubkey, numAddresses)
	offset := 8
	for i := uint64(0); i < numAddresses; i++ {
		copy(inst.NewAddresses[i][:], data[offset:offset+32])
		offset += 32
	}

	return nil
}

// Encode encodes an ExtendLookupTable instruction to bytes.
func (inst *ExtendLookupTableInstruction) Encode() []byte {
	numAddresses := len(inst.NewAddresses)
	data := make([]byte, 4+8+numAddresses*32)
	binary.LittleEndian.PutUint32(data[0:4], InstructionExtendLookupTable)
	binary.LittleEndian.PutUint64(data[4:12], uint64(numAddresses))

	offset := 12
	for _, addr := range inst.NewAddresses {
		copy(data[offset:offset+32], addr[:])
		offset += 32
	}

	return data
}

// DeactivateLookupTableInstruction represents a DeactivateLookupTable instruction.
// Begins the deactivation process for a lookup table.
//
// Account layout:
//   [0] lookup table account (writable)
//   [1] authority (signer)
type DeactivateLookupTableInstruction struct {
	// No additional data required
}

// Decode decodes a DeactivateLookupTable instruction from bytes.
func (inst *DeactivateLookupTableInstruction) Decode(data []byte) error {
	// No additional data to decode
	return nil
}

// Encode encodes a DeactivateLookupTable instruction to bytes.
func (inst *DeactivateLookupTableInstruction) Encode() []byte {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data[0:4], InstructionDeactivateLookupTable)
	return data
}

// CloseLookupTableInstruction represents a CloseLookupTable instruction.
// Closes a deactivated lookup table and reclaims lamports.
//
// Account layout:
//   [0] lookup table account (writable)
//   [1] authority (signer)
//   [2] recipient (writable) - receives the lamports
type CloseLookupTableInstruction struct {
	// No additional data required
}

// Decode decodes a CloseLookupTable instruction from bytes.
func (inst *CloseLookupTableInstruction) Decode(data []byte) error {
	// No additional data to decode
	return nil
}

// Encode encodes a CloseLookupTable instruction to bytes.
func (inst *CloseLookupTableInstruction) Encode() []byte {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data[0:4], InstructionCloseLookupTable)
	return data
}

// ParseInstructionDiscriminator extracts the instruction discriminator from instruction data.
func ParseInstructionDiscriminator(data []byte) (uint32, error) {
	if len(data) < 4 {
		return 0, fmt.Errorf("%w: instruction data too short", ErrInvalidInstructionData)
	}
	return binary.LittleEndian.Uint32(data[0:4]), nil
}
