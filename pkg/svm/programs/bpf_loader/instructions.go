package bpf_loader

import (
	"encoding/binary"
	"fmt"
)

// BPF Loader Upgradeable instruction discriminators (first 4 bytes of instruction data)
const (
	InstructionInitializeBuffer    uint32 = 0
	InstructionWrite               uint32 = 1
	InstructionDeployWithMaxDataLen uint32 = 2
	InstructionUpgrade             uint32 = 3
	InstructionSetAuthority        uint32 = 4
	InstructionClose               uint32 = 5
	InstructionExtendProgram       uint32 = 6
	InstructionSetAuthorityChecked uint32 = 7
)

// InitializeBufferInstruction represents an InitializeBuffer instruction.
// Initializes a buffer account for program deployment.
// No additional data required.
type InitializeBufferInstruction struct {
	// No data fields
}

// Decode decodes an InitializeBuffer instruction from bytes.
func (inst *InitializeBufferInstruction) Decode(data []byte) error {
	// No additional data to decode
	return nil
}

// Encode encodes an InitializeBuffer instruction to bytes.
func (inst *InitializeBufferInstruction) Encode() []byte {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data[0:4], InstructionInitializeBuffer)
	return data
}

// WriteInstruction represents a Write instruction.
// Writes bytes to a buffer at a specified offset.
type WriteInstruction struct {
	Offset uint32 // Offset in the buffer to write at
	Bytes  []byte // Bytes to write
}

// Decode decodes a Write instruction from bytes.
func (inst *WriteInstruction) Decode(data []byte) error {
	// Data layout: offset (4 bytes) + bytes_len (4 bytes as part of serialized vec) + bytes (variable)
	if len(data) < 4 {
		return fmt.Errorf("%w: Write requires at least 4 bytes", ErrInvalidInstructionData)
	}
	inst.Offset = binary.LittleEndian.Uint32(data[0:4])

	// The rest is the bytes to write
	if len(data) > 4 {
		inst.Bytes = make([]byte, len(data)-4)
		copy(inst.Bytes, data[4:])
	}
	return nil
}

// Encode encodes a Write instruction to bytes.
func (inst *WriteInstruction) Encode() []byte {
	data := make([]byte, 4+4+len(inst.Bytes))
	binary.LittleEndian.PutUint32(data[0:4], InstructionWrite)
	binary.LittleEndian.PutUint32(data[4:8], inst.Offset)
	copy(data[8:], inst.Bytes)
	return data
}

// DeployWithMaxDataLenInstruction represents a DeployWithMaxDataLen instruction.
// Deploys a program from a buffer with a maximum data length.
type DeployWithMaxDataLenInstruction struct {
	MaxDataLen uint64 // Maximum data length for the program
}

// Decode decodes a DeployWithMaxDataLen instruction from bytes.
func (inst *DeployWithMaxDataLenInstruction) Decode(data []byte) error {
	// Data layout: max_data_len (8 bytes, usize which is u64 on 64-bit)
	if len(data) < 8 {
		return fmt.Errorf("%w: DeployWithMaxDataLen requires 8 bytes, got %d", ErrInvalidInstructionData, len(data))
	}
	inst.MaxDataLen = binary.LittleEndian.Uint64(data[0:8])
	return nil
}

// Encode encodes a DeployWithMaxDataLen instruction to bytes.
func (inst *DeployWithMaxDataLenInstruction) Encode() []byte {
	data := make([]byte, 4+8)
	binary.LittleEndian.PutUint32(data[0:4], InstructionDeployWithMaxDataLen)
	binary.LittleEndian.PutUint64(data[4:12], inst.MaxDataLen)
	return data
}

// UpgradeInstruction represents an Upgrade instruction.
// Upgrades an existing program with new bytecode from a buffer.
// No additional data required.
type UpgradeInstruction struct {
	// No data fields
}

// Decode decodes an Upgrade instruction from bytes.
func (inst *UpgradeInstruction) Decode(data []byte) error {
	// No additional data to decode
	return nil
}

// Encode encodes an Upgrade instruction to bytes.
func (inst *UpgradeInstruction) Encode() []byte {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data[0:4], InstructionUpgrade)
	return data
}

// SetAuthorityInstruction represents a SetAuthority instruction.
// Changes the upgrade authority of a program or buffer.
// New authority is passed via accounts.
// No additional data required.
type SetAuthorityInstruction struct {
	// No data fields
}

// Decode decodes a SetAuthority instruction from bytes.
func (inst *SetAuthorityInstruction) Decode(data []byte) error {
	// No additional data to decode
	return nil
}

// Encode encodes a SetAuthority instruction to bytes.
func (inst *SetAuthorityInstruction) Encode() []byte {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data[0:4], InstructionSetAuthority)
	return data
}

// CloseInstruction represents a Close instruction.
// Closes a buffer or program account and transfers lamports.
// No additional data required.
type CloseInstruction struct {
	// No data fields
}

// Decode decodes a Close instruction from bytes.
func (inst *CloseInstruction) Decode(data []byte) error {
	// No additional data to decode
	return nil
}

// Encode encodes a Close instruction to bytes.
func (inst *CloseInstruction) Encode() []byte {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data[0:4], InstructionClose)
	return data
}

// ExtendProgramInstruction represents an ExtendProgram instruction.
// Extends the program data account size.
type ExtendProgramInstruction struct {
	AdditionalBytes uint32 // Number of additional bytes to allocate
}

// Decode decodes an ExtendProgram instruction from bytes.
func (inst *ExtendProgramInstruction) Decode(data []byte) error {
	// Data layout: additional_bytes (4 bytes)
	if len(data) < 4 {
		return fmt.Errorf("%w: ExtendProgram requires 4 bytes, got %d", ErrInvalidInstructionData, len(data))
	}
	inst.AdditionalBytes = binary.LittleEndian.Uint32(data[0:4])
	return nil
}

// Encode encodes an ExtendProgram instruction to bytes.
func (inst *ExtendProgramInstruction) Encode() []byte {
	data := make([]byte, 4+4)
	binary.LittleEndian.PutUint32(data[0:4], InstructionExtendProgram)
	binary.LittleEndian.PutUint32(data[4:8], inst.AdditionalBytes)
	return data
}

// SetAuthorityCheckedInstruction represents a SetAuthorityChecked instruction.
// Changes the upgrade authority with verification that the new authority signs.
// New authority must sign the transaction.
// No additional data required.
type SetAuthorityCheckedInstruction struct {
	// No data fields
}

// Decode decodes a SetAuthorityChecked instruction from bytes.
func (inst *SetAuthorityCheckedInstruction) Decode(data []byte) error {
	// No additional data to decode
	return nil
}

// Encode encodes a SetAuthorityChecked instruction to bytes.
func (inst *SetAuthorityCheckedInstruction) Encode() []byte {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data[0:4], InstructionSetAuthorityChecked)
	return data
}

// ParseInstructionDiscriminator extracts the instruction discriminator from instruction data.
func ParseInstructionDiscriminator(data []byte) (uint32, error) {
	if len(data) < 4 {
		return 0, fmt.Errorf("%w: instruction data too short", ErrInvalidInstructionData)
	}
	return binary.LittleEndian.Uint32(data[0:4]), nil
}
