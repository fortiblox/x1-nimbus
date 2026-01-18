package compute_budget

import (
	"encoding/binary"
	"fmt"
)

// Compute Budget Program instruction types (first byte of instruction data)
const (
	// InstructionRequestHeapFrame requests a specific heap frame size.
	// Deprecated but still supported for backwards compatibility.
	InstructionRequestHeapFrame uint8 = 1

	// InstructionSetComputeUnitLimit sets the compute unit limit for the transaction.
	InstructionSetComputeUnitLimit uint8 = 2

	// InstructionSetComputeUnitPrice sets the priority fee in micro-lamports per compute unit.
	InstructionSetComputeUnitPrice uint8 = 3

	// InstructionSetLoadedAccountsDataSizeLimit sets the maximum loaded account data size.
	InstructionSetLoadedAccountsDataSizeLimit uint8 = 4
)

// Constants for compute budget limits
const (
	// MaxComputeUnits is the maximum compute units allowed per transaction.
	MaxComputeUnits uint32 = 1_400_000

	// DefaultComputeUnits is the default compute units per instruction.
	DefaultComputeUnits uint32 = 200_000

	// MaxHeapFrameSize is the maximum heap frame size (256KB).
	MaxHeapFrameSize uint32 = 256 * 1024

	// DefaultHeapFrameSize is the default heap frame size (32KB).
	DefaultHeapFrameSize uint32 = 32 * 1024

	// HeapFrameAlignment is the required alignment for heap frame sizes.
	HeapFrameAlignment uint32 = 1024

	// DefaultLoadedAccountsDataSizeLimit is the default limit for loaded account data.
	DefaultLoadedAccountsDataSizeLimit uint32 = 64 * 1024 * 1024 // 64MB
)

// RequestHeapFrameInstruction represents a request for a specific heap frame size.
type RequestHeapFrameInstruction struct {
	// HeapFrameSize is the requested heap frame size in bytes.
	// Must be a multiple of 1024 and at most 256KB.
	HeapFrameSize uint32
}

// Decode decodes a RequestHeapFrame instruction from bytes.
func (inst *RequestHeapFrameInstruction) Decode(data []byte) error {
	// Data layout: heap_frame_size (4 bytes)
	if len(data) < 4 {
		return fmt.Errorf("%w: RequestHeapFrame requires 4 bytes, got %d", ErrInvalidInstructionData, len(data))
	}
	inst.HeapFrameSize = binary.LittleEndian.Uint32(data[0:4])
	return nil
}

// Encode encodes a RequestHeapFrame instruction to bytes.
func (inst *RequestHeapFrameInstruction) Encode() []byte {
	data := make([]byte, 5) // instruction type (1 byte) + heap_frame_size (4 bytes)
	data[0] = InstructionRequestHeapFrame
	binary.LittleEndian.PutUint32(data[1:5], inst.HeapFrameSize)
	return data
}

// SetComputeUnitLimitInstruction represents a request to set the compute unit limit.
type SetComputeUnitLimitInstruction struct {
	// ComputeUnitLimit is the maximum compute units for the transaction.
	// Maximum value is 1,400,000.
	ComputeUnitLimit uint32
}

// Decode decodes a SetComputeUnitLimit instruction from bytes.
func (inst *SetComputeUnitLimitInstruction) Decode(data []byte) error {
	// Data layout: compute_unit_limit (4 bytes)
	if len(data) < 4 {
		return fmt.Errorf("%w: SetComputeUnitLimit requires 4 bytes, got %d", ErrInvalidInstructionData, len(data))
	}
	inst.ComputeUnitLimit = binary.LittleEndian.Uint32(data[0:4])
	return nil
}

// Encode encodes a SetComputeUnitLimit instruction to bytes.
func (inst *SetComputeUnitLimitInstruction) Encode() []byte {
	data := make([]byte, 5) // instruction type (1 byte) + compute_unit_limit (4 bytes)
	data[0] = InstructionSetComputeUnitLimit
	binary.LittleEndian.PutUint32(data[1:5], inst.ComputeUnitLimit)
	return data
}

// SetComputeUnitPriceInstruction represents a request to set the priority fee.
type SetComputeUnitPriceInstruction struct {
	// MicroLamportsPerComputeUnit is the priority fee in micro-lamports per compute unit.
	// This determines transaction priority in the scheduler.
	MicroLamportsPerComputeUnit uint64
}

// Decode decodes a SetComputeUnitPrice instruction from bytes.
func (inst *SetComputeUnitPriceInstruction) Decode(data []byte) error {
	// Data layout: micro_lamports_per_compute_unit (8 bytes)
	if len(data) < 8 {
		return fmt.Errorf("%w: SetComputeUnitPrice requires 8 bytes, got %d", ErrInvalidInstructionData, len(data))
	}
	inst.MicroLamportsPerComputeUnit = binary.LittleEndian.Uint64(data[0:8])
	return nil
}

// Encode encodes a SetComputeUnitPrice instruction to bytes.
func (inst *SetComputeUnitPriceInstruction) Encode() []byte {
	data := make([]byte, 9) // instruction type (1 byte) + micro_lamports_per_compute_unit (8 bytes)
	data[0] = InstructionSetComputeUnitPrice
	binary.LittleEndian.PutUint64(data[1:9], inst.MicroLamportsPerComputeUnit)
	return data
}

// SetLoadedAccountsDataSizeLimitInstruction represents a request to limit loaded account data.
type SetLoadedAccountsDataSizeLimitInstruction struct {
	// DataSizeLimit is the maximum bytes of account data that can be loaded.
	DataSizeLimit uint32
}

// Decode decodes a SetLoadedAccountsDataSizeLimit instruction from bytes.
func (inst *SetLoadedAccountsDataSizeLimitInstruction) Decode(data []byte) error {
	// Data layout: data_size_limit (4 bytes)
	if len(data) < 4 {
		return fmt.Errorf("%w: SetLoadedAccountsDataSizeLimit requires 4 bytes, got %d", ErrInvalidInstructionData, len(data))
	}
	inst.DataSizeLimit = binary.LittleEndian.Uint32(data[0:4])
	return nil
}

// Encode encodes a SetLoadedAccountsDataSizeLimit instruction to bytes.
func (inst *SetLoadedAccountsDataSizeLimitInstruction) Encode() []byte {
	data := make([]byte, 5) // instruction type (1 byte) + data_size_limit (4 bytes)
	data[0] = InstructionSetLoadedAccountsDataSizeLimit
	binary.LittleEndian.PutUint32(data[1:5], inst.DataSizeLimit)
	return data
}

// ParseInstructionType extracts the instruction type from instruction data.
func ParseInstructionType(data []byte) (uint8, error) {
	if len(data) < 1 {
		return 0, fmt.Errorf("%w: instruction data too short", ErrInvalidInstructionData)
	}
	return data[0], nil
}
