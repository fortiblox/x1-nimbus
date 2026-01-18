package bpf_loader

import (
	"encoding/binary"
	"fmt"
)

// ELF constants for sBPF programs
const (
	// ELF magic number
	ELFMagic0 = 0x7F
	ELFMagic1 = 'E'
	ELFMagic2 = 'L'
	ELFMagic3 = 'F'

	// ELF class
	ELFClass64 = 2 // 64-bit

	// ELF data encoding
	ELFDataLittleEndian = 1

	// ELF version
	ELFVersionCurrent = 1

	// ELF OS/ABI
	ELFOSABINone = 0

	// ELF type
	ELFTypeDyn = 3 // Shared object file (used for BPF)
	ELFTypeExec = 2 // Executable file

	// ELF machine type for BPF
	ELFMachineBPF = 247 // EM_BPF

	// Minimum ELF header size for 64-bit
	ELFHeaderSize64 = 64

	// Minimum size for a valid sBPF program
	MinProgramSize = ELFHeaderSize64
)

// ELFHeader64 represents the 64-bit ELF header structure.
type ELFHeader64 struct {
	Magic      [4]byte  // ELF magic number
	Class      uint8    // 64-bit = 2
	Data       uint8    // Little endian = 1
	Version    uint8    // ELF version
	OSABI      uint8    // OS/ABI identification
	ABIVersion uint8    // ABI version
	Padding    [7]byte  // Padding
	Type       uint16   // Object file type
	Machine    uint16   // Machine type
	Version2   uint32   // Object file version
	Entry      uint64   // Entry point address
	PhOff      uint64   // Program header offset
	ShOff      uint64   // Section header offset
	Flags      uint32   // Processor-specific flags
	EhSize     uint16   // ELF header size
	PhEntSize  uint16   // Size of program header entry
	PhNum      uint16   // Number of program header entries
	ShEntSize  uint16   // Size of section header entry
	ShNum      uint16   // Number of section header entries
	ShStrNdx   uint16   // Section name string table index
}

// ValidateELF performs basic validation of an sBPF ELF binary.
func ValidateELF(data []byte) error {
	if len(data) < MinProgramSize {
		return fmt.Errorf("%w: program too small, need at least %d bytes, got %d",
			ErrInvalidELF, MinProgramSize, len(data))
	}

	// Check ELF magic number
	if data[0] != ELFMagic0 || data[1] != ELFMagic1 || data[2] != ELFMagic2 || data[3] != ELFMagic3 {
		return fmt.Errorf("%w: invalid ELF magic number", ErrInvalidELF)
	}

	// Check class (must be 64-bit)
	if data[4] != ELFClass64 {
		return fmt.Errorf("%w: expected 64-bit ELF, got class %d", ErrInvalidELF, data[4])
	}

	// Check data encoding (must be little-endian)
	if data[5] != ELFDataLittleEndian {
		return fmt.Errorf("%w: expected little-endian ELF", ErrInvalidELF)
	}

	// Check ELF version
	if data[6] != ELFVersionCurrent {
		return fmt.Errorf("%w: unsupported ELF version %d", ErrInvalidELF, data[6])
	}

	// Parse the rest of the header
	header, err := parseELFHeader64(data)
	if err != nil {
		return err
	}

	// Check machine type (should be BPF)
	if header.Machine != ELFMachineBPF {
		return fmt.Errorf("%w: expected BPF machine type (247), got %d", ErrInvalidELF, header.Machine)
	}

	// Check type (should be DYN or EXEC)
	if header.Type != ELFTypeDyn && header.Type != ELFTypeExec {
		return fmt.Errorf("%w: expected executable or shared object, got type %d", ErrInvalidELF, header.Type)
	}

	// Validate entry point is set
	if header.Entry == 0 {
		return fmt.Errorf("%w: entry point is zero", ErrInvalidELF)
	}

	// Validate program header offset if present
	if header.PhOff > 0 {
		if header.PhOff >= uint64(len(data)) {
			return fmt.Errorf("%w: program header offset %d exceeds data size %d",
				ErrInvalidELF, header.PhOff, len(data))
		}
		// Check program headers fit in data
		phEnd := header.PhOff + uint64(header.PhNum)*uint64(header.PhEntSize)
		if phEnd > uint64(len(data)) {
			return fmt.Errorf("%w: program headers extend beyond data",
				ErrInvalidELF)
		}
	}

	// Validate section header offset if present
	if header.ShOff > 0 {
		if header.ShOff >= uint64(len(data)) {
			return fmt.Errorf("%w: section header offset %d exceeds data size %d",
				ErrInvalidELF, header.ShOff, len(data))
		}
		// Check section headers fit in data
		shEnd := header.ShOff + uint64(header.ShNum)*uint64(header.ShEntSize)
		if shEnd > uint64(len(data)) {
			return fmt.Errorf("%w: section headers extend beyond data",
				ErrInvalidELF)
		}
	}

	return nil
}

// parseELFHeader64 parses a 64-bit ELF header from data.
func parseELFHeader64(data []byte) (*ELFHeader64, error) {
	if len(data) < ELFHeaderSize64 {
		return nil, fmt.Errorf("%w: data too short for ELF header", ErrInvalidELF)
	}

	header := &ELFHeader64{}

	// Copy magic
	copy(header.Magic[:], data[0:4])

	header.Class = data[4]
	header.Data = data[5]
	header.Version = data[6]
	header.OSABI = data[7]
	header.ABIVersion = data[8]
	// Padding at bytes 9-15

	// Parse the rest (little-endian)
	header.Type = binary.LittleEndian.Uint16(data[16:18])
	header.Machine = binary.LittleEndian.Uint16(data[18:20])
	header.Version2 = binary.LittleEndian.Uint32(data[20:24])
	header.Entry = binary.LittleEndian.Uint64(data[24:32])
	header.PhOff = binary.LittleEndian.Uint64(data[32:40])
	header.ShOff = binary.LittleEndian.Uint64(data[40:48])
	header.Flags = binary.LittleEndian.Uint32(data[48:52])
	header.EhSize = binary.LittleEndian.Uint16(data[52:54])
	header.PhEntSize = binary.LittleEndian.Uint16(data[54:56])
	header.PhNum = binary.LittleEndian.Uint16(data[56:58])
	header.ShEntSize = binary.LittleEndian.Uint16(data[58:60])
	header.ShNum = binary.LittleEndian.Uint16(data[60:62])
	header.ShStrNdx = binary.LittleEndian.Uint16(data[62:64])

	return header, nil
}

// GetELFEntryPoint returns the entry point of an ELF binary.
func GetELFEntryPoint(data []byte) (uint64, error) {
	header, err := parseELFHeader64(data)
	if err != nil {
		return 0, err
	}
	return header.Entry, nil
}

// IsValidSBPFProgram checks if the data is a valid sBPF program.
func IsValidSBPFProgram(data []byte) bool {
	return ValidateELF(data) == nil
}
