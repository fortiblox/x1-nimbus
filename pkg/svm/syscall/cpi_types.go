package syscall

import (
	"encoding/binary"
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/svm/sbpf"
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// CPI limits
const (
	// MaxCPIDepth is the maximum CPI call depth (5 total including top-level).
	// Programs can call other programs up to 4 levels deep.
	MaxCPIDepth = 4

	// MaxCPIAccounts is the maximum number of accounts in a CPI instruction.
	MaxCPIAccounts = 64

	// MaxCPISeeds is the maximum number of signer seeds per CPI.
	MaxCPISeeds = 16

	// MaxCPISeedLen is the maximum length of a single seed.
	MaxCPISeedLen = 32

	// MaxCPISignerSeeds is the maximum number of PDA signers.
	MaxCPISignerSeeds = 16
)

// CPI compute unit costs
const (
	CUCPIBase           uint64 = 1000  // Base cost for CPI
	CUCPIPerAccount     uint64 = 100   // Per-account cost
	CUCPIPerDataByte    uint64 = 1     // Per-byte cost for instruction data
	CUCPIPerSeedByte    uint64 = 1     // Per-byte cost for signer seeds
)

// CPIAccountMeta represents metadata for an account in a CPI call.
// This mirrors the Solana AccountMeta structure.
type CPIAccountMeta struct {
	// Pubkey is the account's public key.
	Pubkey types.Pubkey

	// IsSigner indicates if the account must sign the transaction.
	IsSigner bool

	// IsWritable indicates if the account data may be modified.
	IsWritable bool
}

// Clone creates a deep copy of CPIAccountMeta.
func (m *CPIAccountMeta) Clone() CPIAccountMeta {
	return CPIAccountMeta{
		Pubkey:     m.Pubkey,
		IsSigner:   m.IsSigner,
		IsWritable: m.IsWritable,
	}
}

// CPIInstruction represents a Cross-Program Invocation instruction.
// This is the data structure passed to sol_invoke_signed.
type CPIInstruction struct {
	// ProgramID is the ID of the program to invoke.
	ProgramID types.Pubkey

	// Accounts is the list of accounts to pass to the invoked program.
	Accounts []CPIAccountMeta

	// Data is the instruction data to pass to the program.
	Data []byte
}

// Clone creates a deep copy of CPIInstruction.
func (i *CPIInstruction) Clone() *CPIInstruction {
	clone := &CPIInstruction{
		ProgramID: i.ProgramID,
		Accounts:  make([]CPIAccountMeta, len(i.Accounts)),
		Data:      make([]byte, len(i.Data)),
	}
	for j, acc := range i.Accounts {
		clone.Accounts[j] = acc.Clone()
	}
	copy(clone.Data, i.Data)
	return clone
}

// CPISignerSeeds represents the seeds for a PDA signer.
// Each signer can have multiple seeds concatenated to derive the PDA.
type CPISignerSeeds struct {
	// Seeds is the list of seed byte slices.
	Seeds [][]byte
}

// Clone creates a deep copy of CPISignerSeeds.
func (s *CPISignerSeeds) Clone() CPISignerSeeds {
	clone := CPISignerSeeds{
		Seeds: make([][]byte, len(s.Seeds)),
	}
	for i, seed := range s.Seeds {
		clone.Seeds[i] = make([]byte, len(seed))
		copy(clone.Seeds[i], seed)
	}
	return clone
}

// CPIResult contains the result of a CPI call.
type CPIResult struct {
	// Success indicates if the CPI succeeded.
	Success bool

	// ReturnData contains the return data from the called program.
	ReturnData []byte

	// ReturnDataProgramID is the program that set the return data.
	ReturnDataProgramID types.Pubkey

	// ComputeUnitsUsed is the number of compute units consumed by the CPI.
	ComputeUnitsUsed uint64
}

// C-style CPI instruction layout (sol_invoke_signed_c)
// This matches the Solana runtime's C ABI for CPI.
//
// SolInstruction (C):
//   program_id: *const Pubkey (8 bytes pointer)
//   accounts: *const SolAccountMeta (8 bytes pointer)
//   accounts_len: u64 (8 bytes)
//   data: *const u8 (8 bytes pointer)
//   data_len: u64 (8 bytes)
//
// SolAccountMeta (C):
//   pubkey: *const Pubkey (8 bytes pointer)
//   is_writable: bool (1 byte)
//   is_signer: bool (1 byte)
//   padding: [6]u8 (6 bytes for alignment)
const (
	// C instruction layout offsets
	CInstructionProgramIDOffset  = 0
	CInstructionAccountsOffset   = 8
	CInstructionAccountsLenOffset = 16
	CInstructionDataOffset       = 24
	CInstructionDataLenOffset    = 32
	CInstructionSize             = 40

	// C account meta layout
	CAccountMetaPubkeyOffset    = 0
	CAccountMetaIsWritableOffset = 8
	CAccountMetaIsSignerOffset  = 9
	CAccountMetaSize            = 16 // With padding for alignment
)

// Rust-style CPI instruction layout (sol_invoke_signed_rust)
// This matches the Solana SDK's Rust representation.
//
// Instruction (Rust):
//   program_id: Pubkey (32 bytes inline)
//   accounts: Vec<AccountMeta> (slice descriptor: ptr + len + cap = 24 bytes)
//   data: Vec<u8> (slice descriptor: ptr + len + cap = 24 bytes)
//
// AccountMeta (Rust):
//   pubkey: Pubkey (32 bytes inline)
//   is_signer: bool (1 byte)
//   is_writable: bool (1 byte)
//   padding: [6]u8 (6 bytes for alignment to 8 bytes)
const (
	// Rust instruction layout offsets
	RustInstructionProgramIDOffset = 0
	RustInstructionAccountsOffset  = 32
	RustInstructionDataOffset      = 56
	RustInstructionSize            = 80

	// Rust account meta layout (inline pubkey)
	RustAccountMetaPubkeyOffset    = 0
	RustAccountMetaIsSignerOffset  = 32
	RustAccountMetaIsWritableOffset = 33
	RustAccountMetaSize            = 40 // 32 + 1 + 1 + 6 padding
)

// ReadCPIInstructionC reads a C-style CPI instruction from VM memory.
// This is used by sol_invoke_signed_c.
func ReadCPIInstructionC(vm *sbpf.VM, instructionAddr uint64) (*CPIInstruction, error) {
	mem := vm.Memory()

	// Read program ID pointer
	programIDPtr, err := mem.ReadUint64(instructionAddr + CInstructionProgramIDOffset)
	if err != nil {
		return nil, fmt.Errorf("failed to read program ID pointer: %w", err)
	}

	// Read program ID
	programIDBytes, err := vm.ReadMemory(programIDPtr, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to read program ID: %w", err)
	}
	programID, err := types.PubkeyFromBytes(programIDBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid program ID: %w", err)
	}

	// Read accounts pointer and length
	accountsPtr, err := mem.ReadUint64(instructionAddr + CInstructionAccountsOffset)
	if err != nil {
		return nil, fmt.Errorf("failed to read accounts pointer: %w", err)
	}
	accountsLen, err := mem.ReadUint64(instructionAddr + CInstructionAccountsLenOffset)
	if err != nil {
		return nil, fmt.Errorf("failed to read accounts length: %w", err)
	}

	if accountsLen > MaxCPIAccounts {
		return nil, fmt.Errorf("too many CPI accounts: %d > %d", accountsLen, MaxCPIAccounts)
	}

	// Read account metas
	accounts := make([]CPIAccountMeta, accountsLen)
	for i := uint64(0); i < accountsLen; i++ {
		metaAddr := accountsPtr + i*CAccountMetaSize

		// Read pubkey pointer
		pubkeyPtr, err := mem.ReadUint64(metaAddr + CAccountMetaPubkeyOffset)
		if err != nil {
			return nil, fmt.Errorf("failed to read account %d pubkey pointer: %w", i, err)
		}

		// Read pubkey
		pubkeyBytes, err := vm.ReadMemory(pubkeyPtr, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to read account %d pubkey: %w", i, err)
		}
		pubkey, err := types.PubkeyFromBytes(pubkeyBytes)
		if err != nil {
			return nil, fmt.Errorf("invalid account %d pubkey: %w", i, err)
		}

		// Read is_writable and is_signer
		isWritable, err := mem.ReadByte(metaAddr + CAccountMetaIsWritableOffset)
		if err != nil {
			return nil, fmt.Errorf("failed to read account %d is_writable: %w", i, err)
		}
		isSigner, err := mem.ReadByte(metaAddr + CAccountMetaIsSignerOffset)
		if err != nil {
			return nil, fmt.Errorf("failed to read account %d is_signer: %w", i, err)
		}

		accounts[i] = CPIAccountMeta{
			Pubkey:     pubkey,
			IsSigner:   isSigner != 0,
			IsWritable: isWritable != 0,
		}
	}

	// Read instruction data pointer and length
	dataPtr, err := mem.ReadUint64(instructionAddr + CInstructionDataOffset)
	if err != nil {
		return nil, fmt.Errorf("failed to read data pointer: %w", err)
	}
	dataLen, err := mem.ReadUint64(instructionAddr + CInstructionDataLenOffset)
	if err != nil {
		return nil, fmt.Errorf("failed to read data length: %w", err)
	}

	if dataLen > MaxInstructionData {
		return nil, fmt.Errorf("instruction data too large: %d > %d", dataLen, MaxInstructionData)
	}

	// Read instruction data
	var data []byte
	if dataLen > 0 {
		data, err = vm.ReadMemory(dataPtr, int(dataLen))
		if err != nil {
			return nil, fmt.Errorf("failed to read instruction data: %w", err)
		}
	}

	return &CPIInstruction{
		ProgramID: programID,
		Accounts:  accounts,
		Data:      data,
	}, nil
}

// ReadCPIInstructionRust reads a Rust-style CPI instruction from VM memory.
// This is used by sol_invoke_signed_rust.
func ReadCPIInstructionRust(vm *sbpf.VM, instructionAddr uint64) (*CPIInstruction, error) {
	mem := vm.Memory()

	// Read inline program ID (32 bytes)
	programIDBytes, err := vm.ReadMemory(instructionAddr+RustInstructionProgramIDOffset, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to read program ID: %w", err)
	}
	programID, err := types.PubkeyFromBytes(programIDBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid program ID: %w", err)
	}

	// Read accounts Vec (ptr, len, cap)
	accountsPtr, err := mem.ReadUint64(instructionAddr + RustInstructionAccountsOffset)
	if err != nil {
		return nil, fmt.Errorf("failed to read accounts pointer: %w", err)
	}
	accountsLen, err := mem.ReadUint64(instructionAddr + RustInstructionAccountsOffset + 8)
	if err != nil {
		return nil, fmt.Errorf("failed to read accounts length: %w", err)
	}
	// Skip capacity (we don't need it)

	if accountsLen > MaxCPIAccounts {
		return nil, fmt.Errorf("too many CPI accounts: %d > %d", accountsLen, MaxCPIAccounts)
	}

	// Read account metas
	accounts := make([]CPIAccountMeta, accountsLen)
	for i := uint64(0); i < accountsLen; i++ {
		metaAddr := accountsPtr + i*RustAccountMetaSize

		// Read inline pubkey (32 bytes)
		pubkeyBytes, err := vm.ReadMemory(metaAddr+RustAccountMetaPubkeyOffset, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to read account %d pubkey: %w", i, err)
		}
		pubkey, err := types.PubkeyFromBytes(pubkeyBytes)
		if err != nil {
			return nil, fmt.Errorf("invalid account %d pubkey: %w", i, err)
		}

		// Read is_signer and is_writable (note: different order from C)
		isSigner, err := mem.ReadByte(metaAddr + RustAccountMetaIsSignerOffset)
		if err != nil {
			return nil, fmt.Errorf("failed to read account %d is_signer: %w", i, err)
		}
		isWritable, err := mem.ReadByte(metaAddr + RustAccountMetaIsWritableOffset)
		if err != nil {
			return nil, fmt.Errorf("failed to read account %d is_writable: %w", i, err)
		}

		accounts[i] = CPIAccountMeta{
			Pubkey:     pubkey,
			IsSigner:   isSigner != 0,
			IsWritable: isWritable != 0,
		}
	}

	// Read instruction data Vec (ptr, len, cap)
	dataPtr, err := mem.ReadUint64(instructionAddr + RustInstructionDataOffset)
	if err != nil {
		return nil, fmt.Errorf("failed to read data pointer: %w", err)
	}
	dataLen, err := mem.ReadUint64(instructionAddr + RustInstructionDataOffset + 8)
	if err != nil {
		return nil, fmt.Errorf("failed to read data length: %w", err)
	}
	// Skip capacity

	if dataLen > MaxInstructionData {
		return nil, fmt.Errorf("instruction data too large: %d > %d", dataLen, MaxInstructionData)
	}

	// Read instruction data
	var data []byte
	if dataLen > 0 {
		data, err = vm.ReadMemory(dataPtr, int(dataLen))
		if err != nil {
			return nil, fmt.Errorf("failed to read instruction data: %w", err)
		}
	}

	return &CPIInstruction{
		ProgramID: programID,
		Accounts:  accounts,
		Data:      data,
	}, nil
}

// ReadSignerSeedsC reads signer seeds from VM memory in C format.
// C format: Array of seed slice descriptors (ptr + len each 8 bytes).
//
// Layout:
//   seeds_addr -> array of signer seed sets
//   Each signer: array of seed descriptors (ptr, len)
func ReadSignerSeedsC(vm *sbpf.VM, seedsAddr uint64, numSigners uint64) ([]CPISignerSeeds, error) {
	if numSigners == 0 {
		return nil, nil
	}

	if numSigners > MaxCPISignerSeeds {
		return nil, fmt.Errorf("too many signers: %d > %d", numSigners, MaxCPISignerSeeds)
	}

	mem := vm.Memory()
	signers := make([]CPISignerSeeds, numSigners)

	// The outer array contains pointers to each signer's seed array
	// Each element is a SolSignerSeeds struct:
	//   seeds: *const SolSignerSeed (8 bytes)
	//   seeds_len: u64 (8 bytes)
	const signerSeedsSize = 16

	for i := uint64(0); i < numSigners; i++ {
		signerAddr := seedsAddr + i*signerSeedsSize

		// Read seeds array pointer
		seedsPtr, err := mem.ReadUint64(signerAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to read signer %d seeds pointer: %w", i, err)
		}

		// Read seeds array length
		seedsLen, err := mem.ReadUint64(signerAddr + 8)
		if err != nil {
			return nil, fmt.Errorf("failed to read signer %d seeds length: %w", i, err)
		}

		if seedsLen > MaxCPISeeds {
			return nil, fmt.Errorf("signer %d has too many seeds: %d > %d", i, seedsLen, MaxCPISeeds)
		}

		// Read each seed
		seeds := make([][]byte, seedsLen)
		for j := uint64(0); j < seedsLen; j++ {
			// Each SolSignerSeed is (ptr, len) = 16 bytes
			seedDescAddr := seedsPtr + j*16

			seedPtr, err := mem.ReadUint64(seedDescAddr)
			if err != nil {
				return nil, fmt.Errorf("failed to read signer %d seed %d pointer: %w", i, j, err)
			}

			seedLen, err := mem.ReadUint64(seedDescAddr + 8)
			if err != nil {
				return nil, fmt.Errorf("failed to read signer %d seed %d length: %w", i, j, err)
			}

			if seedLen > MaxCPISeedLen {
				return nil, fmt.Errorf("signer %d seed %d too long: %d > %d", i, j, seedLen, MaxCPISeedLen)
			}

			seedData, err := vm.ReadMemory(seedPtr, int(seedLen))
			if err != nil {
				return nil, fmt.Errorf("failed to read signer %d seed %d data: %w", i, j, err)
			}

			seeds[j] = make([]byte, seedLen)
			copy(seeds[j], seedData)
		}

		signers[i] = CPISignerSeeds{Seeds: seeds}
	}

	return signers, nil
}

// ReadSignerSeedsRust reads signer seeds from VM memory in Rust format.
// Rust format uses Vec structures with inline data or pointers.
//
// Layout: Vec<&[&[u8]]> - vector of slices of slices
func ReadSignerSeedsRust(vm *sbpf.VM, seedsAddr uint64, numSigners uint64) ([]CPISignerSeeds, error) {
	if numSigners == 0 {
		return nil, nil
	}

	if numSigners > MaxCPISignerSeeds {
		return nil, fmt.Errorf("too many signers: %d > %d", numSigners, MaxCPISignerSeeds)
	}

	mem := vm.Memory()
	signers := make([]CPISignerSeeds, numSigners)

	// Rust slice: (ptr, len) = 16 bytes each
	const sliceSize = 16

	for i := uint64(0); i < numSigners; i++ {
		signerSliceAddr := seedsAddr + i*sliceSize

		// Read inner slice descriptor (ptr, len)
		innerPtr, err := mem.ReadUint64(signerSliceAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to read signer %d slice pointer: %w", i, err)
		}

		innerLen, err := mem.ReadUint64(signerSliceAddr + 8)
		if err != nil {
			return nil, fmt.Errorf("failed to read signer %d slice length: %w", i, err)
		}

		if innerLen > MaxCPISeeds {
			return nil, fmt.Errorf("signer %d has too many seeds: %d > %d", i, innerLen, MaxCPISeeds)
		}

		// Read each seed slice
		seeds := make([][]byte, innerLen)
		for j := uint64(0); j < innerLen; j++ {
			seedSliceAddr := innerPtr + j*sliceSize

			seedPtr, err := mem.ReadUint64(seedSliceAddr)
			if err != nil {
				return nil, fmt.Errorf("failed to read signer %d seed %d pointer: %w", i, j, err)
			}

			seedLen, err := mem.ReadUint64(seedSliceAddr + 8)
			if err != nil {
				return nil, fmt.Errorf("failed to read signer %d seed %d length: %w", i, j, err)
			}

			if seedLen > MaxCPISeedLen {
				return nil, fmt.Errorf("signer %d seed %d too long: %d > %d", i, j, seedLen, MaxCPISeedLen)
			}

			seedData, err := vm.ReadMemory(seedPtr, int(seedLen))
			if err != nil {
				return nil, fmt.Errorf("failed to read signer %d seed %d data: %w", i, j, err)
			}

			seeds[j] = make([]byte, seedLen)
			copy(seeds[j], seedData)
		}

		signers[i] = CPISignerSeeds{Seeds: seeds}
	}

	return signers, nil
}

// SerializeCPIInstruction serializes a CPI instruction for passing to a callee.
// This creates the input buffer format expected by BPF programs.
func SerializeCPIInstruction(inst *CPIInstruction, accounts []*AccountInfo) ([]byte, error) {
	// Calculate buffer size
	// Format:
	//   num_accounts: u64 (8 bytes)
	//   for each account:
	//     duplicate_index: u8 (1 byte) - 0xFF if not duplicate
	//     is_signer: u8 (1 byte)
	//     is_writable: u8 (1 byte)
	//     executable: u8 (1 byte)
	//     padding: [4]u8 (4 bytes)
	//     pubkey: [32]u8 (32 bytes)
	//     owner: [32]u8 (32 bytes)
	//     lamports: u64 (8 bytes)
	//     data_len: u64 (8 bytes)
	//     data: [data_len]u8
	//     padding to 8-byte alignment
	//     rent_epoch: u64 (8 bytes)
	//   instruction_data_len: u64 (8 bytes)
	//   instruction_data: [data_len]u8
	//   program_id: [32]u8 (32 bytes)

	// Pre-calculate size
	size := 8 // num_accounts
	for _, acc := range accounts {
		accSize := 1 + 1 + 1 + 1 + 4 + 32 + 32 + 8 + 8 // Fixed fields
		accSize += len(acc.Data)
		// Align to 8 bytes
		if accSize%8 != 0 {
			accSize += 8 - (accSize % 8)
		}
		accSize += 8 // rent_epoch
		size += accSize
	}
	size += 8 + len(inst.Data) + 32 // instruction data + program_id

	buf := make([]byte, size)
	offset := 0

	// Write number of accounts
	binary.LittleEndian.PutUint64(buf[offset:], uint64(len(accounts)))
	offset += 8

	// Write each account
	for i, acc := range accounts {
		// Check if this account is a duplicate of an earlier one
		duplicateIndex := byte(0xFF)
		for j := 0; j < i; j++ {
			if accounts[j].Pubkey == acc.Pubkey {
				duplicateIndex = byte(j)
				break
			}
		}

		buf[offset] = duplicateIndex
		offset++

		if acc.IsSigner {
			buf[offset] = 1
		}
		offset++

		if acc.IsWritable {
			buf[offset] = 1
		}
		offset++

		if acc.Executable {
			buf[offset] = 1
		}
		offset++

		// Padding
		offset += 4

		// Pubkey
		copy(buf[offset:], acc.Pubkey[:])
		offset += 32

		// Owner
		copy(buf[offset:], acc.Owner[:])
		offset += 32

		// Lamports
		binary.LittleEndian.PutUint64(buf[offset:], *acc.Lamports)
		offset += 8

		// Data length
		binary.LittleEndian.PutUint64(buf[offset:], uint64(len(acc.Data)))
		offset += 8

		// Data
		copy(buf[offset:], acc.Data)
		offset += len(acc.Data)

		// Align to 8 bytes
		if offset%8 != 0 {
			offset += 8 - (offset % 8)
		}

		// Rent epoch
		binary.LittleEndian.PutUint64(buf[offset:], acc.RentEpoch)
		offset += 8
	}

	// Write instruction data length
	binary.LittleEndian.PutUint64(buf[offset:], uint64(len(inst.Data)))
	offset += 8

	// Write instruction data
	copy(buf[offset:], inst.Data)
	offset += len(inst.Data)

	// Write program ID
	copy(buf[offset:], inst.ProgramID[:])

	return buf, nil
}

// DeserializeCPIAccountChanges reads back account changes from callee's memory.
// This is used to propagate account modifications back to the caller.
func DeserializeCPIAccountChanges(vm *sbpf.VM, inputAddr uint64, accounts []*AccountInfo) error {
	mem := vm.Memory()
	offset := uint64(8) // Skip num_accounts

	for _, acc := range accounts {
		// Skip duplicate_index, is_signer, is_writable, executable, padding, pubkey, owner
		offset += 1 + 1 + 1 + 1 + 4 + 32 + 32

		// Read lamports
		lamports, err := mem.ReadUint64(inputAddr + offset)
		if err != nil {
			return fmt.Errorf("failed to read lamports: %w", err)
		}
		offset += 8

		// Read data length
		dataLen, err := mem.ReadUint64(inputAddr + offset)
		if err != nil {
			return fmt.Errorf("failed to read data length: %w", err)
		}
		offset += 8

		// Read data if writable
		if acc.IsWritable {
			*acc.Lamports = lamports
			if int(dataLen) <= len(acc.Data) {
				data, err := vm.ReadMemory(inputAddr+offset, int(dataLen))
				if err != nil {
					return fmt.Errorf("failed to read account data: %w", err)
				}
				copy(acc.Data, data)
			}
		}
		offset += dataLen

		// Align to 8 bytes
		if offset%8 != 0 {
			offset += 8 - (offset % 8)
		}

		// Skip rent_epoch
		offset += 8
	}

	return nil
}
