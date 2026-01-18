// Package replayer provides BPF program execution integration for the SVM.
package replayer

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/svm/programs/bpf_loader"
	"github.com/fortiblox/x1-nimbus/pkg/svm/sbpf"
	"github.com/fortiblox/x1-nimbus/pkg/svm/syscall"
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// BPF execution errors
var (
	// ErrInvalidELF indicates the program is not a valid ELF binary.
	ErrInvalidELF = errors.New("invalid ELF binary")

	// ErrNoTextSection indicates the ELF has no .text section.
	ErrNoTextSection = errors.New("ELF has no .text section")

	// ErrProgramDataNotFound indicates the program data account was not found.
	ErrProgramDataNotFound = errors.New("program data account not found")

	// ErrVMExecutionFailed indicates VM execution failed.
	ErrVMExecutionFailed = errors.New("VM execution failed")
)

// BPFExecutor handles execution of BPF programs through the sBPF VM.
type BPFExecutor struct {
	// accountsDB provides access to account storage for loading program data.
	accountsDB AccountsDB

	// ctx is the execution context for syscalls.
	ctx *syscall.ExecutionContext

	// syscallRegistry holds registered syscall handlers.
	syscallRegistry *syscall.Registry
}

// NewBPFExecutor creates a new BPF executor.
func NewBPFExecutor(db AccountsDB, ctx *syscall.ExecutionContext) *BPFExecutor {
	return &BPFExecutor{
		accountsDB:      db,
		ctx:             ctx,
		syscallRegistry: syscall.NewRegistry(),
	}
}

// Execute executes a BPF program with the given instruction.
func (e *BPFExecutor) Execute(programID types.Pubkey, instruction *types.Instruction) error {
	// Load the program account
	programAccount, err := e.accountsDB.GetAccount(programID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProgramNotFound, err)
	}

	if programAccount == nil {
		return fmt.Errorf("%w: program account not found", ErrProgramNotFound)
	}

	if !programAccount.Executable {
		return fmt.Errorf("%w: %s", ErrProgramNotExecutable, programID.String())
	}

	// Get the ELF bytecode from the program
	elfData, err := e.loadProgramELF(programAccount)
	if err != nil {
		return fmt.Errorf("failed to load program ELF: %w", err)
	}

	// Parse ELF and extract bytecode
	bytecode, err := e.extractBytecode(elfData)
	if err != nil {
		return fmt.Errorf("failed to extract bytecode: %w", err)
	}

	// Serialize input data (accounts + instruction data)
	inputData := e.serializeInput(instruction)

	// Create and configure the VM
	vm, err := sbpf.NewVM(bytecode, e.ctx.GetComputeUnitsRemaining())
	if err != nil {
		return fmt.Errorf("failed to create VM: %w", err)
	}

	// Set up syscall handler
	syscallHandler := &SyscallDispatcher{
		ctx:      e.ctx,
		registry: e.syscallRegistry,
	}
	vm.SetSyscallHandler(syscallHandler)

	// Register syscalls for this execution
	syscall.RegisterDefaultSyscalls(e.ctx)
	e.copySyscallRegistry()

	// Execute the program
	result, err := vm.Run(inputData)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrVMExecutionFailed, err)
	}

	// Update compute units consumed in context
	_ = e.ctx.ConsumeComputeUnits(vm.GetComputeUnitsUsed())

	// Check result - non-zero indicates error
	if result != 0 {
		return fmt.Errorf("program returned error code: %d", result)
	}

	// Deserialize and apply account modifications from input region
	err = e.applyAccountModifications(vm, instruction)
	if err != nil {
		return fmt.Errorf("failed to apply account modifications: %w", err)
	}

	return nil
}

// loadProgramELF loads the ELF data for a program account.
// Handles both direct executable accounts and upgradeable loader accounts.
func (e *BPFExecutor) loadProgramELF(programAccount *types.Account) ([]byte, error) {
	// Check the owner to determine the loader type
	owner := programAccount.Owner

	switch owner {
	case types.BPFLoaderUpgradeableProgramID:
		// Upgradeable loader - program account points to program data account
		return e.loadUpgradeableProgram(programAccount)

	case types.BPFLoaderProgramID, types.BPFLoader2ProgramID:
		// Legacy loaders - ELF is directly in the account data
		if len(programAccount.Data) == 0 {
			return nil, fmt.Errorf("%w: empty program data", ErrInvalidELF)
		}
		return programAccount.Data, nil

	default:
		// Assume the data is the ELF directly for other owners
		if len(programAccount.Data) == 0 {
			return nil, fmt.Errorf("%w: empty program data", ErrInvalidELF)
		}
		return programAccount.Data, nil
	}
}

// loadUpgradeableProgram loads ELF from an upgradeable loader program.
func (e *BPFExecutor) loadUpgradeableProgram(programAccount *types.Account) ([]byte, error) {
	// Parse the program account state to get the program data address
	programDataAddress, err := bpf_loader.GetProgramDataFromProgram(programAccount.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to get program data address: %w", err)
	}

	// Load the program data account
	programDataAccount, err := e.accountsDB.GetAccount(programDataAddress)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProgramDataNotFound, err)
	}

	if programDataAccount == nil {
		return nil, fmt.Errorf("%w: program data account not found at %s",
			ErrProgramDataNotFound, programDataAddress.String())
	}

	// Extract the ELF from the program data account
	elfData, err := bpf_loader.GetProgramBytecode(programDataAccount.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to get program bytecode: %w", err)
	}

	return elfData, nil
}

// extractBytecode parses an ELF binary and extracts the executable bytecode.
func (e *BPFExecutor) extractBytecode(elfData []byte) ([]byte, error) {
	// Validate ELF structure
	if err := bpf_loader.ValidateELF(elfData); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidELF, err)
	}

	// Parse ELF header
	header, err := e.parseELFHeader(elfData)
	if err != nil {
		return nil, err
	}

	// Find and extract the .text section
	bytecode, err := e.extractTextSection(elfData, header)
	if err != nil {
		return nil, err
	}

	return bytecode, nil
}

// ELFHeader64 represents the 64-bit ELF header.
type ELFHeader64 struct {
	Entry     uint64
	PhOff     uint64
	ShOff     uint64
	PhEntSize uint16
	PhNum     uint16
	ShEntSize uint16
	ShNum     uint16
	ShStrNdx  uint16
}

// ELFSectionHeader64 represents a 64-bit ELF section header.
type ELFSectionHeader64 struct {
	Name      uint32
	Type      uint32
	Flags     uint64
	Addr      uint64
	Offset    uint64
	Size      uint64
	Link      uint32
	Info      uint32
	AddrAlign uint64
	EntSize   uint64
}

// ELF section types
const (
	SHT_PROGBITS = 1 // Program data
)

// ELF section flags
const (
	SHF_EXECINSTR = 0x4 // Executable
)

// parseELFHeader parses the ELF header from binary data.
func (e *BPFExecutor) parseELFHeader(data []byte) (*ELFHeader64, error) {
	if len(data) < 64 {
		return nil, fmt.Errorf("%w: data too short for ELF header", ErrInvalidELF)
	}

	return &ELFHeader64{
		Entry:     binary.LittleEndian.Uint64(data[24:32]),
		PhOff:     binary.LittleEndian.Uint64(data[32:40]),
		ShOff:     binary.LittleEndian.Uint64(data[40:48]),
		PhEntSize: binary.LittleEndian.Uint16(data[54:56]),
		PhNum:     binary.LittleEndian.Uint16(data[56:58]),
		ShEntSize: binary.LittleEndian.Uint16(data[58:60]),
		ShNum:     binary.LittleEndian.Uint16(data[60:62]),
		ShStrNdx:  binary.LittleEndian.Uint16(data[62:64]),
	}, nil
}

// parseSectionHeader parses a section header from binary data.
func (e *BPFExecutor) parseSectionHeader(data []byte) *ELFSectionHeader64 {
	return &ELFSectionHeader64{
		Name:      binary.LittleEndian.Uint32(data[0:4]),
		Type:      binary.LittleEndian.Uint32(data[4:8]),
		Flags:     binary.LittleEndian.Uint64(data[8:16]),
		Addr:      binary.LittleEndian.Uint64(data[16:24]),
		Offset:    binary.LittleEndian.Uint64(data[24:32]),
		Size:      binary.LittleEndian.Uint64(data[32:40]),
		Link:      binary.LittleEndian.Uint32(data[40:44]),
		Info:      binary.LittleEndian.Uint32(data[44:48]),
		AddrAlign: binary.LittleEndian.Uint64(data[48:56]),
		EntSize:   binary.LittleEndian.Uint64(data[56:64]),
	}
}

// extractTextSection finds and extracts the .text section from an ELF binary.
func (e *BPFExecutor) extractTextSection(data []byte, header *ELFHeader64) ([]byte, error) {
	if header.ShOff == 0 || header.ShNum == 0 {
		return nil, fmt.Errorf("%w: no section headers", ErrNoTextSection)
	}

	// Validate section header table bounds
	shTableEnd := header.ShOff + uint64(header.ShNum)*uint64(header.ShEntSize)
	if shTableEnd > uint64(len(data)) {
		return nil, fmt.Errorf("%w: section header table out of bounds", ErrInvalidELF)
	}

	// First, find the string table section
	var strTable []byte
	if header.ShStrNdx < header.ShNum {
		strOffset := header.ShOff + uint64(header.ShStrNdx)*uint64(header.ShEntSize)
		if strOffset+64 <= uint64(len(data)) {
			strSection := e.parseSectionHeader(data[strOffset:])
			if strSection.Offset+strSection.Size <= uint64(len(data)) {
				strTable = data[strSection.Offset : strSection.Offset+strSection.Size]
			}
		}
	}

	// Iterate through sections looking for .text or executable sections
	var textSection *ELFSectionHeader64
	for i := uint16(0); i < header.ShNum; i++ {
		offset := header.ShOff + uint64(i)*uint64(header.ShEntSize)
		if offset+64 > uint64(len(data)) {
			continue
		}

		section := e.parseSectionHeader(data[offset:])

		// Check if this is an executable program section
		if section.Type == SHT_PROGBITS && (section.Flags&SHF_EXECINSTR) != 0 {
			// Try to verify it's named ".text" if we have the string table
			if strTable != nil && section.Name < uint32(len(strTable)) {
				name := e.getSectionName(strTable, section.Name)
				if name == ".text" {
					textSection = section
					break
				}
			}
			// If no string table or no match, use first executable section
			if textSection == nil {
				textSection = section
			}
		}
	}

	if textSection == nil {
		// If no explicit text section found, try to use the entry point
		// Many sBPF programs have the code at the entry point
		return e.extractCodeFromEntry(data, header)
	}

	// Validate section bounds
	if textSection.Offset+textSection.Size > uint64(len(data)) {
		return nil, fmt.Errorf("%w: text section out of bounds", ErrInvalidELF)
	}

	if textSection.Size == 0 {
		return nil, fmt.Errorf("%w: empty text section", ErrNoTextSection)
	}

	return data[textSection.Offset : textSection.Offset+textSection.Size], nil
}

// getSectionName extracts a null-terminated section name from the string table.
func (e *BPFExecutor) getSectionName(strTable []byte, nameOffset uint32) string {
	if nameOffset >= uint32(len(strTable)) {
		return ""
	}

	end := nameOffset
	for end < uint32(len(strTable)) && strTable[end] != 0 {
		end++
	}

	return string(strTable[nameOffset:end])
}

// extractCodeFromEntry extracts code starting from the entry point.
// This is a fallback when no .text section is found.
func (e *BPFExecutor) extractCodeFromEntry(data []byte, header *ELFHeader64) ([]byte, error) {
	if header.Entry == 0 {
		return nil, fmt.Errorf("%w: no entry point", ErrNoTextSection)
	}

	// For sBPF, the entry point is typically an offset into the program data
	// We need to find which segment contains the entry point

	// If no program headers, use a simple approach
	if header.PhOff == 0 || header.PhNum == 0 {
		// Assume entry is a file offset (simplified)
		if header.Entry >= uint64(len(data)) {
			return nil, fmt.Errorf("%w: entry point out of bounds", ErrInvalidELF)
		}
		// Return from entry to end of file
		return data[header.Entry:], nil
	}

	// Parse program headers to find the loadable segment containing entry
	for i := uint16(0); i < header.PhNum; i++ {
		offset := header.PhOff + uint64(i)*uint64(header.PhEntSize)
		if offset+56 > uint64(len(data)) {
			continue
		}

		// Program header structure (simplified)
		// p_type (4), p_flags (4), p_offset (8), p_vaddr (8), p_paddr (8),
		// p_filesz (8), p_memsz (8), p_align (8)
		pType := binary.LittleEndian.Uint32(data[offset:])
		pOffset := binary.LittleEndian.Uint64(data[offset+8:])
		pVaddr := binary.LittleEndian.Uint64(data[offset+16:])
		pFilesz := binary.LittleEndian.Uint64(data[offset+32:])

		// PT_LOAD = 1
		if pType == 1 && header.Entry >= pVaddr && header.Entry < pVaddr+pFilesz {
			// Calculate file offset from virtual address
			fileOffset := pOffset + (header.Entry - pVaddr)
			endOffset := pOffset + pFilesz

			if fileOffset >= uint64(len(data)) || endOffset > uint64(len(data)) {
				continue
			}

			return data[fileOffset:endOffset], nil
		}
	}

	return nil, fmt.Errorf("%w: could not find code segment", ErrNoTextSection)
}

// serializeInput serializes the accounts and instruction data for the VM input region.
// Format follows Solana's serialization format for BPF programs.
func (e *BPFExecutor) serializeInput(instruction *types.Instruction) []byte {
	// Calculate total size needed
	// Format:
	// - num_accounts (8 bytes)
	// - for each account:
	//   - is_duplicate (1 byte) - always 0 for now
	//   - is_signer (1 byte)
	//   - is_writable (1 byte)
	//   - executable (1 byte)
	//   - padding (4 bytes)
	//   - pubkey (32 bytes)
	//   - owner (32 bytes)
	//   - lamports (8 bytes)
	//   - data_len (8 bytes)
	//   - data (aligned to 8 bytes)
	//   - rent_epoch (8 bytes)
	// - instruction_data_len (8 bytes)
	// - instruction_data
	// - program_id (32 bytes)

	accounts := e.ctx.Accounts

	// Calculate total size
	size := 8 // num_accounts
	for _, acc := range accounts {
		size += 1 + 1 + 1 + 1 + 4 // flags + padding
		size += 32                 // pubkey
		size += 32                 // owner
		size += 8                  // lamports
		size += 8                  // data_len
		dataLen := len(acc.Data)
		size += dataLen
		// Align to 8 bytes
		if dataLen%8 != 0 {
			size += 8 - (dataLen % 8)
		}
		size += 8 // rent_epoch
	}
	size += 8                        // instruction_data_len
	size += len(instruction.Data)    // instruction_data
	size += 32                       // program_id

	// Allocate buffer
	buf := make([]byte, size)
	offset := 0

	// Write number of accounts
	binary.LittleEndian.PutUint64(buf[offset:], uint64(len(accounts)))
	offset += 8

	// Write each account
	for _, acc := range accounts {
		// is_duplicate (always 0)
		buf[offset] = 0
		offset++

		// is_signer
		if acc.IsSigner {
			buf[offset] = 1
		} else {
			buf[offset] = 0
		}
		offset++

		// is_writable
		if acc.IsWritable {
			buf[offset] = 1
		} else {
			buf[offset] = 0
		}
		offset++

		// executable
		if acc.Executable {
			buf[offset] = 1
		} else {
			buf[offset] = 0
		}
		offset++

		// padding
		offset += 4

		// pubkey
		copy(buf[offset:], acc.Pubkey[:])
		offset += 32

		// owner
		copy(buf[offset:], acc.Owner[:])
		offset += 32

		// lamports
		binary.LittleEndian.PutUint64(buf[offset:], *acc.Lamports)
		offset += 8

		// data_len
		binary.LittleEndian.PutUint64(buf[offset:], uint64(len(acc.Data)))
		offset += 8

		// data
		copy(buf[offset:], acc.Data)
		offset += len(acc.Data)

		// Align to 8 bytes
		if len(acc.Data)%8 != 0 {
			offset += 8 - (len(acc.Data) % 8)
		}

		// rent_epoch
		binary.LittleEndian.PutUint64(buf[offset:], acc.RentEpoch)
		offset += 8
	}

	// Write instruction data length
	binary.LittleEndian.PutUint64(buf[offset:], uint64(len(instruction.Data)))
	offset += 8

	// Write instruction data
	copy(buf[offset:], instruction.Data)
	offset += len(instruction.Data)

	// Write program ID
	copy(buf[offset:], instruction.ProgramID[:])

	return buf
}

// applyAccountModifications reads modified account data from VM memory
// and applies changes back to the execution context.
func (e *BPFExecutor) applyAccountModifications(vm *sbpf.VM, instruction *types.Instruction) error {
	// Read from the input region which may have been modified by the program
	mem := vm.Memory()
	if mem == nil {
		return nil
	}

	inputData := mem.Input.Data
	if len(inputData) < 8 {
		return nil
	}

	offset := 0

	// Read number of accounts
	numAccounts := binary.LittleEndian.Uint64(inputData[offset:])
	offset += 8

	if numAccounts != uint64(len(e.ctx.Accounts)) {
		return fmt.Errorf("account count mismatch: expected %d, got %d",
			len(e.ctx.Accounts), numAccounts)
	}

	// Process each account
	for i := uint64(0); i < numAccounts; i++ {
		if offset+8 > len(inputData) {
			break
		}

		// Skip is_duplicate, is_signer, is_writable, executable, padding
		offset += 8

		// Skip pubkey
		offset += 32

		// Skip owner (owner changes not allowed via VM)
		offset += 32

		// Read lamports
		if offset+8 > len(inputData) {
			break
		}
		newLamports := binary.LittleEndian.Uint64(inputData[offset:])
		offset += 8

		// Read data_len
		if offset+8 > len(inputData) {
			break
		}
		dataLen := binary.LittleEndian.Uint64(inputData[offset:])
		offset += 8

		// Read data
		if offset+int(dataLen) > len(inputData) {
			break
		}
		newData := inputData[offset : offset+int(dataLen)]
		offset += int(dataLen)

		// Skip alignment padding
		if int(dataLen)%8 != 0 {
			offset += 8 - (int(dataLen) % 8)
		}

		// Skip rent_epoch
		offset += 8

		// Apply modifications to writable accounts
		if i < uint64(len(e.ctx.Accounts)) {
			acc := e.ctx.Accounts[i]
			if acc.IsWritable {
				*acc.Lamports = newLamports
				if len(newData) > 0 {
					// Resize if needed
					if len(acc.Data) != len(newData) {
						acc.Data = make([]byte, len(newData))
					}
					copy(acc.Data, newData)
				}
			}
		}
	}

	return nil
}

// copySyscallRegistry copies syscalls from the default registry to our local registry.
func (e *BPFExecutor) copySyscallRegistry() {
	// The default registry is populated by RegisterDefaultSyscalls
	// We need to copy handlers to our local registry
	syscalls := syscall.DefaultRegistry.ListSyscalls()
	for name, hash := range syscalls {
		if handler, ok := syscall.DefaultRegistry.GetHandler(hash); ok {
			e.syscallRegistry.RegisterSyscall(name, handler)
		}
	}
}

// SyscallDispatcher implements sbpf.SyscallHandler and dispatches
// syscalls to the syscall registry.
type SyscallDispatcher struct {
	ctx      *syscall.ExecutionContext
	registry *syscall.Registry
}

// HandleSyscall implements sbpf.SyscallHandler.
// It routes syscalls to the appropriate handler based on the syscall number.
func (d *SyscallDispatcher) HandleSyscall(vm *sbpf.VM, syscallNum uint32) (uint64, error) {
	// Get register values for syscall arguments (R1-R5)
	r1 := vm.GetRegister(sbpf.R1)
	r2 := vm.GetRegister(sbpf.R2)
	r3 := vm.GetRegister(sbpf.R3)
	r4 := vm.GetRegister(sbpf.R4)
	r5 := vm.GetRegister(sbpf.R5)

	// Dispatch to the syscall handler
	result, err := d.registry.Dispatch(syscallNum, vm, r1, r2, r3, r4, r5)
	if err != nil {
		// Log the error but return the error code
		_ = d.ctx.AddLog(fmt.Sprintf("syscall 0x%08x error: %v", syscallNum, err))
		return result, nil // Return error code in R0, not as Go error
	}

	return result, nil
}
