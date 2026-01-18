package syscall

import (
	"errors"
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/svm/sbpf"
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// CPI errors
var (
	ErrCPIDepthExceeded          = errors.New("CPI depth exceeded")
	ErrCPIProgramNotExecutable   = errors.New("program account is not executable")
	ErrCPIAccountNotFound        = errors.New("account not found in transaction")
	ErrCPIWritablePrivilege      = errors.New("writable privilege escalation")
	ErrCPISignerPrivilege        = errors.New("signer privilege escalation")
	ErrCPIPDASignerMismatch      = errors.New("PDA signer does not match derived address")
	ErrCPIInvalidSignerSeeds     = errors.New("invalid signer seeds")
	ErrCPIProgramNotProvided     = errors.New("program account not provided")
	ErrCPIReentrancy             = errors.New("program reentrancy not allowed")
	ErrCPIAccountBorrowFailed    = errors.New("account already borrowed")
	ErrCPIReturnDataTooLarge     = errors.New("return data too large")
	ErrCPIInstructionDataTooLarge = errors.New("instruction data too large")
)

// CPI syscall return codes
const (
	CPISuccess                    uint64 = 0
	CPIErrorInvalidArgument       uint64 = 1
	CPIErrorInvalidMemory         uint64 = 2
	CPIErrorPrivilegeEscalation   uint64 = 3
	CPIErrorMaxDepthExceeded      uint64 = 4
	CPIErrorCalleeError           uint64 = 5
	CPIErrorReentrancy            uint64 = 6
	CPIErrorAccountNotFound       uint64 = 7
	CPIErrorProgramNotExecutable  uint64 = 8
	CPIErrorInvalidPDASigner      uint64 = 9
	CPIErrorComputeExceeded       uint64 = 10
)

// SolInvokeSignedC implements the sol_invoke_signed_c syscall.
// This is the C-style interface for cross-program invocation.
//
// Arguments:
//   r1: pointer to instruction (SolInstruction struct)
//   r2: pointer to account infos array
//   r3: number of account infos
//   r4: pointer to signer seeds array
//   r5: number of signer seeds
//
// Returns 0 on success, error code on failure.
type SolInvokeSignedC struct {
	ctx *ExecutionContext
}

// NewSolInvokeSignedC creates a new sol_invoke_signed_c handler.
func NewSolInvokeSignedC(ctx *ExecutionContext) *SolInvokeSignedC {
	return &SolInvokeSignedC{ctx: ctx}
}

// Invoke implements SyscallHandler.
func (s *SolInvokeSignedC) Invoke(vm *sbpf.VM, r1, r2, r3, r4, r5 uint64) (uint64, error) {
	instructionAddr := r1
	accountInfosAddr := r2
	accountInfosLen := r3
	signerSeedsAddr := r4
	signerSeedsLen := r5

	// Consume base CPI compute units
	cost := CUCPIBase + accountInfosLen*CUCPIPerAccount
	if err := s.ctx.ConsumeComputeUnits(cost); err != nil {
		return CPIErrorComputeExceeded, err
	}

	// Check CPI depth
	if s.ctx.Depth >= MaxCPIDepth {
		return CPIErrorMaxDepthExceeded, ErrCPIDepthExceeded
	}

	// Read instruction from VM memory (C format)
	instruction, err := ReadCPIInstructionC(vm, instructionAddr)
	if err != nil {
		return CPIErrorInvalidMemory, fmt.Errorf("failed to read instruction: %w", err)
	}

	// Consume compute units for instruction data
	if err := s.ctx.ConsumeComputeUnits(uint64(len(instruction.Data)) * CUCPIPerDataByte); err != nil {
		return CPIErrorComputeExceeded, err
	}

	// Read signer seeds (C format)
	var signerSeeds []CPISignerSeeds
	if signerSeedsLen > 0 {
		signerSeeds, err = ReadSignerSeedsC(vm, signerSeedsAddr, signerSeedsLen)
		if err != nil {
			return CPIErrorInvalidMemory, fmt.Errorf("failed to read signer seeds: %w", err)
		}
	}

	// Execute the CPI
	result, err := s.executeCPI(vm, instruction, accountInfosAddr, accountInfosLen, signerSeeds)
	if err != nil {
		return result, err
	}

	return CPISuccess, nil
}

// executeCPI performs the actual cross-program invocation.
func (s *SolInvokeSignedC) executeCPI(vm *sbpf.VM, instruction *CPIInstruction, accountInfosAddr, accountInfosLen uint64, signerSeeds []CPISignerSeeds) (uint64, error) {
	// Validate the instruction accounts are a subset of caller's accounts
	calleeAccounts, err := s.resolveAndValidateAccounts(instruction)
	if err != nil {
		if errors.Is(err, ErrCPIAccountNotFound) {
			return CPIErrorAccountNotFound, err
		}
		if errors.Is(err, ErrCPIWritablePrivilege) || errors.Is(err, ErrCPISignerPrivilege) {
			return CPIErrorPrivilegeEscalation, err
		}
		return CPIErrorInvalidArgument, err
	}

	// Verify PDA signers if seeds are provided
	pdaSigners, err := s.verifyPDASigners(instruction, signerSeeds)
	if err != nil {
		return CPIErrorInvalidPDASigner, err
	}

	// Apply PDA signer privileges
	for _, acc := range instruction.Accounts {
		if acc.IsSigner {
			// Check if this is a PDA signer
			if _, isPDA := pdaSigners[acc.Pubkey]; isPDA {
				// PDA can sign for the calling program
				continue
			}
			// Otherwise, the account must already be a signer in the caller's context
			callerAcc, err := s.ctx.GetAccount(acc.Pubkey)
			if err != nil {
				return CPIErrorAccountNotFound, err
			}
			if !callerAcc.IsSigner {
				return CPIErrorPrivilegeEscalation, fmt.Errorf("%w: account %s requires signer but caller doesn't have it", ErrCPISignerPrivilege, acc.Pubkey.String())
			}
		}
	}

	// Check that the program is executable
	programAcc, err := s.ctx.GetAccount(instruction.ProgramID)
	if err != nil {
		return CPIErrorAccountNotFound, fmt.Errorf("program account not found: %w", err)
	}
	if !programAcc.Executable {
		return CPIErrorProgramNotExecutable, ErrCPIProgramNotExecutable
	}

	// Check for reentrancy (program cannot call itself directly)
	if instruction.ProgramID == s.ctx.ProgramID {
		return CPIErrorReentrancy, ErrCPIReentrancy
	}

	// Execute the callee program via the context's InvokeProgram method
	err = s.ctx.InvokeProgram(instruction.ProgramID, instruction.Accounts, instruction.Data, signerSeeds, pdaSigners, calleeAccounts)
	if err != nil {
		return CPIErrorCalleeError, err
	}

	return CPISuccess, nil
}

// resolveAndValidateAccounts validates that instruction accounts are a subset of caller's accounts
// and have appropriate permissions.
func (s *SolInvokeSignedC) resolveAndValidateAccounts(instruction *CPIInstruction) ([]*AccountInfo, error) {
	calleeAccounts := make([]*AccountInfo, len(instruction.Accounts))

	for i, meta := range instruction.Accounts {
		// Find the account in caller's context
		callerAcc, err := s.ctx.GetAccount(meta.Pubkey)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrCPIAccountNotFound, meta.Pubkey.String())
		}

		// Check writable privilege - callee cannot make an account writable if caller doesn't have it
		if meta.IsWritable && !callerAcc.IsWritable {
			return nil, fmt.Errorf("%w: account %s", ErrCPIWritablePrivilege, meta.Pubkey.String())
		}

		// Create account info for callee with possibly restricted permissions
		// (callee can have same or fewer privileges than caller)
		lamports := *callerAcc.Lamports
		calleeAccounts[i] = &AccountInfo{
			Pubkey:     callerAcc.Pubkey,
			Lamports:   &lamports,
			Data:       callerAcc.Data, // Share data slice - changes visible to both
			Owner:      callerAcc.Owner,
			Executable: callerAcc.Executable,
			RentEpoch:  callerAcc.RentEpoch,
			IsSigner:   meta.IsSigner,
			IsWritable: meta.IsWritable,
		}
	}

	return calleeAccounts, nil
}

// verifyPDASigners verifies that PDA signers match the seeds provided.
func (s *SolInvokeSignedC) verifyPDASigners(instruction *CPIInstruction, signerSeeds []CPISignerSeeds) (map[types.Pubkey]bool, error) {
	pdaSigners := make(map[types.Pubkey]bool)

	for _, seeds := range signerSeeds {
		// Derive the PDA from seeds and the calling program's ID
		pda, valid := CreateProgramAddress(seeds.Seeds, s.ctx.ProgramID)
		if !valid {
			return nil, fmt.Errorf("%w: seeds do not produce valid PDA", ErrCPIInvalidSignerSeeds)
		}

		// Verify that the derived PDA is actually used as a signer in the instruction
		found := false
		for _, acc := range instruction.Accounts {
			if acc.Pubkey == pda && acc.IsSigner {
				found = true
				break
			}
		}

		if !found {
			return nil, fmt.Errorf("%w: PDA %s not found as signer in instruction", ErrCPIPDASignerMismatch, pda.String())
		}

		pdaSigners[pda] = true
	}

	return pdaSigners, nil
}

// SolInvokeSignedRust implements the sol_invoke_signed_rust syscall.
// This is the Rust-style interface for cross-program invocation.
//
// Arguments:
//   r1: pointer to instruction (Rust Instruction struct)
//   r2: pointer to account infos array
//   r3: number of account infos
//   r4: pointer to signer seeds slice
//   r5: number of signers
//
// Returns 0 on success, error code on failure.
type SolInvokeSignedRust struct {
	ctx *ExecutionContext
}

// NewSolInvokeSignedRust creates a new sol_invoke_signed_rust handler.
func NewSolInvokeSignedRust(ctx *ExecutionContext) *SolInvokeSignedRust {
	return &SolInvokeSignedRust{ctx: ctx}
}

// Invoke implements SyscallHandler.
func (s *SolInvokeSignedRust) Invoke(vm *sbpf.VM, r1, r2, r3, r4, r5 uint64) (uint64, error) {
	instructionAddr := r1
	accountInfosAddr := r2
	accountInfosLen := r3
	signerSeedsAddr := r4
	signerSeedsLen := r5

	// Consume base CPI compute units
	cost := CUCPIBase + accountInfosLen*CUCPIPerAccount
	if err := s.ctx.ConsumeComputeUnits(cost); err != nil {
		return CPIErrorComputeExceeded, err
	}

	// Check CPI depth
	if s.ctx.Depth >= MaxCPIDepth {
		return CPIErrorMaxDepthExceeded, ErrCPIDepthExceeded
	}

	// Read instruction from VM memory (Rust format)
	instruction, err := ReadCPIInstructionRust(vm, instructionAddr)
	if err != nil {
		return CPIErrorInvalidMemory, fmt.Errorf("failed to read instruction: %w", err)
	}

	// Consume compute units for instruction data
	if err := s.ctx.ConsumeComputeUnits(uint64(len(instruction.Data)) * CUCPIPerDataByte); err != nil {
		return CPIErrorComputeExceeded, err
	}

	// Read signer seeds (Rust format)
	var signerSeeds []CPISignerSeeds
	if signerSeedsLen > 0 {
		signerSeeds, err = ReadSignerSeedsRust(vm, signerSeedsAddr, signerSeedsLen)
		if err != nil {
			return CPIErrorInvalidMemory, fmt.Errorf("failed to read signer seeds: %w", err)
		}
	}

	// Execute the CPI (same logic as C version from here)
	result, err := s.executeCPI(vm, instruction, accountInfosAddr, accountInfosLen, signerSeeds)
	if err != nil {
		return result, err
	}

	return CPISuccess, nil
}

// executeCPI performs the actual cross-program invocation.
func (s *SolInvokeSignedRust) executeCPI(vm *sbpf.VM, instruction *CPIInstruction, accountInfosAddr, accountInfosLen uint64, signerSeeds []CPISignerSeeds) (uint64, error) {
	// Validate the instruction accounts are a subset of caller's accounts
	calleeAccounts, err := s.resolveAndValidateAccounts(instruction)
	if err != nil {
		if errors.Is(err, ErrCPIAccountNotFound) {
			return CPIErrorAccountNotFound, err
		}
		if errors.Is(err, ErrCPIWritablePrivilege) || errors.Is(err, ErrCPISignerPrivilege) {
			return CPIErrorPrivilegeEscalation, err
		}
		return CPIErrorInvalidArgument, err
	}

	// Verify PDA signers if seeds are provided
	pdaSigners, err := s.verifyPDASigners(instruction, signerSeeds)
	if err != nil {
		return CPIErrorInvalidPDASigner, err
	}

	// Apply PDA signer privileges
	for _, acc := range instruction.Accounts {
		if acc.IsSigner {
			// Check if this is a PDA signer
			if _, isPDA := pdaSigners[acc.Pubkey]; isPDA {
				// PDA can sign for the calling program
				continue
			}
			// Otherwise, the account must already be a signer in the caller's context
			callerAcc, err := s.ctx.GetAccount(acc.Pubkey)
			if err != nil {
				return CPIErrorAccountNotFound, err
			}
			if !callerAcc.IsSigner {
				return CPIErrorPrivilegeEscalation, fmt.Errorf("%w: account %s requires signer but caller doesn't have it", ErrCPISignerPrivilege, acc.Pubkey.String())
			}
		}
	}

	// Check that the program is executable
	programAcc, err := s.ctx.GetAccount(instruction.ProgramID)
	if err != nil {
		return CPIErrorAccountNotFound, fmt.Errorf("program account not found: %w", err)
	}
	if !programAcc.Executable {
		return CPIErrorProgramNotExecutable, ErrCPIProgramNotExecutable
	}

	// Check for reentrancy (program cannot call itself directly)
	if instruction.ProgramID == s.ctx.ProgramID {
		return CPIErrorReentrancy, ErrCPIReentrancy
	}

	// Execute the callee program via the context's InvokeProgram method
	err = s.ctx.InvokeProgram(instruction.ProgramID, instruction.Accounts, instruction.Data, signerSeeds, pdaSigners, calleeAccounts)
	if err != nil {
		return CPIErrorCalleeError, err
	}

	return CPISuccess, nil
}

// resolveAndValidateAccounts validates that instruction accounts are a subset of caller's accounts
// and have appropriate permissions.
func (s *SolInvokeSignedRust) resolveAndValidateAccounts(instruction *CPIInstruction) ([]*AccountInfo, error) {
	calleeAccounts := make([]*AccountInfo, len(instruction.Accounts))

	for i, meta := range instruction.Accounts {
		// Find the account in caller's context
		callerAcc, err := s.ctx.GetAccount(meta.Pubkey)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrCPIAccountNotFound, meta.Pubkey.String())
		}

		// Check writable privilege - callee cannot make an account writable if caller doesn't have it
		if meta.IsWritable && !callerAcc.IsWritable {
			return nil, fmt.Errorf("%w: account %s", ErrCPIWritablePrivilege, meta.Pubkey.String())
		}

		// Create account info for callee with possibly restricted permissions
		// (callee can have same or fewer privileges than caller)
		lamports := *callerAcc.Lamports
		calleeAccounts[i] = &AccountInfo{
			Pubkey:     callerAcc.Pubkey,
			Lamports:   &lamports,
			Data:       callerAcc.Data, // Share data slice - changes visible to both
			Owner:      callerAcc.Owner,
			Executable: callerAcc.Executable,
			RentEpoch:  callerAcc.RentEpoch,
			IsSigner:   meta.IsSigner,
			IsWritable: meta.IsWritable,
		}
	}

	return calleeAccounts, nil
}

// verifyPDASigners verifies that PDA signers match the seeds provided.
func (s *SolInvokeSignedRust) verifyPDASigners(instruction *CPIInstruction, signerSeeds []CPISignerSeeds) (map[types.Pubkey]bool, error) {
	pdaSigners := make(map[types.Pubkey]bool)

	for _, seeds := range signerSeeds {
		// Derive the PDA from seeds and the calling program's ID
		pda, valid := CreateProgramAddress(seeds.Seeds, s.ctx.ProgramID)
		if !valid {
			return nil, fmt.Errorf("%w: seeds do not produce valid PDA", ErrCPIInvalidSignerSeeds)
		}

		// Verify that the derived PDA is actually used as a signer in the instruction
		found := false
		for _, acc := range instruction.Accounts {
			if acc.Pubkey == pda && acc.IsSigner {
				found = true
				break
			}
		}

		if !found {
			return nil, fmt.Errorf("%w: PDA %s not found as signer in instruction", ErrCPIPDASignerMismatch, pda.String())
		}

		pdaSigners[pda] = true
	}

	return pdaSigners, nil
}

// SolSetReturnData implements the sol_set_return_data syscall.
// Programs use this to return data to their caller.
//
// Arguments:
//   r1: pointer to return data
//   r2: length of return data
//
// Returns 0 on success, error code on failure.
type SolSetReturnData struct {
	ctx *ExecutionContext
}

// NewSolSetReturnData creates a new sol_set_return_data handler.
func NewSolSetReturnData(ctx *ExecutionContext) *SolSetReturnData {
	return &SolSetReturnData{ctx: ctx}
}

// Invoke implements SyscallHandler.
func (s *SolSetReturnData) Invoke(vm *sbpf.VM, r1, r2, r3, r4, r5 uint64) (uint64, error) {
	dataAddr := r1
	dataLen := r2

	// Consume compute units based on data length
	cost := CULogBase + dataLen*CULogPerByte
	if err := s.ctx.ConsumeComputeUnits(cost); err != nil {
		return SyscallErrorComputeExceeded, err
	}

	// Validate data length
	if dataLen > MaxReturnDataLength {
		return SyscallErrorInvalidArgument, ErrCPIReturnDataTooLarge
	}

	// Read return data from VM memory
	var data []byte
	if dataLen > 0 {
		var err error
		data, err = vm.ReadMemory(dataAddr, int(dataLen))
		if err != nil {
			return SyscallErrorInvalidMemory, err
		}
	}

	// Set return data in context
	if err := s.ctx.SetReturnData(s.ctx.ProgramID, data); err != nil {
		return SyscallErrorInvalidArgument, err
	}

	return SyscallSuccess, nil
}

// SolGetReturnData implements the sol_get_return_data syscall.
// Programs use this to retrieve return data from a previous CPI.
//
// Arguments:
//   r1: pointer to buffer for return data
//   r2: length of buffer
//   r3: pointer to store program ID (32 bytes)
//
// Returns the actual length of return data (may be larger than buffer).
type SolGetReturnData struct {
	ctx *ExecutionContext
}

// NewSolGetReturnData creates a new sol_get_return_data handler.
func NewSolGetReturnData(ctx *ExecutionContext) *SolGetReturnData {
	return &SolGetReturnData{ctx: ctx}
}

// Invoke implements SyscallHandler.
func (s *SolGetReturnData) Invoke(vm *sbpf.VM, r1, r2, r3, r4, r5 uint64) (uint64, error) {
	bufAddr := r1
	bufLen := r2
	programIDAddr := r3

	// Consume compute units
	if err := s.ctx.ConsumeComputeUnits(CULogBase); err != nil {
		return 0, err
	}

	// Get return data from context
	programID, data := s.ctx.GetReturnData()

	// If no return data, return 0
	if len(data) == 0 {
		return 0, nil
	}

	// Write program ID if address is non-zero
	if programIDAddr != 0 {
		if err := vm.WriteMemory(programIDAddr, programID[:]); err != nil {
			return 0, err
		}
	}

	// Write data to buffer (truncate if buffer is smaller)
	copyLen := uint64(len(data))
	if copyLen > bufLen {
		copyLen = bufLen
	}

	if copyLen > 0 && bufAddr != 0 {
		if err := vm.WriteMemory(bufAddr, data[:copyLen]); err != nil {
			return 0, err
		}
	}

	// Return actual data length
	return uint64(len(data)), nil
}

// SolGetStackHeight implements the sol_get_stack_height syscall.
// Returns the current CPI depth (stack height).
//
// Returns: current depth (0 for top-level, up to MaxCPIDepth).
type SolGetStackHeight struct {
	ctx *ExecutionContext
}

// NewSolGetStackHeight creates a new sol_get_stack_height handler.
func NewSolGetStackHeight(ctx *ExecutionContext) *SolGetStackHeight {
	return &SolGetStackHeight{ctx: ctx}
}

// Invoke implements SyscallHandler.
func (s *SolGetStackHeight) Invoke(vm *sbpf.VM, r1, r2, r3, r4, r5 uint64) (uint64, error) {
	// Minimal compute cost
	if err := s.ctx.ConsumeComputeUnits(5); err != nil {
		return 0, err
	}

	return uint64(s.ctx.Depth), nil
}

// RegisterCPISyscalls registers all CPI-related syscalls.
func RegisterCPISyscalls(registry *Registry, ctx *ExecutionContext) {
	registry.RegisterSyscall("sol_invoke_signed_c", NewSolInvokeSignedC(ctx))
	registry.RegisterSyscall("sol_invoke_signed_rust", NewSolInvokeSignedRust(ctx))
	registry.RegisterSyscall("sol_set_return_data", NewSolSetReturnData(ctx))
	registry.RegisterSyscall("sol_get_return_data", NewSolGetReturnData(ctx))
	registry.RegisterSyscall("sol_get_stack_height", NewSolGetStackHeight(ctx))
}

// Well-known CPI syscall hashes
var (
	SyscallInvokeSignedCHash    = MurmurHash3("sol_invoke_signed_c")
	SyscallInvokeSignedRustHash = MurmurHash3("sol_invoke_signed_rust")
	SyscallSetReturnDataHash    = MurmurHash3("sol_set_return_data")
	SyscallGetReturnDataHash    = MurmurHash3("sol_get_return_data")
	SyscallGetStackHeightHash   = MurmurHash3("sol_get_stack_height")
)
