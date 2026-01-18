package syscall

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/fortiblox/x1-nimbus/pkg/svm/sbpf"
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// SolLog implements the sol_log_ syscall.
// Logs a string message from the program.
// Arguments:
//   r1: pointer to message string
//   r2: length of message
type SolLog struct {
	ctx *ExecutionContext
}

// NewSolLog creates a new sol_log_ handler.
func NewSolLog(ctx *ExecutionContext) *SolLog {
	return &SolLog{ctx: ctx}
}

// Invoke implements SyscallHandler.
func (s *SolLog) Invoke(vm *sbpf.VM, r1, r2, r3, r4, r5 uint64) (uint64, error) {
	// Compute cost: base + per-byte cost
	cost := CULogBase + r2*CULogPerByte
	if err := s.ctx.ConsumeComputeUnits(cost); err != nil {
		return SyscallErrorComputeExceeded, err
	}

	// Read the message from memory
	length := r2
	if length > MaxLogMessageLength {
		length = MaxLogMessageLength
	}
	msgBytes, err := vm.ReadMemory(r1, int(length))
	if err != nil {
		return SyscallErrorInvalidMemory, err
	}

	// Add to logs
	message := string(msgBytes)
	if err := s.ctx.AddLog(fmt.Sprintf("Program log: %s", message)); err != nil {
		// Don't fail on log overflow, just stop logging
		return SyscallSuccess, nil
	}

	return SyscallSuccess, nil
}

// SolLog64 implements the sol_log_64_ syscall.
// Logs up to 5 u64 values.
// Arguments:
//   r1-r5: u64 values to log
type SolLog64 struct {
	ctx *ExecutionContext
}

// NewSolLog64 creates a new sol_log_64_ handler.
func NewSolLog64(ctx *ExecutionContext) *SolLog64 {
	return &SolLog64{ctx: ctx}
}

// Invoke implements SyscallHandler.
func (s *SolLog64) Invoke(vm *sbpf.VM, r1, r2, r3, r4, r5 uint64) (uint64, error) {
	if err := s.ctx.ConsumeComputeUnits(CULog64); err != nil {
		return SyscallErrorComputeExceeded, err
	}

	message := fmt.Sprintf("Program log: %d, %d, %d, %d, %d",
		r1, r2, r3, r4, r5)

	if err := s.ctx.AddLog(message); err != nil {
		return SyscallSuccess, nil
	}

	return SyscallSuccess, nil
}

// SolLogPubkey implements the sol_log_pubkey syscall.
// Logs a 32-byte public key.
// Arguments:
//   r1: pointer to 32-byte pubkey
type SolLogPubkey struct {
	ctx *ExecutionContext
}

// NewSolLogPubkey creates a new sol_log_pubkey handler.
func NewSolLogPubkey(ctx *ExecutionContext) *SolLogPubkey {
	return &SolLogPubkey{ctx: ctx}
}

// Invoke implements SyscallHandler.
func (s *SolLogPubkey) Invoke(vm *sbpf.VM, r1, r2, r3, r4, r5 uint64) (uint64, error) {
	if err := s.ctx.ConsumeComputeUnits(CULogPubkey); err != nil {
		return SyscallErrorComputeExceeded, err
	}

	// Read 32 bytes from memory
	pubkeyBytes, err := vm.ReadMemory(r1, 32)
	if err != nil {
		return SyscallErrorInvalidMemory, err
	}

	pubkey, err := types.PubkeyFromBytes(pubkeyBytes)
	if err != nil {
		return SyscallErrorInvalidArgument, err
	}

	message := fmt.Sprintf("Program log: %s", pubkey.String())
	if err := s.ctx.AddLog(message); err != nil {
		return SyscallSuccess, nil
	}

	return SyscallSuccess, nil
}

// SolLogComputeUnits implements the sol_log_compute_units_ syscall.
// Logs the remaining compute units.
type SolLogComputeUnits struct {
	ctx *ExecutionContext
}

// NewSolLogComputeUnits creates a new sol_log_compute_units_ handler.
func NewSolLogComputeUnits(ctx *ExecutionContext) *SolLogComputeUnits {
	return &SolLogComputeUnits{ctx: ctx}
}

// Invoke implements SyscallHandler.
func (s *SolLogComputeUnits) Invoke(vm *sbpf.VM, r1, r2, r3, r4, r5 uint64) (uint64, error) {
	if err := s.ctx.ConsumeComputeUnits(CULogComputeUnits); err != nil {
		return SyscallErrorComputeExceeded, err
	}

	remaining := s.ctx.GetComputeUnitsRemaining()
	message := fmt.Sprintf("Program consumption: %d units remaining", remaining)

	if err := s.ctx.AddLog(message); err != nil {
		return SyscallSuccess, nil
	}

	return SyscallSuccess, nil
}

// SolLogData implements the sol_log_data syscall.
// Logs arbitrary data as base64-encoded slices.
// Arguments:
//   r1: pointer to array of data slice descriptors
//   r2: number of data slices
//
// Each slice descriptor is 16 bytes:
//   - 8 bytes: pointer to data
//   - 8 bytes: length of data
type SolLogData struct {
	ctx *ExecutionContext
}

// NewSolLogData creates a new sol_log_data handler.
func NewSolLogData(ctx *ExecutionContext) *SolLogData {
	return &SolLogData{ctx: ctx}
}

// Invoke implements SyscallHandler.
func (s *SolLogData) Invoke(vm *sbpf.VM, r1, r2, r3, r4, r5 uint64) (uint64, error) {
	if err := s.ctx.ConsumeComputeUnits(CULogData); err != nil {
		return SyscallErrorComputeExceeded, err
	}

	numSlices := r2
	if numSlices > 32 {
		numSlices = 32 // Limit number of slices
	}

	var parts []string
	mem := vm.Memory()

	for i := uint64(0); i < numSlices; i++ {
		// Each slice descriptor is 16 bytes (ptr + len)
		descriptorAddr := r1 + i*16

		// Read pointer (8 bytes)
		dataPtr, err := mem.ReadUint64(descriptorAddr)
		if err != nil {
			return SyscallErrorInvalidMemory, err
		}

		// Read length (8 bytes)
		dataLen, err := mem.ReadUint64(descriptorAddr + 8)
		if err != nil {
			return SyscallErrorInvalidMemory, err
		}

		// Limit data length
		if dataLen > 1024 {
			dataLen = 1024
		}

		// Read actual data
		data, err := vm.ReadMemory(dataPtr, int(dataLen))
		if err != nil {
			return SyscallErrorInvalidMemory, err
		}

		// Encode as base64
		parts = append(parts, base64.StdEncoding.EncodeToString(data))
	}

	message := fmt.Sprintf("Program data: %s", strings.Join(parts, " "))
	if err := s.ctx.AddLog(message); err != nil {
		return SyscallSuccess, nil
	}

	return SyscallSuccess, nil
}

// LogHex is a helper to log data as hex (used internally).
func LogHex(ctx *ExecutionContext, prefix string, data []byte) error {
	message := fmt.Sprintf("%s: %s", prefix, hex.EncodeToString(data))
	return ctx.AddLog(message)
}
