// Package sbpf implements the Solana BPF virtual machine for X1-Nimbus.
package sbpf

import (
	"errors"
	"fmt"
)

// Standard sBPF execution errors.
var (
	// ErrComputeExhausted is returned when the program runs out of compute units.
	ErrComputeExhausted = errors.New("compute units exhausted")

	// ErrAccessViolation is returned when the program attempts to access
	// memory outside its allowed regions or violates read/write permissions.
	ErrAccessViolation = errors.New("memory access violation")

	// ErrDivisionByZero is returned when a division or modulo by zero is attempted.
	ErrDivisionByZero = errors.New("division by zero")

	// ErrInvalidOpcode is returned when an unrecognized opcode is encountered.
	ErrInvalidOpcode = errors.New("invalid opcode")

	// ErrCallDepthExceeded is returned when the call stack exceeds the maximum depth.
	ErrCallDepthExceeded = errors.New("call depth exceeded")

	// ErrInvalidInstruction is returned when an instruction is malformed.
	ErrInvalidInstruction = errors.New("invalid instruction")

	// ErrStackOverflow is returned when the stack grows beyond its allocated region.
	ErrStackOverflow = errors.New("stack overflow")

	// ErrStackUnderflow is returned when attempting to pop from an empty stack.
	ErrStackUnderflow = errors.New("stack underflow")

	// ErrInvalidSyscall is returned when an unknown syscall is invoked.
	ErrInvalidSyscall = errors.New("invalid syscall")

	// ErrSyscallAbort is returned when the program calls abort.
	ErrSyscallAbort = errors.New("program aborted")

	// ErrSyscallPanic is returned when the program panics.
	ErrSyscallPanic = errors.New("program panicked")

	// ErrUnalignedAccess is returned when memory access is not properly aligned.
	ErrUnalignedAccess = errors.New("unaligned memory access")

	// ErrProgramTooLarge is returned when the program exceeds size limits.
	ErrProgramTooLarge = errors.New("program too large")

	// ErrInvalidProgramData is returned when the program data is malformed.
	ErrInvalidProgramData = errors.New("invalid program data")
)

// VMError wraps an error with additional VM state information.
type VMError struct {
	Err     error
	PC      uint64 // Program counter at time of error
	Opcode  uint8  // Opcode that caused the error (if applicable)
	Address uint64 // Memory address involved (if applicable)
}

// Error implements the error interface.
func (e *VMError) Error() string {
	if e.Address != 0 {
		return fmt.Sprintf("sbpf error at PC=%d opcode=0x%02x addr=0x%x: %v",
			e.PC, e.Opcode, e.Address, e.Err)
	}
	if e.Opcode != 0 {
		return fmt.Sprintf("sbpf error at PC=%d opcode=0x%02x: %v",
			e.PC, e.Opcode, e.Err)
	}
	return fmt.Sprintf("sbpf error at PC=%d: %v", e.PC, e.Err)
}

// Unwrap returns the underlying error.
func (e *VMError) Unwrap() error {
	return e.Err
}

// Is reports whether target matches this error.
func (e *VMError) Is(target error) bool {
	return errors.Is(e.Err, target)
}

// NewVMError creates a new VMError.
func NewVMError(err error, pc uint64, opcode uint8, address uint64) *VMError {
	return &VMError{
		Err:     err,
		PC:      pc,
		Opcode:  opcode,
		Address: address,
	}
}

// SyscallError represents an error returned from a syscall.
type SyscallError struct {
	Syscall string
	Code    uint64
	Message string
}

// Error implements the error interface.
func (e *SyscallError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("syscall %s failed with code %d: %s", e.Syscall, e.Code, e.Message)
	}
	return fmt.Sprintf("syscall %s failed with code %d", e.Syscall, e.Code)
}

// NewSyscallError creates a new SyscallError.
func NewSyscallError(syscall string, code uint64, message string) *SyscallError {
	return &SyscallError{
		Syscall: syscall,
		Code:    code,
		Message: message,
	}
}
