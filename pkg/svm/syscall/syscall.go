// Package syscall provides the Solana syscall interface for the SVM.
// Syscalls allow BPF programs to interact with the runtime environment.
package syscall

import (
	"fmt"
	"sync"

	"github.com/fortiblox/x1-nimbus/pkg/svm/sbpf"
)

// Syscall error codes (returned in r0)
const (
	SyscallSuccess              uint64 = 0
	SyscallErrorInvalidArgument uint64 = 1
	SyscallErrorInvalidMemory   uint64 = 2
	SyscallErrorNotAllowed      uint64 = 3
	SyscallErrorComputeExceeded uint64 = 4
	SyscallErrorPanic           uint64 = 5
	SyscallErrorAbort           uint64 = 6
)

// Compute unit costs for syscalls
const (
	CULogBase         uint64 = 100
	CULogPerByte      uint64 = 1
	CULog64           uint64 = 100
	CULogPubkey       uint64 = 100
	CULogComputeUnits uint64 = 100
	CULogData         uint64 = 100
	CUMemoryOp        uint64 = 10
	CUMemoryPerByte   uint64 = 1
	CUSHA256Base      uint64 = 85
	CUSHA256PerByte   uint64 = 1
	CUKeccak256Base   uint64 = 130
	CUKeccak256PerByte uint64 = 1
	CUBlake3Base      uint64 = 29
	CUBlake3PerByte   uint64 = 1
	CUCreatePDA       uint64 = 1500
	CUFindPDA         uint64 = 1500
	CUFindPDAPerIter  uint64 = 50
)

// SyscallHandler defines the interface for syscall implementations.
// Each syscall receives the VM and up to 5 64-bit arguments.
type SyscallHandler interface {
	// Invoke executes the syscall with the given arguments.
	// Returns the result value (placed in r0) and any error.
	Invoke(vm *sbpf.VM, r1, r2, r3, r4, r5 uint64) (uint64, error)
}

// SyscallFunc is a function adapter for SyscallHandler.
type SyscallFunc func(vm *sbpf.VM, r1, r2, r3, r4, r5 uint64) (uint64, error)

// Invoke implements SyscallHandler.
func (f SyscallFunc) Invoke(vm *sbpf.VM, r1, r2, r3, r4, r5 uint64) (uint64, error) {
	return f(vm, r1, r2, r3, r4, r5)
}

// Registry maintains mappings from syscall hashes to handlers.
type Registry struct {
	mu       sync.RWMutex
	handlers map[uint32]SyscallHandler
	names    map[uint32]string // For debugging
}

// NewRegistry creates a new syscall registry.
func NewRegistry() *Registry {
	return &Registry{
		handlers: make(map[uint32]SyscallHandler),
		names:    make(map[uint32]string),
	}
}

// RegisterSyscall registers a syscall handler by name.
// The syscall ID is computed as the MurmurHash3 of the name.
func (r *Registry) RegisterSyscall(name string, handler SyscallHandler) {
	hash := MurmurHash3(name)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[hash] = handler
	r.names[hash] = name
}

// RegisterSyscallFunc registers a syscall function by name.
func (r *Registry) RegisterSyscallFunc(name string, fn SyscallFunc) {
	r.RegisterSyscall(name, fn)
}

// Dispatch invokes the syscall handler for the given hash.
func (r *Registry) Dispatch(hash uint32, vm *sbpf.VM, args ...uint64) (uint64, error) {
	r.mu.RLock()
	handler, ok := r.handlers[hash]
	name := r.names[hash]
	r.mu.RUnlock()

	if !ok {
		return SyscallErrorNotAllowed, fmt.Errorf("unknown syscall: 0x%08x", hash)
	}

	// Pad args to 5 elements
	var r1, r2, r3, r4, r5 uint64
	if len(args) > 0 {
		r1 = args[0]
	}
	if len(args) > 1 {
		r2 = args[1]
	}
	if len(args) > 2 {
		r3 = args[2]
	}
	if len(args) > 3 {
		r4 = args[3]
	}
	if len(args) > 4 {
		r5 = args[4]
	}

	result, err := handler.Invoke(vm, r1, r2, r3, r4, r5)
	if err != nil {
		return result, fmt.Errorf("syscall %s (0x%08x): %w", name, hash, err)
	}
	return result, nil
}

// GetHandler returns the handler for a syscall hash.
func (r *Registry) GetHandler(hash uint32) (SyscallHandler, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.handlers[hash]
	return h, ok
}

// GetName returns the name for a syscall hash.
func (r *Registry) GetName(hash uint32) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n, ok := r.names[hash]
	return n, ok
}

// ListSyscalls returns all registered syscall names and hashes.
func (r *Registry) ListSyscalls() map[string]uint32 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make(map[string]uint32, len(r.names))
	for hash, name := range r.names {
		result[name] = hash
	}
	return result
}

// MurmurHash3 computes a 32-bit MurmurHash3 hash of the input string.
// This is used to compute syscall IDs from their names.
// Reference: https://en.wikipedia.org/wiki/MurmurHash
func MurmurHash3(key string) uint32 {
	data := []byte(key)
	length := len(data)

	const (
		c1   uint32 = 0xcc9e2d51
		c2   uint32 = 0x1b873593
		seed uint32 = 0
	)

	h1 := seed
	nblocks := length / 4

	// Body
	for i := 0; i < nblocks; i++ {
		k1 := uint32(data[i*4]) |
			uint32(data[i*4+1])<<8 |
			uint32(data[i*4+2])<<16 |
			uint32(data[i*4+3])<<24

		k1 *= c1
		k1 = rotl32(k1, 15)
		k1 *= c2

		h1 ^= k1
		h1 = rotl32(h1, 13)
		h1 = h1*5 + 0xe6546b64
	}

	// Tail
	tail := data[nblocks*4:]
	var k1 uint32

	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = rotl32(k1, 15)
		k1 *= c2
		h1 ^= k1
	}

	// Finalization
	h1 ^= uint32(length)
	h1 = fmix32(h1)

	return h1
}

// rotl32 performs a 32-bit left rotation.
func rotl32(x uint32, r uint8) uint32 {
	return (x << r) | (x >> (32 - r))
}

// fmix32 is the finalization mix for MurmurHash3.
func fmix32(h uint32) uint32 {
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

// DefaultRegistry is the global default syscall registry.
var DefaultRegistry = NewRegistry()

// RegisterDefaultSyscalls registers all standard Solana syscalls.
func RegisterDefaultSyscalls(ctx *ExecutionContext) {
	// Logging syscalls
	DefaultRegistry.RegisterSyscall("sol_log_", NewSolLog(ctx))
	DefaultRegistry.RegisterSyscall("sol_log_64_", NewSolLog64(ctx))
	DefaultRegistry.RegisterSyscall("sol_log_pubkey", NewSolLogPubkey(ctx))
	DefaultRegistry.RegisterSyscall("sol_log_compute_units_", NewSolLogComputeUnits(ctx))
	DefaultRegistry.RegisterSyscall("sol_log_data", NewSolLogData(ctx))

	// Memory syscalls
	DefaultRegistry.RegisterSyscall("sol_memcpy_", SyscallFunc(SolMemcpy))
	DefaultRegistry.RegisterSyscall("sol_memmove_", SyscallFunc(SolMemmove))
	DefaultRegistry.RegisterSyscall("sol_memset_", SyscallFunc(SolMemset))
	DefaultRegistry.RegisterSyscall("sol_memcmp_", SyscallFunc(SolMemcmp))
	DefaultRegistry.RegisterSyscall("sol_alloc_free_", SyscallFunc(SolAllocFree))

	// Hash syscalls
	DefaultRegistry.RegisterSyscall("sol_sha256", SyscallFunc(SolSHA256))
	DefaultRegistry.RegisterSyscall("sol_keccak256", SyscallFunc(SolKeccak256))
	DefaultRegistry.RegisterSyscall("sol_blake3", SyscallFunc(SolBlake3))

	// PDA syscalls
	DefaultRegistry.RegisterSyscall("sol_create_program_address", NewSolCreateProgramAddress(ctx))
	DefaultRegistry.RegisterSyscall("sol_try_find_program_address", NewSolTryFindProgramAddress(ctx))

	// CPI syscalls
	RegisterCPISyscalls(DefaultRegistry, ctx)
}

// Well-known syscall hashes (precomputed for reference)
var (
	SyscallLogHash           = MurmurHash3("sol_log_")            // 0x207559bd
	SyscallLog64Hash         = MurmurHash3("sol_log_64_")         // 0x7ef088ca
	SyscallLogPubkeyHash     = MurmurHash3("sol_log_pubkey")      // 0x7317b434
	SyscallLogCUHash         = MurmurHash3("sol_log_compute_units_")
	SyscallLogDataHash       = MurmurHash3("sol_log_data")
	SyscallMemcpyHash        = MurmurHash3("sol_memcpy_")         // 0x717cc4a3
	SyscallMemmoveHash       = MurmurHash3("sol_memmove_")        // 0x5fdcde31
	SyscallMemsetHash        = MurmurHash3("sol_memset_")         // 0x3770fb22
	SyscallMemcmpHash        = MurmurHash3("sol_memcmp_")         // 0x3c8b2ab9
	SyscallAllocFreeHash     = MurmurHash3("sol_alloc_free_")     // 0x83f00e8f
	SyscallSHA256Hash        = MurmurHash3("sol_sha256")          // 0x80e18a25
	SyscallKeccak256Hash     = MurmurHash3("sol_keccak256")       // 0x0d0b2696
	SyscallBlake3Hash        = MurmurHash3("sol_blake3")          // 0x78c61766
	SyscallCreatePDAHash     = MurmurHash3("sol_create_program_address")
	SyscallTryFindPDAHash    = MurmurHash3("sol_try_find_program_address")
)
