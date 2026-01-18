package replayer

import (
	"errors"
	"sync"

	"github.com/fortiblox/x1-nimbus/pkg/svm/programs/address_lookup_table"
	"github.com/fortiblox/x1-nimbus/pkg/svm/programs/bpf_loader"
	"github.com/fortiblox/x1-nimbus/pkg/svm/programs/compute_budget"
	"github.com/fortiblox/x1-nimbus/pkg/svm/programs/stake"
	"github.com/fortiblox/x1-nimbus/pkg/svm/programs/system"
	"github.com/fortiblox/x1-nimbus/pkg/svm/programs/token"
	"github.com/fortiblox/x1-nimbus/pkg/svm/programs/vote"
	"github.com/fortiblox/x1-nimbus/pkg/svm/syscall"
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// Program execution errors
var (
	// ErrProgramNotFound indicates the program is not registered.
	ErrProgramNotFound = errors.New("program not found")

	// ErrProgramExecutionFailed indicates program execution failed.
	ErrProgramExecutionFailed = errors.New("program execution failed")

	// ErrInvalidInstruction indicates an invalid instruction.
	ErrInvalidInstruction = errors.New("invalid instruction")

	// ErrAccountMismatch indicates an account mismatch.
	ErrAccountMismatch = errors.New("account mismatch")
)

// ProgramExecutor defines the interface for program execution.
// Programs implement this interface to handle instructions.
type ProgramExecutor interface {
	// Execute executes an instruction within the given context.
	// Returns an error if execution fails.
	Execute(ctx *syscall.ExecutionContext, instruction *types.Instruction) error
}

// ProgramExecutorFunc is a function adapter for ProgramExecutor.
type ProgramExecutorFunc func(ctx *syscall.ExecutionContext, instruction *types.Instruction) error

// Execute implements ProgramExecutor.
func (f ProgramExecutorFunc) Execute(ctx *syscall.ExecutionContext, instruction *types.Instruction) error {
	return f(ctx, instruction)
}

// ProgramRegistry manages the mapping of program IDs to their executors.
// It supports both native programs (built-in) and BPF programs.
type ProgramRegistry struct {
	mu       sync.RWMutex
	programs map[types.Pubkey]ProgramExecutor
	names    map[types.Pubkey]string
}

// NewProgramRegistry creates a new program registry.
func NewProgramRegistry() *ProgramRegistry {
	return &ProgramRegistry{
		programs: make(map[types.Pubkey]ProgramExecutor),
		names:    make(map[types.Pubkey]string),
	}
}

// RegisterProgram registers a program executor for the given program ID.
func (r *ProgramRegistry) RegisterProgram(id types.Pubkey, executor ProgramExecutor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.programs[id] = executor
}

// RegisterProgramWithName registers a program executor with a name for debugging.
func (r *ProgramRegistry) RegisterProgramWithName(id types.Pubkey, name string, executor ProgramExecutor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.programs[id] = executor
	r.names[id] = name
}

// RegisterProgramFunc registers a function as a program executor.
func (r *ProgramRegistry) RegisterProgramFunc(id types.Pubkey, fn ProgramExecutorFunc) {
	r.RegisterProgram(id, fn)
}

// GetProgram returns the executor for the given program ID.
func (r *ProgramRegistry) GetProgram(id types.Pubkey) (ProgramExecutor, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	executor, ok := r.programs[id]
	return executor, ok
}

// GetProgramName returns the name for the given program ID.
func (r *ProgramRegistry) GetProgramName(id types.Pubkey) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	name, ok := r.names[id]
	return name, ok
}

// HasProgram checks if a program is registered.
func (r *ProgramRegistry) HasProgram(id types.Pubkey) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.programs[id]
	return ok
}

// UnregisterProgram removes a program from the registry.
func (r *ProgramRegistry) UnregisterProgram(id types.Pubkey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.programs, id)
	delete(r.names, id)
}

// ListPrograms returns all registered program IDs.
func (r *ProgramRegistry) ListPrograms() []types.Pubkey {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]types.Pubkey, 0, len(r.programs))
	for id := range r.programs {
		ids = append(ids, id)
	}
	return ids
}

// Count returns the number of registered programs.
func (r *ProgramRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.programs)
}

// Clear removes all registered programs.
func (r *ProgramRegistry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.programs = make(map[types.Pubkey]ProgramExecutor)
	r.names = make(map[types.Pubkey]string)
}

// Clone creates a copy of the registry.
func (r *ProgramRegistry) Clone() *ProgramRegistry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	clone := &ProgramRegistry{
		programs: make(map[types.Pubkey]ProgramExecutor, len(r.programs)),
		names:    make(map[types.Pubkey]string, len(r.names)),
	}

	for id, executor := range r.programs {
		clone.programs[id] = executor
	}
	for id, name := range r.names {
		clone.names[id] = name
	}

	return clone
}

// NativeProgram wraps a native program implementation.
type NativeProgram struct {
	name     string
	executor ProgramExecutor
}

// NewNativeProgram creates a new native program wrapper.
func NewNativeProgram(name string, executor ProgramExecutor) *NativeProgram {
	return &NativeProgram{
		name:     name,
		executor: executor,
	}
}

// Name returns the program name.
func (np *NativeProgram) Name() string {
	return np.name
}

// Execute implements ProgramExecutor.
func (np *NativeProgram) Execute(ctx *syscall.ExecutionContext, instruction *types.Instruction) error {
	return np.executor.Execute(ctx, instruction)
}

// BPFProgram represents a BPF program loaded from account data.
// This is a placeholder for the actual BPF VM integration.
type BPFProgram struct {
	programID types.Pubkey
	data      []byte
}

// NewBPFProgram creates a new BPF program from account data.
func NewBPFProgram(programID types.Pubkey, data []byte) *BPFProgram {
	return &BPFProgram{
		programID: programID,
		data:      data,
	}
}

// Execute implements ProgramExecutor for BPF programs.
// This is a placeholder - actual BPF execution requires the SVM.
func (bp *BPFProgram) Execute(ctx *syscall.ExecutionContext, instruction *types.Instruction) error {
	// TODO: Integrate with SVM/sBPF VM for actual BPF execution
	// For now, this returns an error indicating BPF execution is not yet supported
	return errors.New("BPF program execution not yet implemented")
}

// ProgramID returns the program's public key.
func (bp *BPFProgram) ProgramID() types.Pubkey {
	return bp.programID
}

// Data returns the program's executable data.
func (bp *BPFProgram) Data() []byte {
	return bp.data
}

// RegisterNativePrograms registers all native programs in the registry.
// This includes System, Token, Vote, Stake, and other built-in programs.
func RegisterNativePrograms(registry *ProgramRegistry) {
	// System Program
	registry.RegisterProgramWithName(types.SystemProgramID, "System Program",
		ProgramExecutorFunc(executeSystemProgram))

	// Compute Budget Program
	registry.RegisterProgramWithName(types.ComputeBudgetProgramID, "Compute Budget Program",
		ProgramExecutorFunc(executeComputeBudgetProgram))

	// Token Program (SPL Token)
	registry.RegisterProgramWithName(types.TokenProgramID, "Token Program",
		ProgramExecutorFunc(executeTokenProgram))

	// Token-2022 Program
	registry.RegisterProgramWithName(types.Token2022ProgramID, "Token-2022 Program",
		ProgramExecutorFunc(executeToken2022Program))

	// Associated Token Program
	registry.RegisterProgramWithName(types.AssociatedTokenProgramID, "Associated Token Program",
		ProgramExecutorFunc(executeAssociatedTokenProgram))

	// Vote Program
	registry.RegisterProgramWithName(types.VoteProgramID, "Vote Program",
		ProgramExecutorFunc(executeVoteProgram))

	// Stake Program
	registry.RegisterProgramWithName(types.StakeProgramID, "Stake Program",
		ProgramExecutorFunc(executeStakeProgram))

	// Config Program
	registry.RegisterProgramWithName(types.ConfigProgramID, "Config Program",
		ProgramExecutorFunc(executeConfigProgram))

	// BPF Loader (v1)
	registry.RegisterProgramWithName(types.BPFLoaderProgramID, "BPF Loader",
		ProgramExecutorFunc(executeBPFLoaderProgram))

	// BPF Loader v2
	registry.RegisterProgramWithName(types.BPFLoader2ProgramID, "BPF Loader v2",
		ProgramExecutorFunc(executeBPFLoader2Program))

	// BPF Loader Upgradeable
	registry.RegisterProgramWithName(types.BPFLoaderUpgradeableProgramID, "BPF Loader Upgradeable",
		ProgramExecutorFunc(executeBPFLoaderUpgradeableProgram))

	// Address Lookup Table Program
	registry.RegisterProgramWithName(types.AddressLookupTableProgramID, "Address Lookup Table Program",
		ProgramExecutorFunc(executeAddressLookupTableProgram))

	// Ed25519 Precompile
	registry.RegisterProgramWithName(types.Ed25519ProgramID, "Ed25519 Precompile",
		ProgramExecutorFunc(executeEd25519Program))

	// Secp256k1 Precompile
	registry.RegisterProgramWithName(types.Secp256k1ProgramID, "Secp256k1 Precompile",
		ProgramExecutorFunc(executeSecp256k1Program))
}

// Native program execution stubs
// These will be implemented with full logic in separate packages

func executeSystemProgram(ctx *syscall.ExecutionContext, instruction *types.Instruction) error {
	prog := system.New()
	return prog.Execute(ctx, instruction.Data)
}

func executeComputeBudgetProgram(ctx *syscall.ExecutionContext, instruction *types.Instruction) error {
	prog := compute_budget.New()
	return prog.Execute(ctx, instruction.Data)
}

func executeTokenProgram(ctx *syscall.ExecutionContext, instruction *types.Instruction) error {
	prog := token.New()
	return prog.Execute(ctx, instruction)
}

func executeToken2022Program(ctx *syscall.ExecutionContext, instruction *types.Instruction) error {
	// Token-2022 is similar to Token but with extensions
	// For now, use the same token program implementation
	prog := token.New()
	return prog.Execute(ctx, instruction)
}

func executeAssociatedTokenProgram(ctx *syscall.ExecutionContext, instruction *types.Instruction) error {
	// Associated Token Program creates/finds associated token accounts
	// This is typically a thin wrapper that calls Token Program
	// For now, return success as it mainly does PDA derivation
	return nil
}

func executeVoteProgram(ctx *syscall.ExecutionContext, instruction *types.Instruction) error {
	prog := vote.New()
	return prog.Execute(ctx, instruction.Data)
}

func executeStakeProgram(ctx *syscall.ExecutionContext, instruction *types.Instruction) error {
	prog := stake.New()
	return prog.Execute(ctx, instruction.Data)
}

func executeConfigProgram(ctx *syscall.ExecutionContext, instruction *types.Instruction) error {
	// TODO: Implement Config Program logic
	return nil
}

func executeBPFLoaderProgram(ctx *syscall.ExecutionContext, instruction *types.Instruction) error {
	// BPF Loader v1 is deprecated, but we still need to handle it
	// For now, return success as most operations are no-ops
	return nil
}

func executeBPFLoader2Program(ctx *syscall.ExecutionContext, instruction *types.Instruction) error {
	// BPF Loader v2 handles immutable programs
	// Most operations are handled at the loader level, not instruction level
	return nil
}

func executeBPFLoaderUpgradeableProgram(ctx *syscall.ExecutionContext, instruction *types.Instruction) error {
	prog := bpf_loader.New()
	return prog.Execute(ctx, instruction)
}

func executeAddressLookupTableProgram(ctx *syscall.ExecutionContext, instruction *types.Instruction) error {
	prog := address_lookup_table.New()
	return prog.Execute(ctx, instruction.Data)
}

func executeEd25519Program(ctx *syscall.ExecutionContext, instruction *types.Instruction) error {
	// Ed25519 signature verification precompile
	// Verification is done during transaction processing, not here
	return nil
}

func executeSecp256k1Program(ctx *syscall.ExecutionContext, instruction *types.Instruction) error {
	// Secp256k1 signature recovery precompile
	// Verification is done during transaction processing, not here
	return nil
}
