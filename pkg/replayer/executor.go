package replayer

import (
	"errors"
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/svm/syscall"
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// Executor errors
var (
	// ErrExecutionFailed indicates transaction execution failed.
	ErrExecutionFailed = errors.New("transaction execution failed")

	// ErrInstructionFailed indicates instruction execution failed.
	ErrInstructionFailed = errors.New("instruction execution failed")

	// ErrProgramNotExecutable indicates the program is not executable.
	ErrProgramNotExecutable = errors.New("program is not executable")

	// ErrAccountNotProvided indicates a required account was not provided.
	ErrAccountNotProvided = errors.New("account not provided")

	// ErrInvalidProgramID indicates an invalid program ID.
	ErrInvalidProgramID = errors.New("invalid program ID")

	// ErrMaxCPIDepthExceeded indicates the maximum CPI depth was exceeded.
	ErrMaxCPIDepthExceeded = errors.New("maximum CPI depth exceeded")
)

// Execution limits
const (
	// MaxCPIDepth is the maximum depth for cross-program invocations.
	MaxCPIDepth = 4

	// DefaultComputeUnits is the default compute unit limit per transaction.
	DefaultComputeUnits = 200_000

	// MaxComputeUnits is the maximum compute unit limit per transaction.
	MaxComputeUnits = 1_400_000
)

// AccountsDB is the interface for account storage.
// This allows the executor to load and store account data.
type AccountsDB interface {
	// GetAccount retrieves an account by its public key.
	GetAccount(pubkey types.Pubkey) (*types.Account, error)

	// SetAccount stores an account.
	SetAccount(pubkey types.Pubkey, account *types.Account) error

	// HasAccount checks if an account exists.
	HasAccount(pubkey types.Pubkey) bool
}

// Executor handles transaction and instruction execution.
type Executor struct {
	// accountsDB provides account storage access.
	accountsDB AccountsDB

	// programRegistry contains registered program executors.
	programRegistry *ProgramRegistry

	// computeUnitsLimit is the compute unit limit for the current transaction.
	computeUnitsLimit types.ComputeUnits

	// currentSlot is the current slot number.
	currentSlot types.Slot

	// currentBlockhash is the current blockhash.
	currentBlockhash types.Hash
}

// NewExecutor creates a new transaction executor.
func NewExecutor(db AccountsDB, registry *ProgramRegistry) *Executor {
	return &Executor{
		accountsDB:        db,
		programRegistry:   registry,
		computeUnitsLimit: DefaultComputeUnits,
	}
}

// SetComputeUnitsLimit sets the compute units limit for transactions.
func (e *Executor) SetComputeUnitsLimit(limit types.ComputeUnits) {
	e.computeUnitsLimit = limit
}

// SetCurrentSlot sets the current slot.
func (e *Executor) SetCurrentSlot(slot types.Slot) {
	e.currentSlot = slot
}

// SetCurrentBlockhash sets the current blockhash.
func (e *Executor) SetCurrentBlockhash(hash types.Hash) {
	e.currentBlockhash = hash
}

// ExecuteTransaction executes a complete transaction.
func (e *Executor) ExecuteTransaction(tx *types.Transaction) (*types.TransactionResult, error) {
	result := &types.TransactionResult{
		Success:       false,
		Logs:          make([]string, 0),
		AccountDeltas: make([]types.AccountDelta, 0),
	}

	// Validate transaction
	if tx == nil {
		result.Error = errors.New("nil transaction")
		return result, nil
	}

	if len(tx.Message.Instructions) == 0 {
		result.Error = errors.New("transaction has no instructions")
		return result, nil
	}

	// Load accounts referenced by the transaction
	accounts, err := e.loadTransactionAccounts(tx)
	if err != nil {
		result.Error = fmt.Errorf("failed to load accounts: %w", err)
		return result, nil
	}

	// Create snapshots of accounts before execution for delta tracking
	accountSnapshots := make(map[types.Pubkey]*types.Account)
	for _, acc := range accounts {
		accountSnapshots[acc.Pubkey] = accountInfoToAccount(acc)
	}

	// Execute each instruction in order
	for i, compiledIx := range tx.Message.Instructions {
		instruction, err := e.decompileInstruction(tx, &compiledIx)
		if err != nil {
			result.Error = fmt.Errorf("failed to decompile instruction %d: %w", i, err)
			return result, nil
		}

		// Create execution context for the instruction
		ctx := e.createExecutionContext(instruction, accounts)

		// Execute the instruction
		err = e.ExecuteInstruction(ctx, instruction)
		if err != nil {
			result.Error = fmt.Errorf("instruction %d failed: %w", i, err)
			result.Logs = append(result.Logs, ctx.GetLogs()...)
			result.ComputeUnits = types.ComputeUnits(ctx.GetComputeUnitsConsumed())
			return result, nil
		}

		// Collect logs
		result.Logs = append(result.Logs, ctx.GetLogs()...)
		result.ComputeUnits = types.ComputeUnits(ctx.GetComputeUnitsConsumed())

		// Collect return data
		if len(ctx.ReturnData) > 0 {
			result.ReturnData = ctx.ReturnData
		}
	}

	// Compute account deltas
	for pubkey, oldAccount := range accountSnapshots {
		newAccount, err := e.accountsDB.GetAccount(pubkey)
		if err != nil {
			// Account may have been deleted
			newAccount = nil
		}

		// Check if account changed
		if !accountsEqual(oldAccount, newAccount) {
			result.AccountDeltas = append(result.AccountDeltas, types.AccountDelta{
				Pubkey:     pubkey,
				OldAccount: oldAccount,
				NewAccount: newAccount,
			})
		}
	}

	result.Success = true
	return result, nil
}

// ExecuteInstruction executes a single instruction.
func (e *Executor) ExecuteInstruction(ctx *syscall.ExecutionContext, instruction *types.Instruction) error {
	if instruction == nil {
		return ErrInvalidInstruction
	}

	// Check CPI depth
	if ctx.Depth > MaxCPIDepth {
		return ErrMaxCPIDepthExceeded
	}

	// Get the program executor
	executor, ok := e.programRegistry.GetProgram(instruction.ProgramID)
	if !ok {
		// Check if it's a native program that should exist
		if instruction.ProgramID.IsNativeProgram() {
			return fmt.Errorf("%w: native program %s not registered",
				ErrProgramNotFound, instruction.ProgramID.String())
		}

		// For non-native programs, try to load as BPF program
		return e.executeBPFProgram(ctx, instruction)
	}

	// Execute the program
	return executor.Execute(ctx, instruction)
}

// executeBPFProgram executes a BPF program using the sBPF VM.
func (e *Executor) executeBPFProgram(ctx *syscall.ExecutionContext, instruction *types.Instruction) error {
	// Create the BPF executor with the accounts database and execution context
	bpfExecutor := NewBPFExecutor(e.accountsDB, ctx)

	// Execute the BPF program
	err := bpfExecutor.Execute(instruction.ProgramID, instruction)
	if err != nil {
		return fmt.Errorf("BPF execution failed: %w", err)
	}

	return nil
}

// loadTransactionAccounts loads all accounts referenced by a transaction.
func (e *Executor) loadTransactionAccounts(tx *types.Transaction) ([]*syscall.AccountInfo, error) {
	accounts := make([]*syscall.AccountInfo, len(tx.Message.AccountKeys))

	numSigners := int(tx.Message.Header.NumRequiredSignatures)
	numReadonlySigned := int(tx.Message.Header.NumReadonlySignedAccounts)
	numReadonlyUnsigned := int(tx.Message.Header.NumReadonlyUnsignedAccounts)
	numAccounts := len(tx.Message.AccountKeys)

	for i, pubkey := range tx.Message.AccountKeys {
		account, err := e.accountsDB.GetAccount(pubkey)
		if err != nil || account == nil {
			// Account doesn't exist - create empty account
			account = &types.Account{
				Lamports: 0,
				Data:     nil,
				Owner:    types.SystemProgramID,
			}
		}

		// Determine if account is signer
		isSigner := i < numSigners

		// Determine if account is writable
		// Writable accounts are: signed accounts (except readonly) + unsigned accounts (except readonly)
		isWritable := false
		if isSigner {
			// Signed accounts: writable if not in the readonly signed range
			isWritable = i < (numSigners - numReadonlySigned)
		} else {
			// Unsigned accounts: writable if not in the readonly unsigned range
			unsignedIndex := i - numSigners
			numUnsignedWritable := numAccounts - numSigners - numReadonlyUnsigned
			isWritable = unsignedIndex < numUnsignedWritable
		}

		lamports := uint64(account.Lamports)
		accounts[i] = &syscall.AccountInfo{
			Pubkey:     pubkey,
			Lamports:   &lamports,
			Data:       account.Data,
			Owner:      account.Owner,
			Executable: account.Executable,
			RentEpoch:  uint64(account.RentEpoch),
			IsSigner:   isSigner,
			IsWritable: isWritable,
		}
	}

	return accounts, nil
}

// decompileInstruction converts a compiled instruction to a full instruction.
func (e *Executor) decompileInstruction(tx *types.Transaction, compiled *types.CompiledInstruction) (*types.Instruction, error) {
	if int(compiled.ProgramIDIndex) >= len(tx.Message.AccountKeys) {
		return nil, fmt.Errorf("program ID index out of bounds: %d", compiled.ProgramIDIndex)
	}

	programID := tx.Message.AccountKeys[compiled.ProgramIDIndex]

	accounts := make([]types.AccountMeta, len(compiled.AccountIndices))
	numSigners := int(tx.Message.Header.NumRequiredSignatures)
	numReadonlySigned := int(tx.Message.Header.NumReadonlySignedAccounts)
	numReadonlyUnsigned := int(tx.Message.Header.NumReadonlyUnsignedAccounts)
	numAccounts := len(tx.Message.AccountKeys)

	for i, idx := range compiled.AccountIndices {
		if int(idx) >= len(tx.Message.AccountKeys) {
			return nil, fmt.Errorf("account index out of bounds: %d", idx)
		}

		accountIdx := int(idx)
		isSigner := accountIdx < numSigners

		isWritable := false
		if isSigner {
			isWritable = accountIdx < (numSigners - numReadonlySigned)
		} else {
			unsignedIndex := accountIdx - numSigners
			numUnsignedWritable := numAccounts - numSigners - numReadonlyUnsigned
			isWritable = unsignedIndex < numUnsignedWritable
		}

		accounts[i] = types.AccountMeta{
			Pubkey:     tx.Message.AccountKeys[idx],
			IsSigner:   isSigner,
			IsWritable: isWritable,
		}
	}

	return &types.Instruction{
		ProgramID: programID,
		Accounts:  accounts,
		Data:      compiled.Data,
	}, nil
}

// createExecutionContext creates an execution context for an instruction.
func (e *Executor) createExecutionContext(instruction *types.Instruction, accounts []*syscall.AccountInfo) *syscall.ExecutionContext {
	// Filter accounts to only those referenced by the instruction
	instructionAccounts := make([]*syscall.AccountInfo, len(instruction.Accounts))
	for i, meta := range instruction.Accounts {
		for _, acc := range accounts {
			if acc.Pubkey == meta.Pubkey {
				// Clone the account info with instruction-specific flags
				cloned := acc.Clone()
				cloned.IsSigner = meta.IsSigner
				cloned.IsWritable = meta.IsWritable
				instructionAccounts[i] = cloned
				break
			}
		}
	}

	return syscall.NewExecutionContext(
		instruction.ProgramID,
		instructionAccounts,
		instruction.Data,
		uint64(e.computeUnitsLimit),
	)
}

// accountInfoToAccount converts a syscall.AccountInfo to a types.Account.
func accountInfoToAccount(info *syscall.AccountInfo) *types.Account {
	if info == nil {
		return nil
	}
	var data []byte
	if info.Data != nil {
		data = make([]byte, len(info.Data))
		copy(data, info.Data)
	}
	return &types.Account{
		Lamports:   types.Lamports(*info.Lamports),
		Data:       data,
		Owner:      info.Owner,
		Executable: info.Executable,
		RentEpoch:  types.Epoch(info.RentEpoch),
	}
}

// accountsEqual checks if two accounts are equal.
func accountsEqual(a, b *types.Account) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if a.Lamports != b.Lamports {
		return false
	}
	if a.Owner != b.Owner {
		return false
	}
	if a.Executable != b.Executable {
		return false
	}
	if len(a.Data) != len(b.Data) {
		return false
	}
	for i := range a.Data {
		if a.Data[i] != b.Data[i] {
			return false
		}
	}
	return true
}

// ExecutionResult contains detailed execution results.
type ExecutionResult struct {
	// Success indicates if execution was successful.
	Success bool

	// Error contains any error that occurred.
	Error error

	// Logs contains execution logs.
	Logs []string

	// ComputeUnitsConsumed is the total compute units used.
	ComputeUnitsConsumed uint64

	// ReturnData contains program return data.
	ReturnData []byte

	// AccountChanges tracks which accounts were modified.
	AccountChanges map[types.Pubkey]struct{}
}

// InstructionExecutionError contains details about an instruction execution failure.
type InstructionExecutionError struct {
	InstructionIndex int
	ProgramID        types.Pubkey
	Err              error
}

// Error implements the error interface.
func (e *InstructionExecutionError) Error() string {
	return fmt.Sprintf("instruction %d (program %s) failed: %v",
		e.InstructionIndex, e.ProgramID.String(), e.Err)
}

// Unwrap returns the underlying error.
func (e *InstructionExecutionError) Unwrap() error {
	return e.Err
}
