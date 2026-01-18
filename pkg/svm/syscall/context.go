package syscall

import (
	"errors"
	"fmt"
	"sync"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// Context errors
var (
	ErrAccountNotFound     = errors.New("account not found")
	ErrAccountNotWritable  = errors.New("account is not writable")
	ErrAccountNotSigner    = errors.New("account is not a signer")
	ErrInsufficientFunds   = errors.New("insufficient funds")
	ErrComputeExhausted    = errors.New("compute units exhausted")
	ErrMaxLogsExceeded     = errors.New("maximum log entries exceeded")
	ErrLogTooLong          = errors.New("log message too long")
	ErrInvalidAccountIndex = errors.New("invalid account index")
	ErrReadOnlyModified    = errors.New("read-only account was modified")
)

// Limits for execution
const (
	MaxLogMessages      = 64
	MaxLogMessageLength = 10000
	MaxReturnDataLength = 1024
	MaxInstructionData  = 1232
	MaxAccountDataSize  = 10 * 1024 * 1024 // 10MB
)

// AccountInfo represents account information available to a program.
type AccountInfo struct {
	Pubkey     types.Pubkey
	Lamports   *uint64 // Pointer allows modification detection
	Data       []byte
	Owner      types.Pubkey
	Executable bool
	RentEpoch  uint64
	IsSigner   bool
	IsWritable bool
}

// Clone creates a deep copy of AccountInfo.
func (a *AccountInfo) Clone() *AccountInfo {
	if a == nil {
		return nil
	}
	lamports := *a.Lamports
	clone := &AccountInfo{
		Pubkey:     a.Pubkey,
		Lamports:   &lamports,
		Owner:      a.Owner,
		Executable: a.Executable,
		RentEpoch:  a.RentEpoch,
		IsSigner:   a.IsSigner,
		IsWritable: a.IsWritable,
	}
	if a.Data != nil {
		clone.Data = make([]byte, len(a.Data))
		copy(clone.Data, a.Data)
	}
	return clone
}

// ExecutionContext holds the execution state for syscalls.
type ExecutionContext struct {
	mu sync.RWMutex

	// Program being executed
	ProgramID types.Pubkey

	// Accounts available to the instruction
	Accounts []*AccountInfo

	// Account index by pubkey for fast lookup
	accountIndex map[types.Pubkey]int

	// Instruction data
	InstructionData []byte

	// Compute meter
	computeUnits    uint64
	maxComputeUnits uint64

	// Execution logs
	logs    []string
	maxLogs int

	// Return data from the program
	ReturnData       []byte
	ReturnDataProgram types.Pubkey

	// Depth of CPI calls
	Depth int

	// Stack of callers for CPI
	CallerStack []types.Pubkey

	// Slot context
	Slot uint64

	// Recent blockhashes (for sysvars)
	RecentBlockhashes []types.Hash

	// Clock values
	UnixTimestamp int64
	Epoch         uint64
	EpochStartTimestamp int64

	// Rent parameters
	RentLamportsPerByteYear uint64
	RentExemptionThreshold  float64
}

// NewExecutionContext creates a new execution context.
func NewExecutionContext(programID types.Pubkey, accounts []*AccountInfo, instructionData []byte, computeUnits uint64) *ExecutionContext {
	ctx := &ExecutionContext{
		ProgramID:       programID,
		Accounts:        accounts,
		InstructionData: instructionData,
		computeUnits:    computeUnits,
		maxComputeUnits: computeUnits,
		accountIndex:    make(map[types.Pubkey]int),
		logs:            make([]string, 0, MaxLogMessages),
		maxLogs:         MaxLogMessages,
		Depth:           0,
		CallerStack:     make([]types.Pubkey, 0, 4),
		// Default rent parameters (mainnet values)
		RentLamportsPerByteYear: 3480,
		RentExemptionThreshold:  2.0,
	}

	// Build account index
	for i, acc := range accounts {
		ctx.accountIndex[acc.Pubkey] = i
	}

	return ctx
}

// ConsumeComputeUnits deducts compute units.
func (ctx *ExecutionContext) ConsumeComputeUnits(units uint64) error {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	if units > ctx.computeUnits {
		ctx.computeUnits = 0
		return ErrComputeExhausted
	}
	ctx.computeUnits -= units
	return nil
}

// GetComputeUnitsRemaining returns remaining compute units.
func (ctx *ExecutionContext) GetComputeUnitsRemaining() uint64 {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()
	return ctx.computeUnits
}

// GetComputeUnitsConsumed returns consumed compute units.
func (ctx *ExecutionContext) GetComputeUnitsConsumed() uint64 {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()
	return ctx.maxComputeUnits - ctx.computeUnits
}

// AddLog adds a log message.
func (ctx *ExecutionContext) AddLog(message string) error {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	if len(ctx.logs) >= ctx.maxLogs {
		return ErrMaxLogsExceeded
	}
	if len(message) > MaxLogMessageLength {
		return ErrLogTooLong
	}

	ctx.logs = append(ctx.logs, message)
	return nil
}

// GetLogs returns all log messages.
func (ctx *ExecutionContext) GetLogs() []string {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()
	logs := make([]string, len(ctx.logs))
	copy(logs, ctx.logs)
	return logs
}

// ClearLogs clears all log messages.
func (ctx *ExecutionContext) ClearLogs() {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	ctx.logs = ctx.logs[:0]
}

// GetAccount returns an account by pubkey.
func (ctx *ExecutionContext) GetAccount(pubkey types.Pubkey) (*AccountInfo, error) {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()

	idx, ok := ctx.accountIndex[pubkey]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrAccountNotFound, pubkey.String())
	}
	return ctx.Accounts[idx], nil
}

// GetAccountByIndex returns an account by index.
func (ctx *ExecutionContext) GetAccountByIndex(index int) (*AccountInfo, error) {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()

	if index < 0 || index >= len(ctx.Accounts) {
		return nil, fmt.Errorf("%w: %d", ErrInvalidAccountIndex, index)
	}
	return ctx.Accounts[index], nil
}

// GetWritableAccount returns a writable account by pubkey.
func (ctx *ExecutionContext) GetWritableAccount(pubkey types.Pubkey) (*AccountInfo, error) {
	acc, err := ctx.GetAccount(pubkey)
	if err != nil {
		return nil, err
	}
	if !acc.IsWritable {
		return nil, fmt.Errorf("%w: %s", ErrAccountNotWritable, pubkey.String())
	}
	return acc, nil
}

// GetSignerAccount returns a signer account by pubkey.
func (ctx *ExecutionContext) GetSignerAccount(pubkey types.Pubkey) (*AccountInfo, error) {
	acc, err := ctx.GetAccount(pubkey)
	if err != nil {
		return nil, err
	}
	if !acc.IsSigner {
		return nil, fmt.Errorf("%w: %s", ErrAccountNotSigner, pubkey.String())
	}
	return acc, nil
}

// AccountCount returns the number of accounts.
func (ctx *ExecutionContext) AccountCount() int {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()
	return len(ctx.Accounts)
}

// SetReturnData sets the return data for the instruction.
func (ctx *ExecutionContext) SetReturnData(programID types.Pubkey, data []byte) error {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	if len(data) > MaxReturnDataLength {
		data = data[:MaxReturnDataLength]
	}

	ctx.ReturnDataProgram = programID
	ctx.ReturnData = make([]byte, len(data))
	copy(ctx.ReturnData, data)
	return nil
}

// GetReturnData returns the current return data.
func (ctx *ExecutionContext) GetReturnData() (types.Pubkey, []byte) {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()
	data := make([]byte, len(ctx.ReturnData))
	copy(data, ctx.ReturnData)
	return ctx.ReturnDataProgram, data
}

// TransferLamports transfers lamports between accounts.
func (ctx *ExecutionContext) TransferLamports(from, to types.Pubkey, amount uint64) error {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	fromIdx, ok := ctx.accountIndex[from]
	if !ok {
		return fmt.Errorf("%w: %s", ErrAccountNotFound, from.String())
	}
	toIdx, ok := ctx.accountIndex[to]
	if !ok {
		return fmt.Errorf("%w: %s", ErrAccountNotFound, to.String())
	}

	fromAcc := ctx.Accounts[fromIdx]
	toAcc := ctx.Accounts[toIdx]

	if !fromAcc.IsWritable {
		return fmt.Errorf("%w: %s", ErrAccountNotWritable, from.String())
	}
	if !toAcc.IsWritable {
		return fmt.Errorf("%w: %s", ErrAccountNotWritable, to.String())
	}
	if *fromAcc.Lamports < amount {
		return ErrInsufficientFunds
	}

	*fromAcc.Lamports -= amount
	*toAcc.Lamports += amount
	return nil
}

// ResizeAccountData resizes an account's data buffer.
func (ctx *ExecutionContext) ResizeAccountData(pubkey types.Pubkey, newSize int) error {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	idx, ok := ctx.accountIndex[pubkey]
	if !ok {
		return fmt.Errorf("%w: %s", ErrAccountNotFound, pubkey.String())
	}

	acc := ctx.Accounts[idx]
	if !acc.IsWritable {
		return fmt.Errorf("%w: %s", ErrAccountNotWritable, pubkey.String())
	}
	if newSize > MaxAccountDataSize {
		return fmt.Errorf("data size %d exceeds maximum %d", newSize, MaxAccountDataSize)
	}

	oldData := acc.Data
	acc.Data = make([]byte, newSize)
	if len(oldData) > 0 {
		copy(acc.Data, oldData)
	}
	return nil
}

// IsProgramOwned checks if an account is owned by the executing program.
func (ctx *ExecutionContext) IsProgramOwned(pubkey types.Pubkey) bool {
	acc, err := ctx.GetAccount(pubkey)
	if err != nil {
		return false
	}
	return acc.Owner == ctx.ProgramID
}

// CheckAccountOwnership verifies an account is owned by the expected program.
func (ctx *ExecutionContext) CheckAccountOwnership(pubkey types.Pubkey, expectedOwner types.Pubkey) error {
	acc, err := ctx.GetAccount(pubkey)
	if err != nil {
		return err
	}
	if acc.Owner != expectedOwner {
		return fmt.Errorf("account %s owned by %s, expected %s",
			pubkey.String(), acc.Owner.String(), expectedOwner.String())
	}
	return nil
}

// PushCaller pushes a caller onto the CPI stack.
func (ctx *ExecutionContext) PushCaller(programID types.Pubkey) {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	ctx.CallerStack = append(ctx.CallerStack, programID)
	ctx.Depth++
}

// PopCaller pops a caller from the CPI stack.
func (ctx *ExecutionContext) PopCaller() (types.Pubkey, bool) {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	if len(ctx.CallerStack) == 0 {
		return types.ZeroPubkey, false
	}
	caller := ctx.CallerStack[len(ctx.CallerStack)-1]
	ctx.CallerStack = ctx.CallerStack[:len(ctx.CallerStack)-1]
	ctx.Depth--
	return caller, true
}

// GetCaller returns the current caller (program that invoked this one).
func (ctx *ExecutionContext) GetCaller() (types.Pubkey, bool) {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()
	if len(ctx.CallerStack) == 0 {
		return types.ZeroPubkey, false
	}
	return ctx.CallerStack[len(ctx.CallerStack)-1], true
}

// ProgramExecutor is the interface for executing programs during CPI.
// This allows the syscall package to invoke programs without depending on the execution layer.
type ProgramExecutor interface {
	// ExecuteProgram executes a program with the given context.
	// Returns any error from program execution.
	ExecuteProgram(ctx *ExecutionContext) error
}

// programExecutor is the registered program executor for CPI calls.
var programExecutor ProgramExecutor

// SetProgramExecutor sets the global program executor for CPI calls.
// This should be called during initialization by the execution layer.
func SetProgramExecutor(executor ProgramExecutor) {
	programExecutor = executor
}

// GetProgramExecutor returns the registered program executor.
func GetProgramExecutor() ProgramExecutor {
	return programExecutor
}

// InvokeProgram performs a cross-program invocation.
// This is called by the CPI syscalls (sol_invoke_signed_c, sol_invoke_signed_rust).
//
// Parameters:
//   - programID: The program to invoke
//   - accounts: Account metadata for the instruction
//   - data: Instruction data
//   - signerSeeds: Seeds for PDA signers (used to derive PDAs that can sign)
//   - pdaSigners: Map of PDA pubkeys that are authorized to sign
//   - calleeAccounts: Pre-resolved account infos for the callee
//
// The function:
// 1. Validates CPI depth limit
// 2. Creates a new execution context for the callee
// 3. Executes the callee program
// 4. Propagates account changes back to the caller
// 5. Handles return data
func (ctx *ExecutionContext) InvokeProgram(
	programID types.Pubkey,
	accounts []CPIAccountMeta,
	data []byte,
	signerSeeds []CPISignerSeeds,
	pdaSigners map[types.Pubkey]bool,
	calleeAccounts []*AccountInfo,
) error {
	// Validate CPI depth (max 4 levels deep, 5 total including top-level)
	if ctx.Depth >= MaxCPIDepth {
		return ErrCPIDepthExceeded
	}

	// Check for program executor
	if programExecutor == nil {
		return errors.New("no program executor registered for CPI")
	}

	// Push the current program onto the caller stack
	ctx.PushCaller(ctx.ProgramID)
	defer ctx.PopCaller()

	// Store current state for rollback on error
	oldProgramID := ctx.ProgramID
	oldAccounts := ctx.Accounts
	oldAccountIndex := ctx.accountIndex
	oldInstructionData := ctx.InstructionData

	// Clear return data before CPI (callee will set new return data)
	ctx.ReturnData = nil
	ctx.ReturnDataProgram = types.ZeroPubkey

	// Set up callee context
	ctx.ProgramID = programID
	ctx.Accounts = calleeAccounts
	ctx.InstructionData = data

	// Rebuild account index for callee
	ctx.accountIndex = make(map[types.Pubkey]int)
	for i, acc := range calleeAccounts {
		ctx.accountIndex[acc.Pubkey] = i
	}

	// Apply PDA signer privileges to callee accounts
	for i, meta := range accounts {
		if meta.IsSigner {
			if _, isPDA := pdaSigners[meta.Pubkey]; isPDA {
				// Mark the account as a signer for the callee
				calleeAccounts[i].IsSigner = true
			}
		}
	}

	// Log CPI invocation
	_ = ctx.AddLog(fmt.Sprintf("Program %s invoke [%d]", programID.String(), ctx.Depth))

	// Execute the callee program
	err := programExecutor.ExecuteProgram(ctx)

	// Log completion
	if err != nil {
		_ = ctx.AddLog(fmt.Sprintf("Program %s failed: %v", programID.String(), err))
	} else {
		_ = ctx.AddLog(fmt.Sprintf("Program %s success", programID.String()))
	}

	// Propagate account changes back to caller
	// This updates the caller's account data with any modifications made by the callee
	if err == nil {
		err = ctx.propagateAccountChanges(oldAccounts, calleeAccounts, accounts)
	}

	// Restore caller context
	ctx.ProgramID = oldProgramID
	ctx.Accounts = oldAccounts
	ctx.accountIndex = oldAccountIndex
	ctx.InstructionData = oldInstructionData

	// Note: Return data is NOT restored - callee's return data is preserved
	// This allows the caller to access the callee's return data via sol_get_return_data

	return err
}

// propagateAccountChanges copies account modifications from callee back to caller.
// Only writable accounts are updated.
func (ctx *ExecutionContext) propagateAccountChanges(
	callerAccounts []*AccountInfo,
	calleeAccounts []*AccountInfo,
	accountMetas []CPIAccountMeta,
) error {
	// Build a map from pubkey to caller account for fast lookup
	callerAccountMap := make(map[types.Pubkey]*AccountInfo)
	for _, acc := range callerAccounts {
		callerAccountMap[acc.Pubkey] = acc
	}

	// Propagate changes for each callee account
	for i, calleeAcc := range calleeAccounts {
		meta := accountMetas[i]

		// Only propagate changes for writable accounts
		if !meta.IsWritable {
			continue
		}

		// Find the corresponding caller account
		callerAcc, exists := callerAccountMap[calleeAcc.Pubkey]
		if !exists {
			continue
		}

		// Verify the caller account is also writable
		if !callerAcc.IsWritable {
			return fmt.Errorf("%w: account %s", ErrReadOnlyModified, calleeAcc.Pubkey.String())
		}

		// Propagate lamports changes
		*callerAcc.Lamports = *calleeAcc.Lamports

		// Propagate data changes
		// If the callee resized the data, we need to resize the caller's data too
		if len(calleeAcc.Data) != len(callerAcc.Data) {
			callerAcc.Data = make([]byte, len(calleeAcc.Data))
		}
		copy(callerAcc.Data, calleeAcc.Data)

		// Note: Owner changes are handled specially by the runtime
		// (only the system program can change owners)
	}

	return nil
}

// CreateChildContext creates a child execution context for CPI.
// The child context shares compute units with the parent but has its own accounts.
func (ctx *ExecutionContext) CreateChildContext(
	programID types.Pubkey,
	accounts []*AccountInfo,
	instructionData []byte,
) *ExecutionContext {
	child := &ExecutionContext{
		ProgramID:       programID,
		Accounts:        accounts,
		InstructionData: instructionData,
		// Share compute units - CPI uses the same compute budget
		computeUnits:    ctx.computeUnits,
		maxComputeUnits: ctx.maxComputeUnits,
		accountIndex:    make(map[types.Pubkey]int),
		logs:            ctx.logs, // Share logs
		maxLogs:         ctx.maxLogs,
		Depth:           ctx.Depth + 1,
		CallerStack:     append([]types.Pubkey{}, ctx.CallerStack...),
		// Inherit slot context
		Slot:              ctx.Slot,
		RecentBlockhashes: ctx.RecentBlockhashes,
		UnixTimestamp:     ctx.UnixTimestamp,
		Epoch:             ctx.Epoch,
		EpochStartTimestamp: ctx.EpochStartTimestamp,
		RentLamportsPerByteYear: ctx.RentLamportsPerByteYear,
		RentExemptionThreshold:  ctx.RentExemptionThreshold,
	}

	// Build account index for child
	for i, acc := range accounts {
		child.accountIndex[acc.Pubkey] = i
	}

	// Push current program as caller
	child.CallerStack = append(child.CallerStack, ctx.ProgramID)

	return child
}

// SyncComputeUnits synchronizes compute units from a child context back to the parent.
// This is called after CPI completes to reflect compute usage.
func (ctx *ExecutionContext) SyncComputeUnits(child *ExecutionContext) {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	ctx.computeUnits = child.computeUnits
}

// GetDepth returns the current CPI depth.
func (ctx *ExecutionContext) GetDepth() int {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()
	return ctx.Depth
}

// IsTopLevel returns true if this is the top-level execution (not a CPI call).
func (ctx *ExecutionContext) IsTopLevel() bool {
	return ctx.Depth == 0
}

// GetCallerStack returns a copy of the caller stack.
func (ctx *ExecutionContext) GetCallerStack() []types.Pubkey {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()
	stack := make([]types.Pubkey, len(ctx.CallerStack))
	copy(stack, ctx.CallerStack)
	return stack
}

// IsCalledBy checks if the current program was called by the specified program.
func (ctx *ExecutionContext) IsCalledBy(programID types.Pubkey) bool {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()
	for _, caller := range ctx.CallerStack {
		if caller == programID {
			return true
		}
	}
	return false
}

// ClearReturnData clears the return data.
// This is typically called at the start of an instruction or CPI.
func (ctx *ExecutionContext) ClearReturnData() {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	ctx.ReturnData = nil
	ctx.ReturnDataProgram = types.ZeroPubkey
}
