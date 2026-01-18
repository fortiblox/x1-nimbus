package compute_budget

import (
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/svm/syscall"
)

// ComputeBudgetState holds the parsed compute budget parameters for a transaction.
// This is populated during transaction loading and used by the runtime.
type ComputeBudgetState struct {
	// HeapFrameSize is the requested heap frame size in bytes.
	HeapFrameSize uint32

	// ComputeUnitLimit is the maximum compute units for the transaction.
	ComputeUnitLimit uint32

	// ComputeUnitPrice is the priority fee in micro-lamports per compute unit.
	ComputeUnitPrice uint64

	// LoadedAccountsDataSizeLimit is the maximum bytes of account data that can be loaded.
	LoadedAccountsDataSizeLimit uint32

	// Tracking which instructions have been seen (for duplicate detection)
	hasRequestedHeapFrame          bool
	hasSetComputeUnitLimit         bool
	hasSetComputeUnitPrice         bool
	hasSetLoadedAccountsDataLimit  bool
}

// NewComputeBudgetState creates a new ComputeBudgetState with default values.
func NewComputeBudgetState() *ComputeBudgetState {
	return &ComputeBudgetState{
		HeapFrameSize:               DefaultHeapFrameSize,
		ComputeUnitLimit:            DefaultComputeUnits,
		ComputeUnitPrice:            0,
		LoadedAccountsDataSizeLimit: DefaultLoadedAccountsDataSizeLimit,
	}
}

// handleRequestHeapFrame handles the RequestHeapFrame instruction.
// Validates and stores the requested heap frame size.
func handleRequestHeapFrame(ctx *syscall.ExecutionContext, state *ComputeBudgetState, inst *RequestHeapFrameInstruction) error {
	// Check for duplicate instruction
	if state.hasRequestedHeapFrame {
		return fmt.Errorf("%w: RequestHeapFrame", ErrDuplicateInstruction)
	}
	state.hasRequestedHeapFrame = true

	// Validate heap frame size is aligned to 1024 bytes
	if inst.HeapFrameSize%HeapFrameAlignment != 0 {
		return fmt.Errorf("%w: got %d bytes (not aligned to %d)", ErrInvalidHeapFrameSize, inst.HeapFrameSize, HeapFrameAlignment)
	}

	// Validate heap frame size does not exceed maximum
	if inst.HeapFrameSize > MaxHeapFrameSize {
		return fmt.Errorf("%w: got %d bytes (max %d)", ErrHeapFrameSizeTooLarge, inst.HeapFrameSize, MaxHeapFrameSize)
	}

	// Store the validated heap frame size
	state.HeapFrameSize = inst.HeapFrameSize

	// Log the heap frame request (consume minimal compute for logging)
	_ = ctx.ConsumeComputeUnits(100)
	_ = ctx.AddLog(fmt.Sprintf("Program log: Request heap frame: %d bytes", inst.HeapFrameSize))

	return nil
}

// handleSetComputeUnitLimit handles the SetComputeUnitLimit instruction.
// Validates and stores the compute unit limit.
func handleSetComputeUnitLimit(ctx *syscall.ExecutionContext, state *ComputeBudgetState, inst *SetComputeUnitLimitInstruction) error {
	// Check for duplicate instruction
	if state.hasSetComputeUnitLimit {
		return fmt.Errorf("%w: SetComputeUnitLimit", ErrDuplicateInstruction)
	}
	state.hasSetComputeUnitLimit = true

	// Validate compute unit limit does not exceed maximum
	if inst.ComputeUnitLimit > MaxComputeUnits {
		return fmt.Errorf("%w: got %d (max %d)", ErrComputeUnitLimitTooHigh, inst.ComputeUnitLimit, MaxComputeUnits)
	}

	// Store the validated compute unit limit
	state.ComputeUnitLimit = inst.ComputeUnitLimit

	// Log the compute unit limit (consume minimal compute for logging)
	_ = ctx.ConsumeComputeUnits(100)
	_ = ctx.AddLog(fmt.Sprintf("Program log: Set compute unit limit: %d", inst.ComputeUnitLimit))

	return nil
}

// handleSetComputeUnitPrice handles the SetComputeUnitPrice instruction.
// Stores the priority fee (micro-lamports per compute unit).
func handleSetComputeUnitPrice(ctx *syscall.ExecutionContext, state *ComputeBudgetState, inst *SetComputeUnitPriceInstruction) error {
	// Check for duplicate instruction
	if state.hasSetComputeUnitPrice {
		return fmt.Errorf("%w: SetComputeUnitPrice", ErrDuplicateInstruction)
	}
	state.hasSetComputeUnitPrice = true

	// No validation needed - any uint64 value is valid for priority fee
	state.ComputeUnitPrice = inst.MicroLamportsPerComputeUnit

	// Log the compute unit price (consume minimal compute for logging)
	_ = ctx.ConsumeComputeUnits(100)
	_ = ctx.AddLog(fmt.Sprintf("Program log: Set compute unit price: %d micro-lamports/CU", inst.MicroLamportsPerComputeUnit))

	return nil
}

// handleSetLoadedAccountsDataSizeLimit handles the SetLoadedAccountsDataSizeLimit instruction.
// Stores the maximum loaded account data size limit.
func handleSetLoadedAccountsDataSizeLimit(ctx *syscall.ExecutionContext, state *ComputeBudgetState, inst *SetLoadedAccountsDataSizeLimitInstruction) error {
	// Check for duplicate instruction
	if state.hasSetLoadedAccountsDataLimit {
		return fmt.Errorf("%w: SetLoadedAccountsDataSizeLimit", ErrDuplicateInstruction)
	}
	state.hasSetLoadedAccountsDataLimit = true

	// Store the data size limit (no upper bound validation - runtime will enforce actual limits)
	state.LoadedAccountsDataSizeLimit = inst.DataSizeLimit

	// Log the data size limit (consume minimal compute for logging)
	_ = ctx.ConsumeComputeUnits(100)
	_ = ctx.AddLog(fmt.Sprintf("Program log: Set loaded accounts data size limit: %d bytes", inst.DataSizeLimit))

	return nil
}

// CalculatePriorityFee calculates the priority fee in lamports for a transaction.
// Priority fee = (compute_unit_limit * micro_lamports_per_cu) / 1_000_000
func (s *ComputeBudgetState) CalculatePriorityFee() uint64 {
	// Use uint64 arithmetic to avoid overflow
	fee := uint64(s.ComputeUnitLimit) * s.ComputeUnitPrice
	// Convert from micro-lamports to lamports (divide by 1,000,000)
	return fee / 1_000_000
}

// GetEffectiveComputeUnits returns the effective compute unit limit for the transaction.
// If not explicitly set, returns the default.
func (s *ComputeBudgetState) GetEffectiveComputeUnits() uint32 {
	if s.hasSetComputeUnitLimit {
		return s.ComputeUnitLimit
	}
	return DefaultComputeUnits
}

// GetEffectiveHeapSize returns the effective heap frame size for the transaction.
// If not explicitly set, returns the default.
func (s *ComputeBudgetState) GetEffectiveHeapSize() uint32 {
	if s.hasRequestedHeapFrame {
		return s.HeapFrameSize
	}
	return DefaultHeapFrameSize
}
