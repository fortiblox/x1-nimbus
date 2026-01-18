// Package replayer provides block replay and verification for X1-Nimbus.
package replayer

import (
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// BlockResult represents the result of replaying a block.
type BlockResult struct {
	// Slot is the slot number of the replayed block.
	Slot types.Slot

	// TransactionResults contains the result of each transaction in the block.
	TransactionResults []*types.TransactionResult

	// AccountDeltas contains all account changes from the block.
	AccountDeltas []types.AccountDelta

	// BankHash is the computed bank hash for this block.
	BankHash types.Hash

	// SuccessCount is the number of successful transactions.
	SuccessCount int

	// FailureCount is the number of failed transactions.
	FailureCount int

	// TotalComputeUnits is the total compute units consumed.
	TotalComputeUnits types.ComputeUnits

	// SignatureCount is the total number of signatures verified.
	SignatureCount uint64
}

// NewBlockResult creates a new BlockResult for the given slot.
func NewBlockResult(slot types.Slot) *BlockResult {
	return &BlockResult{
		Slot:               slot,
		TransactionResults: make([]*types.TransactionResult, 0),
		AccountDeltas:      make([]types.AccountDelta, 0),
	}
}

// AddTransactionResult adds a transaction result to the block result.
func (br *BlockResult) AddTransactionResult(result *types.TransactionResult) {
	br.TransactionResults = append(br.TransactionResults, result)
	if result.Success {
		br.SuccessCount++
	} else {
		br.FailureCount++
	}
	br.TotalComputeUnits += result.ComputeUnits
	br.AccountDeltas = append(br.AccountDeltas, result.AccountDeltas...)
}

// TotalTransactions returns the total number of transactions processed.
func (br *BlockResult) TotalTransactions() int {
	return br.SuccessCount + br.FailureCount
}

// SuccessRate returns the success rate as a percentage.
func (br *BlockResult) SuccessRate() float64 {
	total := br.TotalTransactions()
	if total == 0 {
		return 0.0
	}
	return float64(br.SuccessCount) / float64(total) * 100.0
}

// AllSuccessful returns true if all transactions were successful.
func (br *BlockResult) AllSuccessful() bool {
	return br.FailureCount == 0
}

// HasFailures returns true if any transactions failed.
func (br *BlockResult) HasFailures() bool {
	return br.FailureCount > 0
}

// GetFailedResults returns only the failed transaction results.
func (br *BlockResult) GetFailedResults() []*types.TransactionResult {
	failed := make([]*types.TransactionResult, 0, br.FailureCount)
	for _, result := range br.TransactionResults {
		if !result.Success {
			failed = append(failed, result)
		}
	}
	return failed
}

// GetSuccessfulResults returns only the successful transaction results.
func (br *BlockResult) GetSuccessfulResults() []*types.TransactionResult {
	successful := make([]*types.TransactionResult, 0, br.SuccessCount)
	for _, result := range br.TransactionResults {
		if result.Success {
			successful = append(successful, result)
		}
	}
	return successful
}

// AggregateAccountDeltas aggregates account deltas, keeping only the final state
// for each account that was modified.
func (br *BlockResult) AggregateAccountDeltas() map[types.Pubkey]types.AccountDelta {
	aggregated := make(map[types.Pubkey]types.AccountDelta)

	for _, delta := range br.AccountDeltas {
		existing, ok := aggregated[delta.Pubkey]
		if !ok {
			// First delta for this account
			aggregated[delta.Pubkey] = delta
		} else {
			// Update with the new state, preserving the original old state
			aggregated[delta.Pubkey] = types.AccountDelta{
				Pubkey:     delta.Pubkey,
				OldAccount: existing.OldAccount,
				NewAccount: delta.NewAccount,
			}
		}
	}

	return aggregated
}

// CollectLogs collects all logs from all transaction results.
func (br *BlockResult) CollectLogs() []string {
	var logs []string
	for _, result := range br.TransactionResults {
		logs = append(logs, result.Logs...)
	}
	return logs
}

// Summary returns a summary string of the block result.
func (br *BlockResult) Summary() string {
	return "BlockResult{Slot=" + itoa(int(br.Slot)) +
		", Success=" + itoa(br.SuccessCount) +
		", Failed=" + itoa(br.FailureCount) +
		", ComputeUnits=" + itoa(int(br.TotalComputeUnits)) +
		", AccountDeltas=" + itoa(len(br.AccountDeltas)) + "}"
}

// itoa is a simple integer to string conversion without fmt dependency.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
