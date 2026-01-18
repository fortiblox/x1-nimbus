package replayer

import (
	"errors"
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/crypto"
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// Signature verification errors
var (
	// ErrBlockSignatureVerificationFailed indicates block signature verification failed.
	ErrBlockSignatureVerificationFailed = errors.New("block signature verification failed")

	// ErrTransactionSignatureVerificationFailed indicates transaction signature verification failed.
	ErrTransactionSignatureVerificationFailed = errors.New("transaction signature verification failed")

	// ErrEmptyBlock indicates the block has no entries.
	ErrEmptyBlock = errors.New("empty block")

	// ErrEmptyEntry indicates an entry has no transactions.
	ErrEmptyEntry = errors.New("empty entry")
)

// SignatureVerifier handles signature verification for blocks and transactions.
type SignatureVerifier struct {
	// useParallel enables parallel verification for large batches
	useParallel bool

	// parallelThreshold is the minimum number of signatures before using parallel verification
	parallelThreshold int
}

// NewSignatureVerifier creates a new signature verifier.
func NewSignatureVerifier() *SignatureVerifier {
	return &SignatureVerifier{
		useParallel:       true,
		parallelThreshold: 8,
	}
}

// SetParallel enables or disables parallel verification.
func (sv *SignatureVerifier) SetParallel(enabled bool) {
	sv.useParallel = enabled
}

// SetParallelThreshold sets the threshold for parallel verification.
func (sv *SignatureVerifier) SetParallelThreshold(threshold int) {
	sv.parallelThreshold = threshold
}

// VerifyBlockSignatures verifies all transaction signatures in a block.
// Returns nil if all signatures are valid.
func VerifyBlockSignatures(block *types.Block) error {
	if block == nil {
		return ErrEmptyBlock
	}

	// Collect all transactions from entries
	var txs []*types.Transaction
	for _, entry := range block.Entries {
		for i := range entry.Transactions {
			txs = append(txs, &entry.Transactions[i])
		}
	}

	if len(txs) == 0 {
		// Block with no transactions (tick-only) is valid
		return nil
	}

	// Use batch verification for efficiency
	errs := crypto.VerifyTransactionBatch(txs)

	// Check for any errors
	for i, err := range errs {
		if err != nil {
			return &BlockSignatureError{
				Slot:             block.Slot,
				TransactionIndex: i,
				Err:              err,
			}
		}
	}

	return nil
}

// VerifyTransactionSignatures verifies all signatures on a transaction.
// Returns nil if all signatures are valid.
func VerifyTransactionSignatures(tx *types.Transaction) error {
	if tx == nil {
		return crypto.ErrMissingMessage
	}

	err := crypto.VerifyTransaction(tx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTransactionSignatureVerificationFailed, err)
	}

	return nil
}

// VerifyBlockSignaturesParallel verifies all signatures in a block using parallel processing.
func (sv *SignatureVerifier) VerifyBlockSignaturesParallel(block *types.Block) error {
	return VerifyBlockSignatures(block)
}

// VerifyTransactionBatch verifies a batch of transactions.
// Returns a slice of errors, one for each transaction (nil if valid).
func (sv *SignatureVerifier) VerifyTransactionBatch(txs []*types.Transaction) []error {
	return crypto.VerifyTransactionBatch(txs)
}

// BlockSignatureError contains details about a block signature verification failure.
type BlockSignatureError struct {
	Slot             types.Slot
	TransactionIndex int
	Err              error
}

// Error implements the error interface.
func (e *BlockSignatureError) Error() string {
	return fmt.Sprintf("block signature verification failed at slot %d, tx %d: %v",
		e.Slot, e.TransactionIndex, e.Err)
}

// Unwrap returns the underlying error.
func (e *BlockSignatureError) Unwrap() error {
	return e.Err
}

// CountSignatures counts the total number of signatures in a block.
func CountSignatures(block *types.Block) uint64 {
	var count uint64
	for _, entry := range block.Entries {
		for _, tx := range entry.Transactions {
			count += uint64(len(tx.Signatures))
		}
	}
	return count
}

// CountTransactions counts the total number of transactions in a block.
func CountTransactions(block *types.Block) int {
	var count int
	for _, entry := range block.Entries {
		count += len(entry.Transactions)
	}
	return count
}

// VerifySignaturesBatch uses the batch verifier for multiple transactions.
// This is more efficient than verifying each transaction individually.
func VerifySignaturesBatch(txs []*types.Transaction) (bool, []error) {
	errs := crypto.VerifyTransactionBatch(txs)

	allValid := true
	for _, err := range errs {
		if err != nil {
			allValid = false
			break
		}
	}

	return allValid, errs
}

// VerifyEntrySignatures verifies all signatures in a single entry.
func VerifyEntrySignatures(entry *types.Entry) error {
	if entry == nil {
		return ErrEmptyEntry
	}

	if len(entry.Transactions) == 0 {
		// Tick entry (no transactions) is valid
		return nil
	}

	txs := make([]*types.Transaction, len(entry.Transactions))
	for i := range entry.Transactions {
		txs[i] = &entry.Transactions[i]
	}

	errs := crypto.VerifyTransactionBatch(txs)

	for i, err := range errs {
		if err != nil {
			return fmt.Errorf("entry signature verification failed at tx %d: %w", i, err)
		}
	}

	return nil
}

// VerificationResult contains the result of batch signature verification.
type VerificationResult struct {
	// AllValid is true if all signatures are valid.
	AllValid bool

	// ValidCount is the number of valid signatures.
	ValidCount int

	// InvalidCount is the number of invalid signatures.
	InvalidCount int

	// Errors contains errors for invalid transactions (index -> error).
	Errors map[int]error
}

// VerifyBlockSignaturesDetailed performs detailed verification and returns comprehensive results.
func VerifyBlockSignaturesDetailed(block *types.Block) *VerificationResult {
	result := &VerificationResult{
		AllValid: true,
		Errors:   make(map[int]error),
	}

	if block == nil {
		result.AllValid = false
		result.Errors[-1] = ErrEmptyBlock
		return result
	}

	// Collect all transactions
	var txs []*types.Transaction
	for _, entry := range block.Entries {
		for i := range entry.Transactions {
			txs = append(txs, &entry.Transactions[i])
		}
	}

	if len(txs) == 0 {
		return result
	}

	// Verify all transactions
	errs := crypto.VerifyTransactionBatch(txs)

	for i, err := range errs {
		if err != nil {
			result.AllValid = false
			result.InvalidCount++
			result.Errors[i] = err
		} else {
			result.ValidCount++
		}
	}

	return result
}
