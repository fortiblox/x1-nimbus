package replayer

import (
	"errors"
	"fmt"
	"sync"

	"github.com/fortiblox/x1-nimbus/pkg/crypto"
	"github.com/fortiblox/x1-nimbus/pkg/poh"
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// Verification errors
var (
	ErrNilBlock              = errors.New("replayer: block is nil")
	ErrPoHVerificationFailed = errors.New("replayer: PoH verification failed")
	ErrBankHashMismatch      = errors.New("replayer: bank hash mismatch")
	ErrNoEntries             = errors.New("replayer: block has no entries")
	ErrTransactionExecution  = errors.New("replayer: transaction execution failed")
)

// VerifyBlock verifies a block against an expected bank hash.
// It performs the following verification steps:
//  1. PoH chain verification (using pkg/poh)
//  2. All transaction signature verification (using pkg/crypto)
//  3. Execute all transactions (placeholder for now)
//  4. Compute bank hash
//  5. Compare with expected bank hash
//
// Returns nil if the block is valid and matches the expected bank hash.
func VerifyBlock(block *types.Block, expectedBankHash types.Hash) error {
	verifier := NewBlockVerifier(nil) // No account loader for basic verification
	return verifier.Verify(block, expectedBankHash)
}

// AccountLoader is an interface for loading accounts during verification.
type AccountLoader interface {
	// LoadAccount loads an account by its pubkey.
	// Returns nil if the account doesn't exist.
	LoadAccount(pubkey types.Pubkey) (*types.Account, error)
}

// TransactionExecutor is an interface for executing transactions during verification.
type TransactionExecutor interface {
	// ExecuteTransaction executes a single transaction and returns the result.
	ExecuteTransaction(tx *types.Transaction) (*types.TransactionResult, error)
}

// BlockVerifier provides full block verification with a customizable pipeline.
type BlockVerifier struct {
	mu sync.RWMutex

	// AccountLoader for loading accounts (optional for signature-only verification)
	accountLoader AccountLoader

	// TransactionExecutor for executing transactions (optional)
	txExecutor TransactionExecutor

	// ParentBankHash is the bank hash of the parent block
	parentBankHash types.Hash

	// SkipSignatureVerification can be set to skip signature checks
	// (useful when signatures have already been verified)
	SkipSignatureVerification bool

	// SkipPoHVerification can be set to skip PoH checks
	SkipPoHVerification bool

	// SkipExecution can be set to skip transaction execution
	SkipExecution bool

	// ParallelSignatureVerification enables parallel signature verification
	ParallelSignatureVerification bool
}

// NewBlockVerifier creates a new BlockVerifier with the given account loader.
func NewBlockVerifier(accountLoader AccountLoader) *BlockVerifier {
	return &BlockVerifier{
		accountLoader:                 accountLoader,
		ParallelSignatureVerification: true,
	}
}

// SetAccountLoader sets the account loader.
func (bv *BlockVerifier) SetAccountLoader(loader AccountLoader) {
	bv.mu.Lock()
	defer bv.mu.Unlock()
	bv.accountLoader = loader
}

// SetTransactionExecutor sets the transaction executor.
func (bv *BlockVerifier) SetTransactionExecutor(executor TransactionExecutor) {
	bv.mu.Lock()
	defer bv.mu.Unlock()
	bv.txExecutor = executor
}

// SetParentBankHash sets the parent bank hash for verification.
func (bv *BlockVerifier) SetParentBankHash(hash types.Hash) {
	bv.mu.Lock()
	defer bv.mu.Unlock()
	bv.parentBankHash = hash
}

// Verify verifies a block against the expected bank hash.
func (bv *BlockVerifier) Verify(block *types.Block, expectedBankHash types.Hash) error {
	if block == nil {
		return ErrNilBlock
	}

	if len(block.Entries) == 0 {
		return ErrNoEntries
	}

	// Step 1: Verify PoH chain
	if !bv.SkipPoHVerification {
		if err := bv.verifyPoH(block); err != nil {
			return fmt.Errorf("%w: %v", ErrPoHVerificationFailed, err)
		}
	}

	// Step 2: Verify all transaction signatures
	if !bv.SkipSignatureVerification {
		if err := bv.verifySignatures(block); err != nil {
			return fmt.Errorf("%w: %v", ErrBlockSignatureVerificationFailed, err)
		}
	}

	// Step 3: Execute all transactions and collect deltas
	result, err := bv.executeBlock(block)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTransactionExecution, err)
	}

	// Step 4: Compute bank hash is done in executeBlock

	// Step 5: Compare with expected
	if result.BankHash != expectedBankHash {
		return fmt.Errorf("%w: computed %s, expected %s",
			ErrBankHashMismatch, result.BankHash.String(), expectedBankHash.String())
	}

	return nil
}

// VerifyPoHOnly verifies only the PoH chain of a block.
func (bv *BlockVerifier) VerifyPoHOnly(block *types.Block) error {
	if block == nil {
		return ErrNilBlock
	}
	return bv.verifyPoH(block)
}

// VerifySignaturesOnly verifies only the transaction signatures in a block.
func (bv *BlockVerifier) VerifySignaturesOnly(block *types.Block) error {
	if block == nil {
		return ErrNilBlock
	}
	return bv.verifySignatures(block)
}

// verifyPoH verifies the PoH chain for a block.
func (bv *BlockVerifier) verifyPoH(block *types.Block) error {
	verifier := poh.NewVerifier(block.PreviousBlockhash)
	return verifier.VerifyEntries(block.Entries)
}

// verifySignatures verifies all transaction signatures in a block.
func (bv *BlockVerifier) verifySignatures(block *types.Block) error {
	// Collect all transactions
	txs := block.AllTransactions()
	if len(txs) == 0 {
		return nil // No transactions to verify
	}

	if bv.ParallelSignatureVerification && len(txs) > 4 {
		return bv.verifySignaturesParallel(txs)
	}

	return bv.verifySignaturesSequential(txs)
}

// verifySignaturesSequential verifies signatures one at a time.
func (bv *BlockVerifier) verifySignaturesSequential(txs []types.Transaction) error {
	for i := range txs {
		if err := crypto.VerifyTransaction(&txs[i]); err != nil {
			return fmt.Errorf("transaction %d (sig: %s): %w",
				i, txs[i].ID().String(), err)
		}
	}
	return nil
}

// verifySignaturesParallel verifies signatures in parallel.
func (bv *BlockVerifier) verifySignaturesParallel(txs []types.Transaction) error {
	// Convert to pointer slice for batch verification
	txPtrs := make([]*types.Transaction, len(txs))
	for i := range txs {
		txPtrs[i] = &txs[i]
	}

	errs := crypto.VerifyTransactionBatch(txPtrs)

	for i, err := range errs {
		if err != nil {
			return fmt.Errorf("transaction %d (sig: %s): %w",
				i, txs[i].ID().String(), err)
		}
	}

	return nil
}

// executeBlock executes all transactions in a block and returns the result.
func (bv *BlockVerifier) executeBlock(block *types.Block) (*BlockResult, error) {
	bv.mu.RLock()
	txExecutor := bv.txExecutor
	parentBankHash := bv.parentBankHash
	skipExecution := bv.SkipExecution
	bv.mu.RUnlock()

	// Create bank hasher
	hasher := NewBankHasher(parentBankHash)
	hasher.SetBlockhash(block.Blockhash)

	result := NewBlockResult(block.Slot)

	// Count signatures and optionally execute transactions
	for _, entry := range block.Entries {
		for i := range entry.Transactions {
			tx := &entry.Transactions[i]

			// Count signatures
			hasher.IncrementSignatureCount(uint64(len(tx.Signatures)))

			// Execute transaction if executor is available and not skipped
			if txExecutor != nil && !skipExecution {
				txResult, err := txExecutor.ExecuteTransaction(tx)
				if err != nil {
					return nil, fmt.Errorf("execute transaction %s: %w",
						tx.ID().String(), err)
				}

				result.AddTransactionResult(txResult)

				// Add account deltas to hasher
				hasher.AddAccountDeltas(txResult.AccountDeltas)
			}
		}
	}

	// Compute bank hash
	result.BankHash = hasher.Compute()
	result.SignatureCount = hasher.GetSignatureCount()

	return result, nil
}

// BlockVerificationResult contains detailed verification results.
type BlockVerificationResult struct {
	// Valid indicates overall verification success
	Valid bool

	// PoHValid indicates PoH verification result
	PoHValid bool

	// SignaturesValid indicates signature verification result
	SignaturesValid bool

	// ExecutionValid indicates transaction execution result
	ExecutionValid bool

	// BankHashValid indicates bank hash comparison result
	BankHashValid bool

	// ComputedBankHash is the bank hash we computed
	ComputedBankHash types.Hash

	// ExpectedBankHash is the expected bank hash
	ExpectedBankHash types.Hash

	// Error contains the first error encountered, if any
	Error error

	// SignatureCount is the total number of signatures verified
	SignatureCount uint64

	// TransactionCount is the total number of transactions processed
	TransactionCount int
}

// VerifyDetailed performs verification and returns detailed results.
func (bv *BlockVerifier) VerifyDetailed(block *types.Block, expectedBankHash types.Hash) *BlockVerificationResult {
	result := &BlockVerificationResult{
		ExpectedBankHash: expectedBankHash,
	}

	if block == nil {
		result.Error = ErrNilBlock
		return result
	}

	// Count transactions
	result.TransactionCount = block.NumTransactions()

	// Step 1: Verify PoH
	if !bv.SkipPoHVerification {
		if err := bv.verifyPoH(block); err != nil {
			result.Error = fmt.Errorf("%w: %v", ErrPoHVerificationFailed, err)
			return result
		}
	}
	result.PoHValid = true

	// Step 2: Verify signatures
	if !bv.SkipSignatureVerification {
		if err := bv.verifySignatures(block); err != nil {
			result.Error = fmt.Errorf("%w: %v", ErrBlockSignatureVerificationFailed, err)
			result.PoHValid = true
			return result
		}
	}
	result.SignaturesValid = true

	// Step 3: Execute block
	blockResult, err := bv.executeBlock(block)
	if err != nil {
		result.Error = fmt.Errorf("%w: %v", ErrTransactionExecution, err)
		return result
	}
	result.ExecutionValid = true
	result.SignatureCount = blockResult.SignatureCount
	result.ComputedBankHash = blockResult.BankHash

	// Step 4: Compare bank hash
	if blockResult.BankHash != expectedBankHash {
		result.Error = fmt.Errorf("%w: computed %s, expected %s",
			ErrBankHashMismatch, blockResult.BankHash.String(), expectedBankHash.String())
		return result
	}
	result.BankHashValid = true
	result.Valid = true

	return result
}

// VerifyPoHChain verifies a sequence of blocks for PoH continuity.
func VerifyPoHChain(blocks []*types.Block) error {
	if len(blocks) == 0 {
		return nil
	}

	for i, block := range blocks {
		if block == nil {
			return fmt.Errorf("block %d is nil", i)
		}

		verifier := poh.NewVerifier(block.PreviousBlockhash)
		if err := verifier.VerifyEntries(block.Entries); err != nil {
			return fmt.Errorf("block %d (slot %d): %w", i, block.Slot, err)
		}

		// Verify chain linkage if not the first block
		if i > 0 {
			prevBlock := blocks[i-1]
			if block.ParentSlot != prevBlock.Slot {
				return fmt.Errorf("block %d: parent slot %d doesn't match previous block slot %d",
					i, block.ParentSlot, prevBlock.Slot)
			}
			if block.PreviousBlockhash != prevBlock.Blockhash {
				return fmt.Errorf("block %d: previous blockhash doesn't match",
					i)
			}
		}
	}

	return nil
}
