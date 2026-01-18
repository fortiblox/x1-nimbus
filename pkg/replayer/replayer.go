package replayer

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// Replayer errors
var (
	ErrNoBlocks           = errors.New("replayer: no blocks to replay")
	ErrBlockNotFound      = errors.New("replayer: block not found")
	ErrReplayFailed       = errors.New("replayer: replay failed")
	ErrVerificationFailed = errors.New("replayer: verification failed")
	ErrAlreadyRunning     = errors.New("replayer: already running")
	ErrNotRunning         = errors.New("replayer: not running")
)

// BlockProvider is an interface for providing blocks to replay.
type BlockProvider interface {
	// GetBlock returns a block by slot number.
	GetBlock(slot types.Slot) (*types.Block, error)

	// GetBlockRange returns blocks in a slot range (inclusive).
	GetBlockRange(startSlot, endSlot types.Slot) ([]*types.Block, error)
}

// ReplayOptions configures replay behavior.
type ReplayOptions struct {
	// VerifyBankHash enables verification of computed bank hash against expected
	VerifyBankHash bool

	// ExpectedBankHashes maps slot to expected bank hash (required if VerifyBankHash is true)
	ExpectedBankHashes map[types.Slot]types.Hash

	// SkipSignatureVerification skips signature verification during replay
	SkipSignatureVerification bool

	// SkipPoHVerification skips PoH verification during replay
	SkipPoHVerification bool

	// ParallelSignatureVerification enables parallel signature verification
	ParallelSignatureVerification bool

	// OnBlockComplete is called after each block is replayed
	OnBlockComplete func(result *BlockResult, duration time.Duration)

	// OnError is called when an error occurs
	OnError func(slot types.Slot, err error)
}

// DefaultReplayOptions returns default replay options.
func DefaultReplayOptions() *ReplayOptions {
	return &ReplayOptions{
		VerifyBankHash:                false,
		ParallelSignatureVerification: true,
	}
}

// Replayer replays blocks to compute state and bank hashes.
type Replayer struct {
	mu sync.RWMutex

	// blockProvider provides blocks for replay
	blockProvider BlockProvider

	// accountLoader loads accounts for transaction execution
	accountLoader AccountLoader

	// txExecutor executes transactions
	txExecutor TransactionExecutor

	// currentBankHash is the current bank hash (after last replayed block)
	currentBankHash types.Hash

	// lastReplayedSlot is the last slot that was replayed
	lastReplayedSlot types.Slot

	// running indicates if a replay is in progress
	running bool

	// options are the current replay options
	options *ReplayOptions
}

// NewReplayer creates a new Replayer.
func NewReplayer(blockProvider BlockProvider) *Replayer {
	return &Replayer{
		blockProvider: blockProvider,
		options:       DefaultReplayOptions(),
	}
}

// SetAccountLoader sets the account loader for transaction execution.
func (r *Replayer) SetAccountLoader(loader AccountLoader) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.accountLoader = loader
}

// SetTransactionExecutor sets the transaction executor.
func (r *Replayer) SetTransactionExecutor(executor TransactionExecutor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.txExecutor = executor
}

// SetOptions sets the replay options.
func (r *Replayer) SetOptions(options *ReplayOptions) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.options = options
}

// SetInitialBankHash sets the initial bank hash (from a known state).
func (r *Replayer) SetInitialBankHash(hash types.Hash) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.currentBankHash = hash
}

// CurrentBankHash returns the current bank hash.
func (r *Replayer) CurrentBankHash() types.Hash {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.currentBankHash
}

// LastReplayedSlot returns the last replayed slot.
func (r *Replayer) LastReplayedSlot() types.Slot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.lastReplayedSlot
}

// IsRunning returns true if a replay is in progress.
func (r *Replayer) IsRunning() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.running
}

// ReplayBlock replays a single block and returns the result.
func (r *Replayer) ReplayBlock(block *types.Block) (*BlockResult, error) {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return nil, ErrAlreadyRunning
	}
	r.running = true
	options := r.options
	currentBankHash := r.currentBankHash
	accountLoader := r.accountLoader
	txExecutor := r.txExecutor
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		r.running = false
		r.mu.Unlock()
	}()

	startTime := time.Now()

	// Create block verifier
	verifier := NewBlockVerifier(accountLoader)
	verifier.SetTransactionExecutor(txExecutor)
	verifier.SetParentBankHash(currentBankHash)
	verifier.SkipSignatureVerification = options.SkipSignatureVerification
	verifier.SkipPoHVerification = options.SkipPoHVerification
	verifier.ParallelSignatureVerification = options.ParallelSignatureVerification

	// Execute the block
	result, err := verifier.executeBlock(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReplayFailed, err)
	}

	duration := time.Since(startTime)

	// Verify bank hash if requested
	if options.VerifyBankHash && options.ExpectedBankHashes != nil {
		if expectedHash, ok := options.ExpectedBankHashes[block.Slot]; ok {
			if result.BankHash != expectedHash {
				return result, fmt.Errorf("%w: slot %d, computed %s, expected %s",
					ErrVerificationFailed, block.Slot,
					result.BankHash.String(), expectedHash.String())
			}
		}
	}

	// Update state
	r.mu.Lock()
	r.currentBankHash = result.BankHash
	r.lastReplayedSlot = block.Slot
	r.mu.Unlock()

	// Call callback if provided
	if options.OnBlockComplete != nil {
		options.OnBlockComplete(result, duration)
	}

	return result, nil
}

// ReplaySlot replays a block by slot number.
func (r *Replayer) ReplaySlot(slot types.Slot) (*BlockResult, error) {
	block, err := r.blockProvider.GetBlock(slot)
	if err != nil {
		return nil, fmt.Errorf("%w: slot %d: %v", ErrBlockNotFound, slot, err)
	}
	return r.ReplayBlock(block)
}

// ReplayRange replays a range of blocks.
func (r *Replayer) ReplayRange(startSlot, endSlot types.Slot) ([]*BlockResult, error) {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return nil, ErrAlreadyRunning
	}
	r.running = true
	options := r.options
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		r.running = false
		r.mu.Unlock()
	}()

	blocks, err := r.blockProvider.GetBlockRange(startSlot, endSlot)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBlockNotFound, err)
	}

	if len(blocks) == 0 {
		return nil, ErrNoBlocks
	}

	results := make([]*BlockResult, 0, len(blocks))

	for _, block := range blocks {
		// Temporarily unset running flag to allow ReplayBlock to run
		r.mu.Lock()
		r.running = false
		r.mu.Unlock()

		result, err := r.ReplayBlock(block)
		if err != nil {
			if options.OnError != nil {
				options.OnError(block.Slot, err)
			}
			return results, err
		}
		results = append(results, result)

		// Reset running flag
		r.mu.Lock()
		r.running = true
		r.mu.Unlock()
	}

	return results, nil
}

// ComputeBankHashForBlock computes the bank hash for a block without full replay.
// This is useful when you have the account deltas already computed.
func (r *Replayer) ComputeBankHashForBlock(block *types.Block, accountDeltas []types.AccountDelta) types.Hash {
	r.mu.RLock()
	parentBankHash := r.currentBankHash
	r.mu.RUnlock()

	hasher := NewBankHasher(parentBankHash)
	hasher.SetBlockhash(block.Blockhash)

	// Count signatures
	sigCount := CountSignatures(block)
	hasher.SetSignatureCount(sigCount)

	// Add account deltas
	hasher.AddAccountDeltas(accountDeltas)

	return hasher.Compute()
}

// VerifyBlockBankHash verifies that a block's computed bank hash matches expected.
func (r *Replayer) VerifyBlockBankHash(block *types.Block, expectedBankHash types.Hash) error {
	r.mu.RLock()
	parentBankHash := r.currentBankHash
	accountLoader := r.accountLoader
	txExecutor := r.txExecutor
	r.mu.RUnlock()

	verifier := NewBlockVerifier(accountLoader)
	verifier.SetTransactionExecutor(txExecutor)
	verifier.SetParentBankHash(parentBankHash)

	return verifier.Verify(block, expectedBankHash)
}

// ReplayStats contains statistics about replay progress.
type ReplayStats struct {
	// BlocksReplayed is the number of blocks replayed
	BlocksReplayed uint64

	// TransactionsExecuted is the total transactions executed
	TransactionsExecuted uint64

	// SignaturesVerified is the total signatures verified
	SignaturesVerified uint64

	// ComputeUnitsUsed is the total compute units consumed
	ComputeUnitsUsed uint64

	// TotalDuration is the total time spent replaying
	TotalDuration time.Duration

	// AvgBlockDuration is the average time per block
	AvgBlockDuration time.Duration

	// LastSlot is the last slot replayed
	LastSlot types.Slot

	// LastBankHash is the bank hash of the last replayed block
	LastBankHash types.Hash
}

// StatsCollector collects replay statistics.
type StatsCollector struct {
	mu    sync.Mutex
	stats ReplayStats
}

// NewStatsCollector creates a new stats collector.
func NewStatsCollector() *StatsCollector {
	return &StatsCollector{}
}

// OnBlockComplete is a callback for updating stats after each block.
func (sc *StatsCollector) OnBlockComplete(result *BlockResult, duration time.Duration) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	sc.stats.BlocksReplayed++
	sc.stats.TransactionsExecuted += uint64(result.TotalTransactions())
	sc.stats.SignaturesVerified += result.SignatureCount
	sc.stats.ComputeUnitsUsed += uint64(result.TotalComputeUnits)
	sc.stats.TotalDuration += duration
	sc.stats.LastSlot = result.Slot
	sc.stats.LastBankHash = result.BankHash

	if sc.stats.BlocksReplayed > 0 {
		sc.stats.AvgBlockDuration = sc.stats.TotalDuration / time.Duration(sc.stats.BlocksReplayed)
	}
}

// Stats returns the current statistics.
func (sc *StatsCollector) Stats() ReplayStats {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.stats
}

// Reset resets the statistics.
func (sc *StatsCollector) Reset() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.stats = ReplayStats{}
}

// QuickReplay performs a quick replay of blocks without full transaction execution.
// This computes bank hashes based on signature counts and account deltas only.
func QuickReplay(blocks []*types.Block, initialBankHash types.Hash, deltaProvider func(slot types.Slot) []types.AccountDelta) ([]types.Hash, error) {
	if len(blocks) == 0 {
		return nil, ErrNoBlocks
	}

	bankHashes := make([]types.Hash, len(blocks))
	currentBankHash := initialBankHash

	for i, block := range blocks {
		if block == nil {
			return bankHashes, fmt.Errorf("block %d is nil", i)
		}

		hasher := NewBankHasher(currentBankHash)
		hasher.SetBlockhash(block.Blockhash)
		hasher.SetSignatureCount(CountSignatures(block))

		if deltaProvider != nil {
			deltas := deltaProvider(block.Slot)
			hasher.AddAccountDeltas(deltas)
		}

		currentBankHash = hasher.Compute()
		bankHashes[i] = currentBankHash
	}

	return bankHashes, nil
}
