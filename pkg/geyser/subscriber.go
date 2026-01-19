package geyser

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// Subscriber manages block and slot subscriptions with automatic reconnection.
type Subscriber struct {
	client        *Client
	config        *Config
	rpc           *RPCClient
	stats         StreamStats
	mu            sync.RWMutex
	closed        atomic.Bool
	activeStreams sync.WaitGroup
}

// newSubscriber creates a new subscriber.
func newSubscriber(client *Client, config *Config, rpc *RPCClient) *Subscriber {
	return &Subscriber{
		client: client,
		config: config,
		rpc:    rpc,
	}
}

// Stats returns current subscription statistics.
func (s *Subscriber) Stats() StreamStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stats
}

// SubscribeBlocks subscribes to new blocks at the specified commitment level.
// Returns a channel that receives block updates.
// The channel is closed when the context is cancelled or an unrecoverable error occurs.
func (s *Subscriber) SubscribeBlocks(ctx context.Context, commitment string) (<-chan *types.Block, error) {
	if s.closed.Load() {
		return nil, fmt.Errorf("subscriber closed")
	}

	if commitment == "" {
		commitment = CommitmentConfirmed
	}

	// Validate commitment
	switch commitment {
	case CommitmentProcessed, CommitmentConfirmed, CommitmentFinalized:
		// Valid
	default:
		return nil, fmt.Errorf("invalid commitment level: %s", commitment)
	}

	blockCh := make(chan *types.Block, s.config.BufferSize)

	s.activeStreams.Add(1)
	go s.blockSubscriptionLoop(ctx, commitment, blockCh)

	return blockCh, nil
}

// blockSubscriptionLoop handles the block subscription with reconnection.
func (s *Subscriber) blockSubscriptionLoop(ctx context.Context, commitment string, blockCh chan<- *types.Block) {
	defer s.activeStreams.Done()
	defer close(blockCh)

	var lastSlot types.Slot
	consecutiveErrors := 0

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if s.closed.Load() {
			return
		}

		// Try to get current slot
		currentSlot, err := s.rpc.GetSlotWithCommitment(ctx, commitment)
		if err != nil {
			consecutiveErrors++
			s.incrementErrors()

			if consecutiveErrors > s.config.MaxRetries && !s.config.AutoReconnect {
				return
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(s.getBackoffDuration(consecutiveErrors)):
				continue
			}
		}

		// Apply a lag to avoid fetching blocks that aren't available yet
		// The RPC returns the current slot, but block data takes several seconds to be available
		// Using 32 slots (~12-15 seconds on X1) to give the RPC time to process and store blocks
		const blockLag = 32
		if currentSlot > blockLag {
			currentSlot = currentSlot - blockLag
		}

		consecutiveErrors = 0

		// If we have a last slot, fetch blocks we might have missed
		if lastSlot > 0 && types.Slot(currentSlot) > lastSlot+1 {
			for slot := uint64(lastSlot + 1); slot < currentSlot; slot++ {
				select {
				case <-ctx.Done():
					return
				default:
				}

				block, err := s.rpc.GetBlock(ctx, slot)
				if err != nil {
					// Slot might be skipped
					if _, ok := err.(*SlotSkippedError); ok {
						continue
					}
					// Other error - continue
					continue
				}

				select {
				case blockCh <- block:
					s.incrementBlocks(block.Slot)
				case <-ctx.Done():
					return
				}
			}
		}

		// Fetch current block
		block, err := s.rpc.GetBlock(ctx, currentSlot)
		if err != nil {
			if _, ok := err.(*SlotSkippedError); !ok {
				consecutiveErrors++
				s.incrementErrors()
			}
			lastSlot = types.Slot(currentSlot)

			select {
			case <-ctx.Done():
				return
			case <-time.After(s.config.RPCPollInterval):
				continue
			}
		}

		if block != nil {
			select {
			case blockCh <- block:
				s.incrementBlocks(block.Slot)
				lastSlot = block.Slot
			case <-ctx.Done():
				return
			}
		} else {
			lastSlot = types.Slot(currentSlot)
		}

		// Wait before polling again
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.config.RPCPollInterval):
		}
	}
}

// SubscribeSlots subscribes to slot updates.
// Returns a channel that receives slot status updates.
func (s *Subscriber) SubscribeSlots(ctx context.Context) (<-chan SlotUpdate, error) {
	if s.closed.Load() {
		return nil, fmt.Errorf("subscriber closed")
	}

	slotCh := make(chan SlotUpdate, s.config.BufferSize)

	s.activeStreams.Add(1)
	go s.slotSubscriptionLoop(ctx, slotCh)

	return slotCh, nil
}

// slotSubscriptionLoop handles the slot subscription with reconnection.
func (s *Subscriber) slotSubscriptionLoop(ctx context.Context, slotCh chan<- SlotUpdate) {
	defer s.activeStreams.Done()
	defer close(slotCh)

	var lastSlot uint64
	consecutiveErrors := 0

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if s.closed.Load() {
			return
		}

		// Get slots at different commitment levels
		processedSlot, err := s.rpc.GetSlotWithCommitment(ctx, CommitmentProcessed)
		if err != nil {
			consecutiveErrors++
			s.incrementErrors()

			if consecutiveErrors > s.config.MaxRetries && !s.config.AutoReconnect {
				return
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(s.getBackoffDuration(consecutiveErrors)):
				continue
			}
		}

		consecutiveErrors = 0

		// Send processed slot update if it's new
		if processedSlot > lastSlot {
			update := SlotUpdate{
				Slot:      types.Slot(processedSlot),
				Parent:    types.Slot(processedSlot - 1), // Approximation
				Status:    SlotStatusProcessed,
				Timestamp: time.Now().Unix(),
			}

			select {
			case slotCh <- update:
				s.incrementSlots(types.Slot(processedSlot))
				lastSlot = processedSlot
			case <-ctx.Done():
				return
			}
		}

		// Also check confirmed and finalized
		confirmedSlot, _ := s.rpc.GetSlotWithCommitment(ctx, CommitmentConfirmed)
		if confirmedSlot > 0 {
			update := SlotUpdate{
				Slot:      types.Slot(confirmedSlot),
				Parent:    types.Slot(confirmedSlot - 1),
				Status:    SlotStatusConfirmed,
				Timestamp: time.Now().Unix(),
			}

			select {
			case slotCh <- update:
			case <-ctx.Done():
				return
			default:
				// Don't block on confirmed updates
			}
		}

		finalizedSlot, _ := s.rpc.GetSlotWithCommitment(ctx, CommitmentFinalized)
		if finalizedSlot > 0 {
			update := SlotUpdate{
				Slot:      types.Slot(finalizedSlot),
				Parent:    types.Slot(finalizedSlot - 1),
				Status:    SlotStatusFinalized,
				Timestamp: time.Now().Unix(),
			}

			select {
			case slotCh <- update:
			case <-ctx.Done():
				return
			default:
				// Don't block on finalized updates
			}
		}

		// Wait before polling again
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.config.RPCPollInterval):
		}
	}
}

// SubscribeAccounts subscribes to account updates for specific accounts.
func (s *Subscriber) SubscribeAccounts(ctx context.Context, accounts []types.Pubkey) (<-chan *AccountUpdate, error) {
	if s.closed.Load() {
		return nil, fmt.Errorf("subscriber closed")
	}

	if len(accounts) == 0 {
		return nil, fmt.Errorf("at least one account must be specified")
	}

	accountCh := make(chan *AccountUpdate, s.config.BufferSize)

	s.activeStreams.Add(1)
	go s.accountSubscriptionLoop(ctx, accounts, accountCh)

	return accountCh, nil
}

// accountSubscriptionLoop handles account subscriptions via polling.
func (s *Subscriber) accountSubscriptionLoop(ctx context.Context, accounts []types.Pubkey, accountCh chan<- *AccountUpdate) {
	defer s.activeStreams.Done()
	defer close(accountCh)

	// Track last known state for each account
	lastState := make(map[types.Pubkey]*types.Account)
	consecutiveErrors := 0

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if s.closed.Load() {
			return
		}

		currentSlot, _ := s.rpc.GetSlot(ctx)

		for _, pubkey := range accounts {
			select {
			case <-ctx.Done():
				return
			default:
			}

			account, err := s.rpc.GetAccountInfo(ctx, pubkey)
			if err != nil {
				consecutiveErrors++
				s.incrementErrors()
				continue
			}

			consecutiveErrors = 0

			// Check if account changed
			last := lastState[pubkey]
			if accountChanged(last, account) {
				update := &AccountUpdate{
					Pubkey:    pubkey,
					Account:   account,
					Slot:      types.Slot(currentSlot),
					Timestamp: time.Now().Unix(),
				}

				select {
				case accountCh <- update:
					s.incrementAccounts()
					lastState[pubkey] = account
				case <-ctx.Done():
					return
				}
			}
		}

		// Wait before polling again
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.config.RPCPollInterval):
		}
	}
}

// accountChanged checks if an account state has changed.
func accountChanged(old, new *types.Account) bool {
	if old == nil && new == nil {
		return false
	}
	if old == nil || new == nil {
		return true
	}
	if old.Lamports != new.Lamports {
		return true
	}
	if old.Owner != new.Owner {
		return true
	}
	if old.Executable != new.Executable {
		return true
	}
	if len(old.Data) != len(new.Data) {
		return true
	}
	for i := range old.Data {
		if old.Data[i] != new.Data[i] {
			return true
		}
	}
	return false
}

// SubscribeTransactions subscribes to transactions matching the filter.
func (s *Subscriber) SubscribeTransactions(ctx context.Context, filter *SubscriptionFilter) (<-chan *TransactionUpdate, error) {
	if s.closed.Load() {
		return nil, fmt.Errorf("subscriber closed")
	}

	if filter == nil {
		filter = DefaultFilter()
	}

	txCh := make(chan *TransactionUpdate, s.config.BufferSize)

	s.activeStreams.Add(1)
	go s.transactionSubscriptionLoop(ctx, filter, txCh)

	return txCh, nil
}

// transactionSubscriptionLoop handles transaction subscriptions via block polling.
func (s *Subscriber) transactionSubscriptionLoop(ctx context.Context, filter *SubscriptionFilter, txCh chan<- *TransactionUpdate) {
	defer s.activeStreams.Done()
	defer close(txCh)

	var lastSlot types.Slot
	consecutiveErrors := 0

	commitment := filter.Commitment
	if commitment == "" {
		commitment = CommitmentConfirmed
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if s.closed.Load() {
			return
		}

		currentSlot, err := s.rpc.GetSlotWithCommitment(ctx, commitment)
		if err != nil {
			consecutiveErrors++
			s.incrementErrors()

			if consecutiveErrors > s.config.MaxRetries && !s.config.AutoReconnect {
				return
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(s.getBackoffDuration(consecutiveErrors)):
				continue
			}
		}

		consecutiveErrors = 0

		// Process missed slots
		startSlot := lastSlot + 1
		if lastSlot == 0 {
			startSlot = types.Slot(currentSlot)
		}

		for slot := uint64(startSlot); slot <= currentSlot; slot++ {
			select {
			case <-ctx.Done():
				return
			default:
			}

			block, err := s.rpc.GetBlock(ctx, slot)
			if err != nil {
				if _, ok := err.(*SlotSkippedError); ok {
					continue
				}
				continue
			}

			// Extract transactions from block
			for _, tx := range block.AllTransactions() {
				// Apply filters
				if !s.matchesFilter(&tx, filter) {
					continue
				}

				update := &TransactionUpdate{
					Signature:   tx.ID(),
					Slot:        block.Slot,
					Transaction: &tx,
					IsVote:      s.isVoteTransaction(&tx),
					Success:     true, // RPC doesn't give us this info easily
					Timestamp:   time.Now().Unix(),
				}

				select {
				case txCh <- update:
					s.incrementTransactions()
				case <-ctx.Done():
					return
				}
			}
		}

		lastSlot = types.Slot(currentSlot)

		// Wait before polling again
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.config.RPCPollInterval):
		}
	}
}

// matchesFilter checks if a transaction matches the subscription filter.
func (s *Subscriber) matchesFilter(tx *types.Transaction, filter *SubscriptionFilter) bool {
	// Check vote filter
	if !filter.IncludeVotes && s.isVoteTransaction(tx) {
		return false
	}

	// Check program filter
	if len(filter.Programs) > 0 {
		matched := false
		for _, ix := range tx.Message.Instructions {
			if int(ix.ProgramIDIndex) < len(tx.Message.AccountKeys) {
				programID := tx.Message.AccountKeys[ix.ProgramIDIndex]
				for _, p := range filter.Programs {
					if programID == p {
						matched = true
						break
					}
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check account filter
	if len(filter.Accounts) > 0 {
		matched := false
		for _, key := range tx.Message.AccountKeys {
			for _, a := range filter.Accounts {
				if key == a {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// isVoteTransaction checks if a transaction is a vote transaction.
func (s *Subscriber) isVoteTransaction(tx *types.Transaction) bool {
	for _, ix := range tx.Message.Instructions {
		if int(ix.ProgramIDIndex) < len(tx.Message.AccountKeys) {
			if tx.Message.AccountKeys[ix.ProgramIDIndex] == types.VoteProgramID {
				return true
			}
		}
	}
	return false
}

// getBackoffDuration calculates exponential backoff duration.
func (s *Subscriber) getBackoffDuration(attempt int) time.Duration {
	if attempt <= 0 {
		return s.config.RetryBaseDelay
	}

	delay := s.config.RetryBaseDelay
	for i := 0; i < attempt; i++ {
		delay = time.Duration(float64(delay) * s.config.RetryMultiplier)
		if delay > s.config.RetryMaxDelay {
			delay = s.config.RetryMaxDelay
			break
		}
	}

	return delay
}

// Statistics update methods
func (s *Subscriber) incrementBlocks(slot types.Slot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.BlocksReceived++
	s.stats.LastSlot = slot
	s.stats.LastBlockTime = time.Now().Unix()
}

func (s *Subscriber) incrementSlots(slot types.Slot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.SlotsReceived++
	s.stats.LastSlot = slot
}

func (s *Subscriber) incrementTransactions() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.TransactionsReceived++
}

func (s *Subscriber) incrementAccounts() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.AccountsReceived++
}

func (s *Subscriber) incrementErrors() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.Errors++
}

func (s *Subscriber) incrementReconnects() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.Reconnects++
}

// Close closes the subscriber and all active streams.
func (s *Subscriber) Close() {
	s.closed.Store(true)
	s.activeStreams.Wait()
}
