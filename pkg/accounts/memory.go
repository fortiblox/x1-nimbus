package accounts

import (
	"sync"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// MemoryDB is an in-memory implementation of AccountsDB for testing.
type MemoryDB struct {
	mu       sync.RWMutex
	accounts map[types.Pubkey]*types.Account
}

// NewMemoryDB creates a new in-memory account database.
func NewMemoryDB() *MemoryDB {
	return &MemoryDB{
		accounts: make(map[types.Pubkey]*types.Account),
	}
}

// GetAccount retrieves an account by pubkey.
// Returns nil, nil if account does not exist.
func (db *MemoryDB) GetAccount(pubkey types.Pubkey) (*types.Account, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	account, exists := db.accounts[pubkey]
	if !exists {
		return nil, nil
	}
	// Return a clone to prevent external modification
	return account.Clone(), nil
}

// SetAccount stores an account.
func (db *MemoryDB) SetAccount(pubkey types.Pubkey, account *types.Account) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	// Store a clone to prevent external modification
	db.accounts[pubkey] = account.Clone()
	return nil
}

// DeleteAccount removes an account.
func (db *MemoryDB) DeleteAccount(pubkey types.Pubkey) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	delete(db.accounts, pubkey)
	return nil
}

// HasAccount returns true if the account exists.
func (db *MemoryDB) HasAccount(pubkey types.Pubkey) bool {
	db.mu.RLock()
	defer db.mu.RUnlock()

	_, exists := db.accounts[pubkey]
	return exists
}

// GetAccountsCount returns the total number of accounts.
func (db *MemoryDB) GetAccountsCount() uint64 {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return uint64(len(db.accounts))
}

// Close closes the database.
func (db *MemoryDB) Close() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	// Clear the map
	db.accounts = make(map[types.Pubkey]*types.Account)
	return nil
}

// Ensure MemoryDB implements AccountsDB.
var _ AccountsDB = (*MemoryDB)(nil)
