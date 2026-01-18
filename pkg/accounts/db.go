// Package accounts provides account storage and management for X1-Nimbus.
package accounts

import (
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// AccountsDB defines the interface for account storage.
type AccountsDB interface {
	// GetAccount retrieves an account by pubkey.
	// Returns nil, nil if account does not exist.
	GetAccount(pubkey types.Pubkey) (*types.Account, error)

	// SetAccount stores an account.
	SetAccount(pubkey types.Pubkey, account *types.Account) error

	// DeleteAccount removes an account.
	DeleteAccount(pubkey types.Pubkey) error

	// HasAccount returns true if the account exists.
	HasAccount(pubkey types.Pubkey) bool

	// GetAccountsCount returns the total number of accounts.
	GetAccountsCount() uint64

	// Close closes the database.
	Close() error
}
