package accounts

import (
	"fmt"
	"sync/atomic"

	"github.com/dgraph-io/badger/v4"
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

const (
	// accountKeyPrefix is the prefix for account keys in BadgerDB.
	accountKeyPrefix = "account:"
)

// BadgerDB is a persistent implementation of AccountsDB using BadgerDB.
type BadgerDB struct {
	db    *badger.DB
	count atomic.Uint64
}

// NewBadgerDB creates a new BadgerDB account database at the specified path.
func NewBadgerDB(path string) (*BadgerDB, error) {
	opts := badger.DefaultOptions(path)
	opts.Logger = nil // Disable badger logging

	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open badger db: %w", err)
	}

	bdb := &BadgerDB{
		db: db,
	}

	// Count existing accounts
	count, err := bdb.countAccounts()
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to count accounts: %w", err)
	}
	bdb.count.Store(count)

	return bdb, nil
}

// makeAccountKey creates the key for an account.
func makeAccountKey(pubkey types.Pubkey) []byte {
	key := make([]byte, len(accountKeyPrefix)+32)
	copy(key, accountKeyPrefix)
	copy(key[len(accountKeyPrefix):], pubkey[:])
	return key
}

// GetAccount retrieves an account by pubkey.
// Returns nil, nil if account does not exist.
func (db *BadgerDB) GetAccount(pubkey types.Pubkey) (*types.Account, error) {
	key := makeAccountKey(pubkey)
	var account *types.Account

	err := db.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err == badger.ErrKeyNotFound {
			return nil
		}
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			var deserErr error
			account, deserErr = DeserializeAccount(val)
			return deserErr
		})
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get account: %w", err)
	}

	return account, nil
}

// SetAccount stores an account.
func (db *BadgerDB) SetAccount(pubkey types.Pubkey, account *types.Account) error {
	key := makeAccountKey(pubkey)

	data, err := SerializeAccount(account)
	if err != nil {
		return fmt.Errorf("failed to serialize account: %w", err)
	}

	err = db.db.Update(func(txn *badger.Txn) error {
		// Check if account already exists
		_, err := txn.Get(key)
		isNew := err == badger.ErrKeyNotFound

		if err := txn.Set(key, data); err != nil {
			return err
		}

		if isNew {
			db.count.Add(1)
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to set account: %w", err)
	}

	return nil
}

// DeleteAccount removes an account.
func (db *BadgerDB) DeleteAccount(pubkey types.Pubkey) error {
	key := makeAccountKey(pubkey)

	err := db.db.Update(func(txn *badger.Txn) error {
		// Check if account exists
		_, err := txn.Get(key)
		if err == badger.ErrKeyNotFound {
			return nil // Already deleted
		}
		if err != nil {
			return err
		}

		if err := txn.Delete(key); err != nil {
			return err
		}

		db.count.Add(^uint64(0)) // Decrement by 1
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to delete account: %w", err)
	}

	return nil
}

// HasAccount returns true if the account exists.
func (db *BadgerDB) HasAccount(pubkey types.Pubkey) bool {
	key := makeAccountKey(pubkey)
	var exists bool

	db.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get(key)
		exists = err == nil
		return nil
	})

	return exists
}

// GetAccountsCount returns the total number of accounts.
func (db *BadgerDB) GetAccountsCount() uint64 {
	return db.count.Load()
}

// Close closes the database.
func (db *BadgerDB) Close() error {
	return db.db.Close()
}

// countAccounts counts all accounts in the database.
func (db *BadgerDB) countAccounts() (uint64, error) {
	var count uint64
	prefix := []byte(accountKeyPrefix)

	err := db.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false // Only need keys for counting
		opts.Prefix = prefix

		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			count++
		}
		return nil
	})

	return count, err
}

// Ensure BadgerDB implements AccountsDB.
var _ AccountsDB = (*BadgerDB)(nil)
