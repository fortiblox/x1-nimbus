package types

import (
	"crypto/sha256"
	"encoding/binary"
)

// Account represents a Solana account.
type Account struct {
	Lamports   Lamports // Balance in lamports
	Data       []byte   // Account data
	Owner      Pubkey   // Program that owns this account
	Executable bool     // Is this a program account?
	RentEpoch  Epoch    // Last epoch rent was collected (deprecated)
}

// NewAccount creates a new account.
func NewAccount(lamports Lamports, owner Pubkey) *Account {
	return &Account{
		Lamports: lamports,
		Data:     nil,
		Owner:    owner,
	}
}

// NewAccountWithData creates a new account with data.
func NewAccountWithData(lamports Lamports, data []byte, owner Pubkey) *Account {
	return &Account{
		Lamports: lamports,
		Data:     data,
		Owner:    owner,
	}
}

// Clone creates a deep copy of the account.
func (a *Account) Clone() *Account {
	if a == nil {
		return nil
	}
	clone := &Account{
		Lamports:   a.Lamports,
		Owner:      a.Owner,
		Executable: a.Executable,
		RentEpoch:  a.RentEpoch,
	}
	if a.Data != nil {
		clone.Data = make([]byte, len(a.Data))
		copy(clone.Data, a.Data)
	}
	return clone
}

// DataLen returns the length of account data.
func (a *Account) DataLen() uint64 {
	if a.Data == nil {
		return 0
	}
	return uint64(len(a.Data))
}

// IsEmpty returns true if the account has zero lamports and no data.
func (a *Account) IsEmpty() bool {
	return a.Lamports == 0 && len(a.Data) == 0
}

// Hash computes the account hash for Merkle tree inclusion.
// Format: SHA256(lamports || rent_epoch || data || executable || owner || pubkey)
func (a *Account) Hash(pubkey Pubkey) Hash {
	h := sha256.New()

	// Write lamports (8 bytes, little-endian)
	var lamportsBuf [8]byte
	binary.LittleEndian.PutUint64(lamportsBuf[:], uint64(a.Lamports))
	h.Write(lamportsBuf[:])

	// Write rent epoch (8 bytes, little-endian)
	var rentEpochBuf [8]byte
	binary.LittleEndian.PutUint64(rentEpochBuf[:], uint64(a.RentEpoch))
	h.Write(rentEpochBuf[:])

	// Write data
	h.Write(a.Data)

	// Write executable (1 byte)
	if a.Executable {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}

	// Write owner (32 bytes)
	h.Write(a.Owner[:])

	// Write pubkey (32 bytes)
	h.Write(pubkey[:])

	var result Hash
	copy(result[:], h.Sum(nil))
	return result
}

// RentExemptMinimum calculates the minimum lamports for rent exemption.
// Formula: (data_size + 128) * 3480 lamports/byte/year * 2 years / 1_000_000_000
// Simplified: (data_size + 128) * 6960 / 1_000_000_000
func RentExemptMinimum(dataSize uint64) Lamports {
	// Rent parameters (mainnet values)
	const (
		lamportsPerByteYear = 3480
		exemptionThreshold  = 2 // years
		accountOverhead     = 128
	)
	return Lamports((dataSize + accountOverhead) * lamportsPerByteYear * exemptionThreshold)
}

// AccountMeta describes an account in an instruction.
type AccountMeta struct {
	Pubkey     Pubkey
	IsSigner   bool
	IsWritable bool
}

// AccountRef is a reference to an account with its pubkey.
type AccountRef struct {
	Pubkey  Pubkey
	Account *Account
}

// AccountDelta represents a change to an account.
type AccountDelta struct {
	Pubkey     Pubkey
	OldAccount *Account // nil if new account
	NewAccount *Account // nil if deleted
}

// IsCreation returns true if this is a new account.
func (d *AccountDelta) IsCreation() bool {
	return d.OldAccount == nil && d.NewAccount != nil
}

// IsDeletion returns true if this account was deleted.
func (d *AccountDelta) IsDeletion() bool {
	return d.OldAccount != nil && d.NewAccount == nil
}

// IsModification returns true if this account was modified.
func (d *AccountDelta) IsModification() bool {
	return d.OldAccount != nil && d.NewAccount != nil
}
