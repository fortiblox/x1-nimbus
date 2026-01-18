package token

import (
	"encoding/binary"
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// Account state sizes
const (
	// MintSize is the size of a serialized Mint account (82 bytes)
	MintSize = 82

	// TokenAccountSize is the size of a serialized TokenAccount (165 bytes)
	TokenAccountSize = 165
)

// Account state enum values
const (
	AccountStateUninitialized uint8 = 0
	AccountStateInitialized   uint8 = 1
	AccountStateFrozen        uint8 = 2
)

// COption represents an optional value (like Rust's COption)
// For Pubkey: 4 bytes tag + 32 bytes value = 36 bytes
type COption struct {
	IsSome bool
	Value  types.Pubkey
}

// COptionU64 represents an optional u64 value
// For u64: 4 bytes tag + 8 bytes value = 12 bytes
type COptionU64 struct {
	IsSome bool
	Value  uint64
}

// Mint represents an SPL Token mint account.
// Layout (82 bytes total):
//   - mint_authority: COption<Pubkey> (36 bytes) - 4 byte tag + 32 byte pubkey
//   - supply: u64 (8 bytes)
//   - decimals: u8 (1 byte)
//   - is_initialized: bool (1 byte)
//   - freeze_authority: COption<Pubkey> (36 bytes)
type Mint struct {
	MintAuthority   COption // Authority to mint new tokens
	Supply          uint64  // Total supply of tokens
	Decimals        uint8   // Number of decimal places
	IsInitialized   bool    // Whether the mint is initialized
	FreezeAuthority COption // Authority to freeze token accounts
}

// TokenAccount represents an SPL Token account.
// Layout (165 bytes total):
//   - mint: Pubkey (32 bytes)
//   - owner: Pubkey (32 bytes)
//   - amount: u64 (8 bytes)
//   - delegate: COption<Pubkey> (36 bytes)
//   - state: AccountState (1 byte)
//   - is_native: COption<u64> (12 bytes) - 4 byte tag + 8 byte value
//   - delegated_amount: u64 (8 bytes)
//   - close_authority: COption<Pubkey> (36 bytes)
type TokenAccount struct {
	Mint            types.Pubkey // The mint this account is associated with
	Owner           types.Pubkey // Owner of this account
	Amount          uint64       // Amount of tokens held
	Delegate        COption      // Optional delegate
	State           uint8        // Account state (Uninitialized, Initialized, Frozen)
	IsNative        COptionU64   // If Some, this is a wrapped SOL account
	DelegatedAmount uint64       // Amount delegated to the delegate
	CloseAuthority  COption      // Authority allowed to close this account
}

// DeserializeMint deserializes a Mint from bytes.
func DeserializeMint(data []byte) (*Mint, error) {
	if len(data) < MintSize {
		return nil, fmt.Errorf("%w: mint data too short, expected %d bytes, got %d",
			ErrInvalidAccountData, MintSize, len(data))
	}

	mint := &Mint{}
	offset := 0

	// mint_authority: COption<Pubkey> (36 bytes)
	mint.MintAuthority, offset = deserializeCOption(data, offset)

	// supply: u64 (8 bytes)
	mint.Supply = binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8

	// decimals: u8 (1 byte)
	mint.Decimals = data[offset]
	offset++

	// is_initialized: bool (1 byte)
	mint.IsInitialized = data[offset] != 0
	offset++

	// freeze_authority: COption<Pubkey> (36 bytes)
	mint.FreezeAuthority, _ = deserializeCOption(data, offset)

	return mint, nil
}

// Serialize serializes the Mint to bytes.
func (m *Mint) Serialize() []byte {
	data := make([]byte, MintSize)
	offset := 0

	// mint_authority: COption<Pubkey> (36 bytes)
	offset = serializeCOption(data, offset, m.MintAuthority)

	// supply: u64 (8 bytes)
	binary.LittleEndian.PutUint64(data[offset:offset+8], m.Supply)
	offset += 8

	// decimals: u8 (1 byte)
	data[offset] = m.Decimals
	offset++

	// is_initialized: bool (1 byte)
	if m.IsInitialized {
		data[offset] = 1
	} else {
		data[offset] = 0
	}
	offset++

	// freeze_authority: COption<Pubkey> (36 bytes)
	serializeCOption(data, offset, m.FreezeAuthority)

	return data
}

// DeserializeTokenAccount deserializes a TokenAccount from bytes.
func DeserializeTokenAccount(data []byte) (*TokenAccount, error) {
	if len(data) < TokenAccountSize {
		return nil, fmt.Errorf("%w: token account data too short, expected %d bytes, got %d",
			ErrInvalidAccountData, TokenAccountSize, len(data))
	}

	account := &TokenAccount{}
	offset := 0

	// mint: Pubkey (32 bytes)
	copy(account.Mint[:], data[offset:offset+32])
	offset += 32

	// owner: Pubkey (32 bytes)
	copy(account.Owner[:], data[offset:offset+32])
	offset += 32

	// amount: u64 (8 bytes)
	account.Amount = binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8

	// delegate: COption<Pubkey> (36 bytes)
	account.Delegate, offset = deserializeCOption(data, offset)

	// state: AccountState (1 byte)
	account.State = data[offset]
	offset++

	// is_native: COption<u64> (12 bytes)
	account.IsNative, offset = deserializeCOptionU64(data, offset)

	// delegated_amount: u64 (8 bytes)
	account.DelegatedAmount = binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8

	// close_authority: COption<Pubkey> (36 bytes)
	account.CloseAuthority, _ = deserializeCOption(data, offset)

	return account, nil
}

// Serialize serializes the TokenAccount to bytes.
func (a *TokenAccount) Serialize() []byte {
	data := make([]byte, TokenAccountSize)
	offset := 0

	// mint: Pubkey (32 bytes)
	copy(data[offset:offset+32], a.Mint[:])
	offset += 32

	// owner: Pubkey (32 bytes)
	copy(data[offset:offset+32], a.Owner[:])
	offset += 32

	// amount: u64 (8 bytes)
	binary.LittleEndian.PutUint64(data[offset:offset+8], a.Amount)
	offset += 8

	// delegate: COption<Pubkey> (36 bytes)
	offset = serializeCOption(data, offset, a.Delegate)

	// state: AccountState (1 byte)
	data[offset] = a.State
	offset++

	// is_native: COption<u64> (12 bytes)
	offset = serializeCOptionU64(data, offset, a.IsNative)

	// delegated_amount: u64 (8 bytes)
	binary.LittleEndian.PutUint64(data[offset:offset+8], a.DelegatedAmount)
	offset += 8

	// close_authority: COption<Pubkey> (36 bytes)
	serializeCOption(data, offset, a.CloseAuthority)

	return data
}

// IsFrozen returns true if the account is frozen.
func (a *TokenAccount) IsFrozen() bool {
	return a.State == AccountStateFrozen
}

// IsNativeAccount returns true if this is a wrapped SOL account.
func (a *TokenAccount) IsNativeAccount() bool {
	return a.IsNative.IsSome
}

// deserializeCOption deserializes a COption<Pubkey> from data at the given offset.
// Returns the COption and the new offset.
func deserializeCOption(data []byte, offset int) (COption, int) {
	opt := COption{}
	// COption tag is 4 bytes: 0 = None, 1 = Some
	tag := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	if tag == 1 {
		opt.IsSome = true
		copy(opt.Value[:], data[offset:offset+32])
	}
	offset += 32

	return opt, offset
}

// serializeCOption serializes a COption<Pubkey> to data at the given offset.
// Returns the new offset.
func serializeCOption(data []byte, offset int, opt COption) int {
	if opt.IsSome {
		binary.LittleEndian.PutUint32(data[offset:offset+4], 1)
		offset += 4
		copy(data[offset:offset+32], opt.Value[:])
	} else {
		binary.LittleEndian.PutUint32(data[offset:offset+4], 0)
		offset += 4
		// Zero out the pubkey space
		for i := 0; i < 32; i++ {
			data[offset+i] = 0
		}
	}
	offset += 32

	return offset
}

// deserializeCOptionU64 deserializes a COption<u64> from data at the given offset.
// Returns the COptionU64 and the new offset.
func deserializeCOptionU64(data []byte, offset int) (COptionU64, int) {
	opt := COptionU64{}
	// COption tag is 4 bytes: 0 = None, 1 = Some
	tag := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	if tag == 1 {
		opt.IsSome = true
		opt.Value = binary.LittleEndian.Uint64(data[offset : offset+8])
	}
	offset += 8

	return opt, offset
}

// serializeCOptionU64 serializes a COption<u64> to data at the given offset.
// Returns the new offset.
func serializeCOptionU64(data []byte, offset int, opt COptionU64) int {
	if opt.IsSome {
		binary.LittleEndian.PutUint32(data[offset:offset+4], 1)
		offset += 4
		binary.LittleEndian.PutUint64(data[offset:offset+8], opt.Value)
	} else {
		binary.LittleEndian.PutUint32(data[offset:offset+4], 0)
		offset += 4
		// Zero out the u64 space
		for i := 0; i < 8; i++ {
			data[offset+i] = 0
		}
	}
	offset += 8

	return offset
}

// NewMint creates a new Mint with the given parameters.
func NewMint(decimals uint8, mintAuthority *types.Pubkey, freezeAuthority *types.Pubkey) *Mint {
	mint := &Mint{
		Supply:        0,
		Decimals:      decimals,
		IsInitialized: true,
	}

	if mintAuthority != nil {
		mint.MintAuthority = COption{IsSome: true, Value: *mintAuthority}
	}

	if freezeAuthority != nil {
		mint.FreezeAuthority = COption{IsSome: true, Value: *freezeAuthority}
	}

	return mint
}

// NewTokenAccount creates a new TokenAccount with the given parameters.
func NewTokenAccount(mint types.Pubkey, owner types.Pubkey) *TokenAccount {
	return &TokenAccount{
		Mint:   mint,
		Owner:  owner,
		Amount: 0,
		State:  AccountStateInitialized,
	}
}
