package address_lookup_table

import (
	"encoding/binary"
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/svm/syscall"
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// State constants
const (
	// LOOKUP_TABLE_META_SIZE is the fixed size of the lookup table metadata in bytes.
	// Layout:
	//   - deactivation_slot: u64 (8 bytes)
	//   - last_extended_slot: u64 (8 bytes)
	//   - last_extended_slot_start_index: u8 (1 byte)
	//   - has_authority: u8 (1 byte) - 0 = no authority, 1 = has authority
	//   - authority: [32]byte (32 bytes, only valid if has_authority == 1)
	//   - padding: [6]byte (6 bytes for alignment)
	// Total: 8 + 8 + 1 + 1 + 32 + 6 = 56 bytes
	LOOKUP_TABLE_META_SIZE = 56

	// SLOT_MAX represents "not deactivated" (u64::MAX equivalent)
	SLOT_MAX = ^uint64(0)

	// MaxAddresses is the maximum number of addresses in a lookup table.
	MaxAddresses = 256

	// DeactivationCooldownSlots is the number of slots to wait before closing.
	// In Solana, this is typically 512 slots (about 3-4 minutes).
	DeactivationCooldownSlots = 512
)

// LookupTableMeta contains the metadata for an address lookup table.
type LookupTableMeta struct {
	// DeactivationSlot is the slot when deactivation was requested.
	// SLOT_MAX means the table is not deactivated.
	DeactivationSlot uint64

	// LastExtendedSlot is the last slot when addresses were added.
	LastExtendedSlot uint64

	// LastExtendedSlotStartIndex is the starting index for addresses
	// added in the last extended slot (used for deactivation checks).
	LastExtendedSlotStartIndex uint8

	// Authority is the optional authority that can modify the table.
	// If nil, the table is frozen and cannot be modified.
	Authority *types.Pubkey
}

// IsActive returns true if the lookup table is active (not deactivated).
func (m *LookupTableMeta) IsActive() bool {
	return m.DeactivationSlot == SLOT_MAX
}

// IsFrozen returns true if the lookup table is frozen (no authority).
func (m *LookupTableMeta) IsFrozen() bool {
	return m.Authority == nil
}

// AddressLookupTable represents an address lookup table account.
type AddressLookupTable struct {
	// Meta contains the lookup table metadata.
	Meta LookupTableMeta

	// Addresses is the list of addresses in the lookup table.
	Addresses []types.Pubkey
}

// NewAddressLookupTable creates a new empty address lookup table.
func NewAddressLookupTable(authority types.Pubkey) *AddressLookupTable {
	return &AddressLookupTable{
		Meta: LookupTableMeta{
			DeactivationSlot:           SLOT_MAX,
			LastExtendedSlot:           0,
			LastExtendedSlotStartIndex: 0,
			Authority:                  &authority,
		},
		Addresses: make([]types.Pubkey, 0),
	}
}

// Serialize serializes the address lookup table to bytes.
func (alt *AddressLookupTable) Serialize() []byte {
	// Calculate total size: metadata + addresses
	totalSize := LOOKUP_TABLE_META_SIZE + len(alt.Addresses)*32
	data := make([]byte, totalSize)

	// Write deactivation slot (8 bytes)
	binary.LittleEndian.PutUint64(data[0:8], alt.Meta.DeactivationSlot)

	// Write last extended slot (8 bytes)
	binary.LittleEndian.PutUint64(data[8:16], alt.Meta.LastExtendedSlot)

	// Write last extended slot start index (1 byte)
	data[16] = alt.Meta.LastExtendedSlotStartIndex

	// Write authority presence flag and authority (1 + 32 bytes)
	if alt.Meta.Authority != nil {
		data[17] = 1
		copy(data[18:50], alt.Meta.Authority[:])
	} else {
		data[17] = 0
		// Leave bytes 18-49 as zeros
	}

	// Bytes 50-55 are padding (already zeros)

	// Write addresses
	offset := LOOKUP_TABLE_META_SIZE
	for _, addr := range alt.Addresses {
		copy(data[offset:offset+32], addr[:])
		offset += 32
	}

	return data
}

// DeserializeAddressLookupTable deserializes bytes into an AddressLookupTable.
func DeserializeAddressLookupTable(data []byte) (*AddressLookupTable, error) {
	if len(data) < LOOKUP_TABLE_META_SIZE {
		return nil, fmt.Errorf("%w: data too short for lookup table meta, got %d bytes",
			ErrInvalidInstructionData, len(data))
	}

	alt := &AddressLookupTable{}

	// Read deactivation slot
	alt.Meta.DeactivationSlot = binary.LittleEndian.Uint64(data[0:8])

	// Read last extended slot
	alt.Meta.LastExtendedSlot = binary.LittleEndian.Uint64(data[8:16])

	// Read last extended slot start index
	alt.Meta.LastExtendedSlotStartIndex = data[16]

	// Read authority
	hasAuthority := data[17]
	if hasAuthority == 1 {
		var authority types.Pubkey
		copy(authority[:], data[18:50])
		alt.Meta.Authority = &authority
	} else {
		alt.Meta.Authority = nil
	}

	// Calculate number of addresses
	addressDataLen := len(data) - LOOKUP_TABLE_META_SIZE
	if addressDataLen%32 != 0 {
		return nil, fmt.Errorf("%w: address data not aligned to 32 bytes", ErrInvalidInstructionData)
	}

	numAddresses := addressDataLen / 32
	alt.Addresses = make([]types.Pubkey, numAddresses)

	offset := LOOKUP_TABLE_META_SIZE
	for i := 0; i < numAddresses; i++ {
		copy(alt.Addresses[i][:], data[offset:offset+32])
		offset += 32
	}

	return alt, nil
}

// CalculateAccountSize calculates the account size needed for a given number of addresses.
func CalculateAccountSize(numAddresses int) int {
	return LOOKUP_TABLE_META_SIZE + numAddresses*32
}

// DeriveLookupTableAddress derives the PDA for a lookup table.
// The address is derived from the authority pubkey and recent slot.
// Returns the derived address and bump seed.
func DeriveLookupTableAddress(authority types.Pubkey, recentSlot uint64) (types.Pubkey, uint8) {
	// Convert slot to bytes (little-endian)
	slotBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(slotBytes, recentSlot)

	// Seeds: [authority, slot_bytes]
	seeds := [][]byte{
		authority[:],
		slotBytes,
	}

	// Derive PDA
	pda, bump, found := syscall.FindProgramAddressSync(seeds, types.AddressLookupTableProgramID)
	if !found {
		// This should not happen in practice, but return zero address if it does
		return types.ZeroPubkey, 0
	}

	return pda, bump
}

// VerifyDerivedAddress verifies that the given address matches the derived PDA.
func VerifyDerivedAddress(address types.Pubkey, authority types.Pubkey, recentSlot uint64, bumpSeed uint8) bool {
	// Convert slot to bytes (little-endian)
	slotBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(slotBytes, recentSlot)

	// Seeds with bump: [authority, slot_bytes, bump]
	seeds := [][]byte{
		authority[:],
		slotBytes,
		{bumpSeed},
	}

	// Create PDA with specific bump
	pda, valid := syscall.CreateProgramAddress(seeds, types.AddressLookupTableProgramID)
	if !valid {
		return false
	}

	return pda == address
}

// AddressCount returns the number of addresses in the lookup table.
func (alt *AddressLookupTable) AddressCount() int {
	return len(alt.Addresses)
}

// CanAddAddresses returns true if the specified number of addresses can be added.
func (alt *AddressLookupTable) CanAddAddresses(count int) bool {
	return len(alt.Addresses)+count <= MaxAddresses
}

// GetAddress returns the address at the given index.
func (alt *AddressLookupTable) GetAddress(index uint8) (types.Pubkey, error) {
	if int(index) >= len(alt.Addresses) {
		return types.ZeroPubkey, fmt.Errorf("address index %d out of bounds (table has %d addresses)",
			index, len(alt.Addresses))
	}
	return alt.Addresses[index], nil
}
