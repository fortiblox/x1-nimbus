package bpf_loader

import (
	"encoding/binary"
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// Size constants for loader account metadata
const (
	// BUFFER_METADATA_SIZE is the size of buffer metadata.
	// Format: state_type (4 bytes) + has_authority (1 byte) + authority (32 bytes) = 37 bytes
	BUFFER_METADATA_SIZE = 37

	// PROGRAMDATA_METADATA_SIZE is the size of program data metadata.
	// Format: state_type (4 bytes) + slot (8 bytes) + has_authority (1 byte) + authority (32 bytes) = 45 bytes
	PROGRAMDATA_METADATA_SIZE = 45

	// PROGRAM_ACCOUNT_SIZE is the size of a program account.
	// Format: state_type (4 bytes) + programdata_address (32 bytes) = 36 bytes
	PROGRAM_ACCOUNT_SIZE = 36
)

// UpgradeableLoaderStateType represents the state type enum.
type UpgradeableLoaderStateType uint32

const (
	// StateUninitialized indicates an uninitialized account.
	StateUninitialized UpgradeableLoaderStateType = 0

	// StateBuffer indicates a buffer account for uploading program data.
	StateBuffer UpgradeableLoaderStateType = 1

	// StateProgram indicates a deployed program account.
	StateProgram UpgradeableLoaderStateType = 2

	// StateProgramData indicates the program data account.
	StateProgramData UpgradeableLoaderStateType = 3
)

// String returns the string representation of the state type.
func (s UpgradeableLoaderStateType) String() string {
	switch s {
	case StateUninitialized:
		return "Uninitialized"
	case StateBuffer:
		return "Buffer"
	case StateProgram:
		return "Program"
	case StateProgramData:
		return "ProgramData"
	default:
		return fmt.Sprintf("Unknown(%d)", s)
	}
}

// UpgradeableLoaderState represents the state of an upgradeable loader account.
type UpgradeableLoaderState struct {
	Type UpgradeableLoaderStateType

	// Buffer state fields
	BufferAuthority *types.Pubkey // Optional authority for buffer

	// Program state fields
	ProgramDataAddress types.Pubkey // Address of the program data account

	// ProgramData state fields
	Slot                    uint64        // Slot when the program was last deployed/upgraded
	UpgradeAuthorityAddress *types.Pubkey // Optional upgrade authority
}

// NewUninitializedState creates a new uninitialized state.
func NewUninitializedState() *UpgradeableLoaderState {
	return &UpgradeableLoaderState{
		Type: StateUninitialized,
	}
}

// NewBufferState creates a new buffer state.
func NewBufferState(authority *types.Pubkey) *UpgradeableLoaderState {
	return &UpgradeableLoaderState{
		Type:            StateBuffer,
		BufferAuthority: authority,
	}
}

// NewProgramState creates a new program state.
func NewProgramState(programDataAddress types.Pubkey) *UpgradeableLoaderState {
	return &UpgradeableLoaderState{
		Type:               StateProgram,
		ProgramDataAddress: programDataAddress,
	}
}

// NewProgramDataState creates a new program data state.
func NewProgramDataState(slot uint64, upgradeAuthority *types.Pubkey) *UpgradeableLoaderState {
	return &UpgradeableLoaderState{
		Type:                    StateProgramData,
		Slot:                    slot,
		UpgradeAuthorityAddress: upgradeAuthority,
	}
}

// Serialize serializes the state to bytes.
func (s *UpgradeableLoaderState) Serialize() ([]byte, error) {
	switch s.Type {
	case StateUninitialized:
		data := make([]byte, 4)
		binary.LittleEndian.PutUint32(data[0:4], uint32(StateUninitialized))
		return data, nil

	case StateBuffer:
		data := make([]byte, BUFFER_METADATA_SIZE)
		binary.LittleEndian.PutUint32(data[0:4], uint32(StateBuffer))
		if s.BufferAuthority != nil {
			data[4] = 1 // has authority
			copy(data[5:37], s.BufferAuthority[:])
		} else {
			data[4] = 0 // no authority
		}
		return data, nil

	case StateProgram:
		data := make([]byte, PROGRAM_ACCOUNT_SIZE)
		binary.LittleEndian.PutUint32(data[0:4], uint32(StateProgram))
		copy(data[4:36], s.ProgramDataAddress[:])
		return data, nil

	case StateProgramData:
		data := make([]byte, PROGRAMDATA_METADATA_SIZE)
		binary.LittleEndian.PutUint32(data[0:4], uint32(StateProgramData))
		binary.LittleEndian.PutUint64(data[4:12], s.Slot)
		if s.UpgradeAuthorityAddress != nil {
			data[12] = 1 // has authority
			copy(data[13:45], s.UpgradeAuthorityAddress[:])
		} else {
			data[12] = 0 // no authority (immutable)
		}
		return data, nil

	default:
		return nil, fmt.Errorf("%w: unknown state type %d", ErrInvalidAccountData, s.Type)
	}
}

// DeserializeUpgradeableLoaderState deserializes state from account data.
func DeserializeUpgradeableLoaderState(data []byte) (*UpgradeableLoaderState, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("%w: data too short", ErrInvalidAccountData)
	}

	stateType := UpgradeableLoaderStateType(binary.LittleEndian.Uint32(data[0:4]))

	switch stateType {
	case StateUninitialized:
		return NewUninitializedState(), nil

	case StateBuffer:
		if len(data) < BUFFER_METADATA_SIZE {
			return nil, fmt.Errorf("%w: buffer data too short", ErrInvalidAccountData)
		}
		state := &UpgradeableLoaderState{Type: StateBuffer}
		hasAuthority := data[4]
		if hasAuthority == 1 {
			var authority types.Pubkey
			copy(authority[:], data[5:37])
			state.BufferAuthority = &authority
		}
		return state, nil

	case StateProgram:
		if len(data) < PROGRAM_ACCOUNT_SIZE {
			return nil, fmt.Errorf("%w: program data too short", ErrInvalidAccountData)
		}
		state := &UpgradeableLoaderState{Type: StateProgram}
		copy(state.ProgramDataAddress[:], data[4:36])
		return state, nil

	case StateProgramData:
		if len(data) < PROGRAMDATA_METADATA_SIZE {
			return nil, fmt.Errorf("%w: program data metadata too short", ErrInvalidAccountData)
		}
		state := &UpgradeableLoaderState{Type: StateProgramData}
		state.Slot = binary.LittleEndian.Uint64(data[4:12])
		hasAuthority := data[12]
		if hasAuthority == 1 {
			var authority types.Pubkey
			copy(authority[:], data[13:45])
			state.UpgradeAuthorityAddress = &authority
		}
		return state, nil

	default:
		return nil, fmt.Errorf("%w: unknown state type %d", ErrInvalidAccountData, stateType)
	}
}

// IsBuffer returns true if this is a buffer state.
func (s *UpgradeableLoaderState) IsBuffer() bool {
	return s.Type == StateBuffer
}

// IsProgram returns true if this is a program state.
func (s *UpgradeableLoaderState) IsProgram() bool {
	return s.Type == StateProgram
}

// IsProgramData returns true if this is a program data state.
func (s *UpgradeableLoaderState) IsProgramData() bool {
	return s.Type == StateProgramData
}

// IsUninitialized returns true if this is an uninitialized state.
func (s *UpgradeableLoaderState) IsUninitialized() bool {
	return s.Type == StateUninitialized
}

// GetBufferDataOffset returns the offset where buffer data starts.
func GetBufferDataOffset() int {
	return BUFFER_METADATA_SIZE
}

// GetProgramDataOffset returns the offset where program data starts.
func GetProgramDataOffset() int {
	return PROGRAMDATA_METADATA_SIZE
}

// WriteStateToAccountData writes the state to account data at offset 0.
func WriteStateToAccountData(data []byte, state *UpgradeableLoaderState) error {
	serialized, err := state.Serialize()
	if err != nil {
		return err
	}
	if len(data) < len(serialized) {
		return fmt.Errorf("%w: account data too small for state", ErrInvalidAccountData)
	}
	copy(data, serialized)
	return nil
}

// GetProgramDataAddress derives the program data address for a program.
func GetProgramDataAddress(programID types.Pubkey) (types.Pubkey, uint8, error) {
	// The program data address is a PDA derived from the program ID
	seeds := [][]byte{programID[:]}
	return FindProgramAddress(seeds, types.BPFLoaderUpgradeableProgramID)
}

// FindProgramAddress finds a program-derived address.
// This is a simplified version - the full implementation would be in the PDA syscall.
func FindProgramAddress(seeds [][]byte, programID types.Pubkey) (types.Pubkey, uint8, error) {
	// Try bump seeds from 255 down to 0
	for bump := uint8(255); bump > 0; bump-- {
		address, err := CreateProgramAddress(append(seeds, []byte{bump}), programID)
		if err == nil {
			return address, bump, nil
		}
	}
	return types.ZeroPubkey, 0, fmt.Errorf("could not find valid program address")
}

// CreateProgramAddress creates a program-derived address from seeds.
func CreateProgramAddress(seeds [][]byte, programID types.Pubkey) (types.Pubkey, error) {
	// Concatenate all seeds
	var data []byte
	for _, seed := range seeds {
		if len(seed) > 32 {
			return types.ZeroPubkey, fmt.Errorf("seed too long")
		}
		data = append(data, seed...)
	}

	// Add program ID and PDA marker
	data = append(data, programID[:]...)
	data = append(data, []byte("ProgramDerivedAddress")...)

	// Hash to get the address
	hash := types.SHA256(data)

	// Check if the address is on the ed25519 curve (simplified check)
	// A proper implementation would verify this is NOT on the curve
	var pubkey types.Pubkey
	copy(pubkey[:], hash[:])

	return pubkey, nil
}
