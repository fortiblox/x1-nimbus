package vote

import (
	"encoding/binary"
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// Vote Program instruction discriminators (first 4 bytes of instruction data)
const (
	InstructionInitializeAccount           uint32 = 0
	InstructionAuthorize                   uint32 = 1
	InstructionVote                        uint32 = 2
	InstructionWithdraw                    uint32 = 3
	InstructionUpdateValidatorIdentity     uint32 = 4
	InstructionUpdateCommission            uint32 = 5
	InstructionVoteSwitch                  uint32 = 6
	InstructionAuthorizeChecked            uint32 = 7
	InstructionUpdateVoteState             uint32 = 8
	InstructionUpdateVoteStateSwitch       uint32 = 9
	InstructionAuthorizeWithSeed           uint32 = 10
	InstructionAuthorizeCheckedWithSeed    uint32 = 11
	InstructionCompactUpdateVoteState      uint32 = 12
	InstructionCompactUpdateVoteStateSwitch uint32 = 13
	InstructionTowerSync                   uint32 = 14
	InstructionTowerSyncSwitch             uint32 = 15
)

// VoteInit contains initialization parameters for a vote account.
type VoteInit struct {
	NodePubkey           types.Pubkey // Validator identity pubkey
	AuthorizedVoter      types.Pubkey // Authority to vote
	AuthorizedWithdrawer types.Pubkey // Authority to withdraw
	Commission           uint8        // Commission rate (0-100)
}

// Decode decodes a VoteInit from bytes.
func (v *VoteInit) Decode(data []byte) error {
	// Data layout: node_pubkey (32) + authorized_voter (32) + authorized_withdrawer (32) + commission (1) = 97 bytes
	if len(data) < 97 {
		return fmt.Errorf("%w: VoteInit requires 97 bytes, got %d", ErrInvalidInstructionData, len(data))
	}
	copy(v.NodePubkey[:], data[0:32])
	copy(v.AuthorizedVoter[:], data[32:64])
	copy(v.AuthorizedWithdrawer[:], data[64:96])
	v.Commission = data[96]
	return nil
}

// Encode encodes a VoteInit to bytes.
func (v *VoteInit) Encode() []byte {
	data := make([]byte, 97)
	copy(data[0:32], v.NodePubkey[:])
	copy(data[32:64], v.AuthorizedVoter[:])
	copy(data[64:96], v.AuthorizedWithdrawer[:])
	data[96] = v.Commission
	return data
}

// InitializeAccountInstruction represents an InitializeAccount instruction.
type InitializeAccountInstruction struct {
	VoteInit VoteInit
}

// Decode decodes an InitializeAccount instruction from bytes.
func (inst *InitializeAccountInstruction) Decode(data []byte) error {
	return inst.VoteInit.Decode(data)
}

// Encode encodes an InitializeAccount instruction to bytes.
func (inst *InitializeAccountInstruction) Encode() []byte {
	data := make([]byte, 4+97)
	binary.LittleEndian.PutUint32(data[0:4], InstructionInitializeAccount)
	copy(data[4:], inst.VoteInit.Encode())
	return data
}

// AuthorizeInstruction represents an Authorize instruction.
type AuthorizeInstruction struct {
	NewAuthority   types.Pubkey  // New authority pubkey
	AuthorizeType  VoteAuthorize // Type of authorization to change
}

// Decode decodes an Authorize instruction from bytes.
func (inst *AuthorizeInstruction) Decode(data []byte) error {
	// Data layout: new_authority (32) + authorize_type (4) = 36 bytes
	if len(data) < 36 {
		return fmt.Errorf("%w: Authorize requires 36 bytes, got %d", ErrInvalidInstructionData, len(data))
	}
	copy(inst.NewAuthority[:], data[0:32])
	authType := binary.LittleEndian.Uint32(data[32:36])
	if authType > 1 {
		return fmt.Errorf("%w: authorize type must be 0 or 1", ErrInvalidAuthorizeType)
	}
	inst.AuthorizeType = VoteAuthorize(authType)
	return nil
}

// Encode encodes an Authorize instruction to bytes.
func (inst *AuthorizeInstruction) Encode() []byte {
	data := make([]byte, 4+36)
	binary.LittleEndian.PutUint32(data[0:4], InstructionAuthorize)
	copy(data[4:36], inst.NewAuthority[:])
	binary.LittleEndian.PutUint32(data[36:40], uint32(inst.AuthorizeType))
	return data
}

// Vote represents a vote with slots, hash, and optional timestamp.
type Vote struct {
	Slots     []uint64    // Slots being voted on
	Hash      types.Hash  // Bank hash at last slot
	Timestamp *int64      // Optional timestamp
}

// Decode decodes a Vote from bytes.
func (v *Vote) Decode(data []byte) error {
	offset := 0

	// Number of slots (4 bytes)
	if offset+4 > len(data) {
		return fmt.Errorf("%w: Vote missing slots length", ErrInvalidInstructionData)
	}
	numSlots := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	if numSlots > MaxLockoutHistory {
		return fmt.Errorf("%w: too many slots in vote: %d > %d", ErrTooManyVotes, numSlots, MaxLockoutHistory)
	}

	// Slots (8 bytes each)
	requiredLen := offset + int(numSlots)*8 + 32 + 1 // slots + hash + timestamp flag
	if len(data) < requiredLen {
		return fmt.Errorf("%w: Vote requires at least %d bytes, got %d", ErrInvalidInstructionData, requiredLen, len(data))
	}

	v.Slots = make([]uint64, numSlots)
	for i := uint32(0); i < numSlots; i++ {
		v.Slots[i] = binary.LittleEndian.Uint64(data[offset : offset+8])
		offset += 8
	}

	// Hash (32 bytes)
	copy(v.Hash[:], data[offset:offset+32])
	offset += 32

	// Timestamp option (1 byte flag + 8 bytes if present)
	if data[offset] == 1 {
		offset++
		if offset+8 > len(data) {
			return fmt.Errorf("%w: Vote missing timestamp value", ErrInvalidInstructionData)
		}
		ts := int64(binary.LittleEndian.Uint64(data[offset : offset+8]))
		v.Timestamp = &ts
	} else {
		v.Timestamp = nil
	}

	return nil
}

// Encode encodes a Vote to bytes.
func (v *Vote) Encode() []byte {
	size := 4 + len(v.Slots)*8 + 32 + 1
	if v.Timestamp != nil {
		size += 8
	}
	data := make([]byte, size)
	offset := 0

	// Number of slots
	binary.LittleEndian.PutUint32(data[offset:offset+4], uint32(len(v.Slots)))
	offset += 4

	// Slots
	for _, slot := range v.Slots {
		binary.LittleEndian.PutUint64(data[offset:offset+8], slot)
		offset += 8
	}

	// Hash
	copy(data[offset:offset+32], v.Hash[:])
	offset += 32

	// Timestamp option
	if v.Timestamp != nil {
		data[offset] = 1
		offset++
		binary.LittleEndian.PutUint64(data[offset:offset+8], uint64(*v.Timestamp))
	} else {
		data[offset] = 0
	}

	return data
}

// VoteInstruction represents a Vote instruction.
type VoteInstruction struct {
	Vote Vote
}

// Decode decodes a Vote instruction from bytes.
func (inst *VoteInstruction) Decode(data []byte) error {
	return inst.Vote.Decode(data)
}

// Encode encodes a Vote instruction to bytes.
func (inst *VoteInstruction) Encode() []byte {
	voteData := inst.Vote.Encode()
	data := make([]byte, 4+len(voteData))
	binary.LittleEndian.PutUint32(data[0:4], InstructionVote)
	copy(data[4:], voteData)
	return data
}

// WithdrawInstruction represents a Withdraw instruction.
type WithdrawInstruction struct {
	Lamports uint64 // Amount of lamports to withdraw
}

// Decode decodes a Withdraw instruction from bytes.
func (inst *WithdrawInstruction) Decode(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("%w: Withdraw requires 8 bytes, got %d", ErrInvalidInstructionData, len(data))
	}
	inst.Lamports = binary.LittleEndian.Uint64(data[0:8])
	return nil
}

// Encode encodes a Withdraw instruction to bytes.
func (inst *WithdrawInstruction) Encode() []byte {
	data := make([]byte, 4+8)
	binary.LittleEndian.PutUint32(data[0:4], InstructionWithdraw)
	binary.LittleEndian.PutUint64(data[4:12], inst.Lamports)
	return data
}

// UpdateValidatorIdentityInstruction represents an UpdateValidatorIdentity instruction.
type UpdateValidatorIdentityInstruction struct {
	// No additional data; new identity is passed as account
}

// Decode decodes an UpdateValidatorIdentity instruction from bytes.
func (inst *UpdateValidatorIdentityInstruction) Decode(data []byte) error {
	// No additional data to decode
	return nil
}

// Encode encodes an UpdateValidatorIdentity instruction to bytes.
func (inst *UpdateValidatorIdentityInstruction) Encode() []byte {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data[0:4], InstructionUpdateValidatorIdentity)
	return data
}

// UpdateCommissionInstruction represents an UpdateCommission instruction.
type UpdateCommissionInstruction struct {
	Commission uint8 // New commission rate (0-100)
}

// Decode decodes an UpdateCommission instruction from bytes.
func (inst *UpdateCommissionInstruction) Decode(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("%w: UpdateCommission requires 1 byte, got %d", ErrInvalidInstructionData, len(data))
	}
	inst.Commission = data[0]
	return nil
}

// Encode encodes an UpdateCommission instruction to bytes.
func (inst *UpdateCommissionInstruction) Encode() []byte {
	data := make([]byte, 4+1)
	binary.LittleEndian.PutUint32(data[0:4], InstructionUpdateCommission)
	data[4] = inst.Commission
	return data
}

// VoteSwitchInstruction represents a VoteSwitch instruction.
type VoteSwitchInstruction struct {
	Vote Vote       // Vote to cast
	Hash types.Hash // Proof hash for switch
}

// Decode decodes a VoteSwitch instruction from bytes.
func (inst *VoteSwitchInstruction) Decode(data []byte) error {
	if err := inst.Vote.Decode(data); err != nil {
		return err
	}
	// Calculate offset where hash should be
	offset := 4 + len(inst.Vote.Slots)*8 + 32 + 1
	if inst.Vote.Timestamp != nil {
		offset += 8
	}
	if offset+32 > len(data) {
		return fmt.Errorf("%w: VoteSwitch missing hash", ErrInvalidInstructionData)
	}
	copy(inst.Hash[:], data[offset:offset+32])
	return nil
}

// Encode encodes a VoteSwitch instruction to bytes.
func (inst *VoteSwitchInstruction) Encode() []byte {
	voteData := inst.Vote.Encode()
	data := make([]byte, 4+len(voteData)+32)
	binary.LittleEndian.PutUint32(data[0:4], InstructionVoteSwitch)
	copy(data[4:4+len(voteData)], voteData)
	copy(data[4+len(voteData):], inst.Hash[:])
	return data
}

// AuthorizeCheckedInstruction represents an AuthorizeChecked instruction.
type AuthorizeCheckedInstruction struct {
	AuthorizeType VoteAuthorize // Type of authorization to change
}

// Decode decodes an AuthorizeChecked instruction from bytes.
func (inst *AuthorizeCheckedInstruction) Decode(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("%w: AuthorizeChecked requires 4 bytes, got %d", ErrInvalidInstructionData, len(data))
	}
	authType := binary.LittleEndian.Uint32(data[0:4])
	if authType > 1 {
		return fmt.Errorf("%w: authorize type must be 0 or 1", ErrInvalidAuthorizeType)
	}
	inst.AuthorizeType = VoteAuthorize(authType)
	return nil
}

// Encode encodes an AuthorizeChecked instruction to bytes.
func (inst *AuthorizeCheckedInstruction) Encode() []byte {
	data := make([]byte, 4+4)
	binary.LittleEndian.PutUint32(data[0:4], InstructionAuthorizeChecked)
	binary.LittleEndian.PutUint32(data[4:8], uint32(inst.AuthorizeType))
	return data
}

// VoteStateUpdate represents a vote state update.
type VoteStateUpdate struct {
	Lockouts  []Lockout  // Vote lockouts
	Root      *uint64    // Optional root slot
	Hash      types.Hash // Bank hash
	Timestamp *int64     // Optional timestamp
}

// Decode decodes a VoteStateUpdate from bytes.
func (v *VoteStateUpdate) Decode(data []byte) error {
	offset := 0

	// Number of lockouts (4 bytes)
	if offset+4 > len(data) {
		return fmt.Errorf("%w: VoteStateUpdate missing lockouts length", ErrInvalidInstructionData)
	}
	numLockouts := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Lockouts (12 bytes each)
	if numLockouts > MaxLockoutHistory {
		return fmt.Errorf("%w: too many lockouts: %d > %d", ErrTooManyVotes, numLockouts, MaxLockoutHistory)
	}

	v.Lockouts = make([]Lockout, numLockouts)
	for i := uint32(0); i < numLockouts; i++ {
		if offset+12 > len(data) {
			return fmt.Errorf("%w: VoteStateUpdate truncated at lockout %d", ErrInvalidInstructionData, i)
		}
		lockout, err := DecodeLockout(data[offset : offset+12])
		if err != nil {
			return err
		}
		v.Lockouts[i] = *lockout
		offset += 12
	}

	// Root option (1 byte flag + 8 bytes if present)
	if offset+1 > len(data) {
		return fmt.Errorf("%w: VoteStateUpdate missing root flag", ErrInvalidInstructionData)
	}
	if data[offset] == 1 {
		offset++
		if offset+8 > len(data) {
			return fmt.Errorf("%w: VoteStateUpdate missing root value", ErrInvalidInstructionData)
		}
		root := binary.LittleEndian.Uint64(data[offset : offset+8])
		v.Root = &root
		offset += 8
	} else {
		v.Root = nil
		offset++
	}

	// Hash (32 bytes)
	if offset+32 > len(data) {
		return fmt.Errorf("%w: VoteStateUpdate missing hash", ErrInvalidInstructionData)
	}
	copy(v.Hash[:], data[offset:offset+32])
	offset += 32

	// Timestamp option (1 byte flag + 8 bytes if present)
	if offset+1 > len(data) {
		return fmt.Errorf("%w: VoteStateUpdate missing timestamp flag", ErrInvalidInstructionData)
	}
	if data[offset] == 1 {
		offset++
		if offset+8 > len(data) {
			return fmt.Errorf("%w: VoteStateUpdate missing timestamp value", ErrInvalidInstructionData)
		}
		ts := int64(binary.LittleEndian.Uint64(data[offset : offset+8]))
		v.Timestamp = &ts
	} else {
		v.Timestamp = nil
	}

	return nil
}

// Encode encodes a VoteStateUpdate to bytes.
func (v *VoteStateUpdate) Encode() []byte {
	size := 4 + len(v.Lockouts)*12 + 1 + 32 + 1
	if v.Root != nil {
		size += 8
	}
	if v.Timestamp != nil {
		size += 8
	}
	data := make([]byte, size)
	offset := 0

	// Number of lockouts
	binary.LittleEndian.PutUint32(data[offset:offset+4], uint32(len(v.Lockouts)))
	offset += 4

	// Lockouts
	for _, lockout := range v.Lockouts {
		copy(data[offset:offset+12], lockout.Encode())
		offset += 12
	}

	// Root option
	if v.Root != nil {
		data[offset] = 1
		offset++
		binary.LittleEndian.PutUint64(data[offset:offset+8], *v.Root)
		offset += 8
	} else {
		data[offset] = 0
		offset++
	}

	// Hash
	copy(data[offset:offset+32], v.Hash[:])
	offset += 32

	// Timestamp option
	if v.Timestamp != nil {
		data[offset] = 1
		offset++
		binary.LittleEndian.PutUint64(data[offset:offset+8], uint64(*v.Timestamp))
	} else {
		data[offset] = 0
	}

	return data
}

// UpdateVoteStateInstruction represents an UpdateVoteState instruction.
type UpdateVoteStateInstruction struct {
	VoteStateUpdate VoteStateUpdate
}

// Decode decodes an UpdateVoteState instruction from bytes.
func (inst *UpdateVoteStateInstruction) Decode(data []byte) error {
	return inst.VoteStateUpdate.Decode(data)
}

// Encode encodes an UpdateVoteState instruction to bytes.
func (inst *UpdateVoteStateInstruction) Encode() []byte {
	updateData := inst.VoteStateUpdate.Encode()
	data := make([]byte, 4+len(updateData))
	binary.LittleEndian.PutUint32(data[0:4], InstructionUpdateVoteState)
	copy(data[4:], updateData)
	return data
}

// UpdateVoteStateSwitchInstruction represents an UpdateVoteStateSwitch instruction.
type UpdateVoteStateSwitchInstruction struct {
	VoteStateUpdate VoteStateUpdate
	Hash            types.Hash
}

// Decode decodes an UpdateVoteStateSwitch instruction from bytes.
func (inst *UpdateVoteStateSwitchInstruction) Decode(data []byte) error {
	if err := inst.VoteStateUpdate.Decode(data); err != nil {
		return err
	}
	// Calculate offset where hash should be
	offset := 4 + len(inst.VoteStateUpdate.Lockouts)*12 + 1 + 32 + 1
	if inst.VoteStateUpdate.Root != nil {
		offset += 8
	}
	if inst.VoteStateUpdate.Timestamp != nil {
		offset += 8
	}
	if offset+32 > len(data) {
		return fmt.Errorf("%w: UpdateVoteStateSwitch missing hash", ErrInvalidInstructionData)
	}
	copy(inst.Hash[:], data[offset:offset+32])
	return nil
}

// Encode encodes an UpdateVoteStateSwitch instruction to bytes.
func (inst *UpdateVoteStateSwitchInstruction) Encode() []byte {
	updateData := inst.VoteStateUpdate.Encode()
	data := make([]byte, 4+len(updateData)+32)
	binary.LittleEndian.PutUint32(data[0:4], InstructionUpdateVoteStateSwitch)
	copy(data[4:4+len(updateData)], updateData)
	copy(data[4+len(updateData):], inst.Hash[:])
	return data
}

// AuthorizeWithSeedInstruction represents an AuthorizeWithSeed instruction.
type AuthorizeWithSeedInstruction struct {
	AuthorizeType          VoteAuthorize
	CurrentAuthorityPubkey types.Pubkey
	CurrentAuthoritySeed   string
	CurrentAuthorityOwner  types.Pubkey
	NewAuthority           types.Pubkey
}

// Decode decodes an AuthorizeWithSeed instruction from bytes.
func (inst *AuthorizeWithSeedInstruction) Decode(data []byte) error {
	offset := 0

	// AuthorizeType (4 bytes)
	if offset+4 > len(data) {
		return fmt.Errorf("%w: AuthorizeWithSeed missing authorize type", ErrInvalidInstructionData)
	}
	authType := binary.LittleEndian.Uint32(data[offset : offset+4])
	if authType > 1 {
		return fmt.Errorf("%w: authorize type must be 0 or 1", ErrInvalidAuthorizeType)
	}
	inst.AuthorizeType = VoteAuthorize(authType)
	offset += 4

	// CurrentAuthorityPubkey (32 bytes)
	if offset+32 > len(data) {
		return fmt.Errorf("%w: AuthorizeWithSeed missing current authority pubkey", ErrInvalidInstructionData)
	}
	copy(inst.CurrentAuthorityPubkey[:], data[offset:offset+32])
	offset += 32

	// CurrentAuthoritySeed (length-prefixed string)
	if offset+8 > len(data) {
		return fmt.Errorf("%w: AuthorizeWithSeed missing seed length", ErrInvalidInstructionData)
	}
	seedLen := binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8

	if offset+int(seedLen) > len(data) {
		return fmt.Errorf("%w: AuthorizeWithSeed seed truncated", ErrInvalidInstructionData)
	}
	inst.CurrentAuthoritySeed = string(data[offset : offset+int(seedLen)])
	offset += int(seedLen)

	// CurrentAuthorityOwner (32 bytes)
	if offset+32 > len(data) {
		return fmt.Errorf("%w: AuthorizeWithSeed missing current authority owner", ErrInvalidInstructionData)
	}
	copy(inst.CurrentAuthorityOwner[:], data[offset:offset+32])
	offset += 32

	// NewAuthority (32 bytes)
	if offset+32 > len(data) {
		return fmt.Errorf("%w: AuthorizeWithSeed missing new authority", ErrInvalidInstructionData)
	}
	copy(inst.NewAuthority[:], data[offset:offset+32])

	return nil
}

// Encode encodes an AuthorizeWithSeed instruction to bytes.
func (inst *AuthorizeWithSeedInstruction) Encode() []byte {
	seedBytes := []byte(inst.CurrentAuthoritySeed)
	data := make([]byte, 4+4+32+8+len(seedBytes)+32+32)
	offset := 0

	binary.LittleEndian.PutUint32(data[offset:offset+4], InstructionAuthorizeWithSeed)
	offset += 4

	binary.LittleEndian.PutUint32(data[offset:offset+4], uint32(inst.AuthorizeType))
	offset += 4

	copy(data[offset:offset+32], inst.CurrentAuthorityPubkey[:])
	offset += 32

	binary.LittleEndian.PutUint64(data[offset:offset+8], uint64(len(seedBytes)))
	offset += 8

	copy(data[offset:offset+len(seedBytes)], seedBytes)
	offset += len(seedBytes)

	copy(data[offset:offset+32], inst.CurrentAuthorityOwner[:])
	offset += 32

	copy(data[offset:offset+32], inst.NewAuthority[:])

	return data
}

// AuthorizeCheckedWithSeedInstruction represents an AuthorizeCheckedWithSeed instruction.
type AuthorizeCheckedWithSeedInstruction struct {
	AuthorizeType          VoteAuthorize
	CurrentAuthorityPubkey types.Pubkey
	CurrentAuthoritySeed   string
	CurrentAuthorityOwner  types.Pubkey
}

// Decode decodes an AuthorizeCheckedWithSeed instruction from bytes.
func (inst *AuthorizeCheckedWithSeedInstruction) Decode(data []byte) error {
	offset := 0

	// AuthorizeType (4 bytes)
	if offset+4 > len(data) {
		return fmt.Errorf("%w: AuthorizeCheckedWithSeed missing authorize type", ErrInvalidInstructionData)
	}
	authType := binary.LittleEndian.Uint32(data[offset : offset+4])
	if authType > 1 {
		return fmt.Errorf("%w: authorize type must be 0 or 1", ErrInvalidAuthorizeType)
	}
	inst.AuthorizeType = VoteAuthorize(authType)
	offset += 4

	// CurrentAuthorityPubkey (32 bytes)
	if offset+32 > len(data) {
		return fmt.Errorf("%w: AuthorizeCheckedWithSeed missing current authority pubkey", ErrInvalidInstructionData)
	}
	copy(inst.CurrentAuthorityPubkey[:], data[offset:offset+32])
	offset += 32

	// CurrentAuthoritySeed (length-prefixed string)
	if offset+8 > len(data) {
		return fmt.Errorf("%w: AuthorizeCheckedWithSeed missing seed length", ErrInvalidInstructionData)
	}
	seedLen := binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8

	if offset+int(seedLen) > len(data) {
		return fmt.Errorf("%w: AuthorizeCheckedWithSeed seed truncated", ErrInvalidInstructionData)
	}
	inst.CurrentAuthoritySeed = string(data[offset : offset+int(seedLen)])
	offset += int(seedLen)

	// CurrentAuthorityOwner (32 bytes)
	if offset+32 > len(data) {
		return fmt.Errorf("%w: AuthorizeCheckedWithSeed missing current authority owner", ErrInvalidInstructionData)
	}
	copy(inst.CurrentAuthorityOwner[:], data[offset:offset+32])

	return nil
}

// Encode encodes an AuthorizeCheckedWithSeed instruction to bytes.
func (inst *AuthorizeCheckedWithSeedInstruction) Encode() []byte {
	seedBytes := []byte(inst.CurrentAuthoritySeed)
	data := make([]byte, 4+4+32+8+len(seedBytes)+32)
	offset := 0

	binary.LittleEndian.PutUint32(data[offset:offset+4], InstructionAuthorizeCheckedWithSeed)
	offset += 4

	binary.LittleEndian.PutUint32(data[offset:offset+4], uint32(inst.AuthorizeType))
	offset += 4

	copy(data[offset:offset+32], inst.CurrentAuthorityPubkey[:])
	offset += 32

	binary.LittleEndian.PutUint64(data[offset:offset+8], uint64(len(seedBytes)))
	offset += 8

	copy(data[offset:offset+len(seedBytes)], seedBytes)
	offset += len(seedBytes)

	copy(data[offset:offset+32], inst.CurrentAuthorityOwner[:])

	return data
}

// CompactUpdateVoteStateInstruction represents a CompactUpdateVoteState instruction.
// Uses a more compact encoding for the vote state update.
type CompactUpdateVoteStateInstruction struct {
	VoteStateUpdate VoteStateUpdate
}

// Decode decodes a CompactUpdateVoteState instruction from bytes.
func (inst *CompactUpdateVoteStateInstruction) Decode(data []byte) error {
	return inst.VoteStateUpdate.Decode(data)
}

// Encode encodes a CompactUpdateVoteState instruction to bytes.
func (inst *CompactUpdateVoteStateInstruction) Encode() []byte {
	updateData := inst.VoteStateUpdate.Encode()
	data := make([]byte, 4+len(updateData))
	binary.LittleEndian.PutUint32(data[0:4], InstructionCompactUpdateVoteState)
	copy(data[4:], updateData)
	return data
}

// CompactUpdateVoteStateSwitchInstruction represents a CompactUpdateVoteStateSwitch instruction.
type CompactUpdateVoteStateSwitchInstruction struct {
	VoteStateUpdate VoteStateUpdate
	Hash            types.Hash
}

// Decode decodes a CompactUpdateVoteStateSwitch instruction from bytes.
func (inst *CompactUpdateVoteStateSwitchInstruction) Decode(data []byte) error {
	if err := inst.VoteStateUpdate.Decode(data); err != nil {
		return err
	}
	// Calculate offset where hash should be
	offset := 4 + len(inst.VoteStateUpdate.Lockouts)*12 + 1 + 32 + 1
	if inst.VoteStateUpdate.Root != nil {
		offset += 8
	}
	if inst.VoteStateUpdate.Timestamp != nil {
		offset += 8
	}
	if offset+32 > len(data) {
		return fmt.Errorf("%w: CompactUpdateVoteStateSwitch missing hash", ErrInvalidInstructionData)
	}
	copy(inst.Hash[:], data[offset:offset+32])
	return nil
}

// Encode encodes a CompactUpdateVoteStateSwitch instruction to bytes.
func (inst *CompactUpdateVoteStateSwitchInstruction) Encode() []byte {
	updateData := inst.VoteStateUpdate.Encode()
	data := make([]byte, 4+len(updateData)+32)
	binary.LittleEndian.PutUint32(data[0:4], InstructionCompactUpdateVoteStateSwitch)
	copy(data[4:4+len(updateData)], updateData)
	copy(data[4+len(updateData):], inst.Hash[:])
	return data
}

// TowerSync represents a tower sync vote.
type TowerSync struct {
	Lockouts  []Lockout  // Vote lockouts
	Root      *uint64    // Optional root slot
	Hash      types.Hash // Bank hash
	Timestamp *int64     // Optional timestamp
	BlockID   types.Hash // Block ID
}

// Decode decodes a TowerSync from bytes.
func (t *TowerSync) Decode(data []byte) error {
	offset := 0

	// Number of lockouts (4 bytes)
	if offset+4 > len(data) {
		return fmt.Errorf("%w: TowerSync missing lockouts length", ErrInvalidInstructionData)
	}
	numLockouts := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	if numLockouts > MaxLockoutHistory {
		return fmt.Errorf("%w: too many lockouts: %d > %d", ErrTooManyVotes, numLockouts, MaxLockoutHistory)
	}

	// Lockouts
	t.Lockouts = make([]Lockout, numLockouts)
	for i := uint32(0); i < numLockouts; i++ {
		if offset+12 > len(data) {
			return fmt.Errorf("%w: TowerSync truncated at lockout %d", ErrInvalidInstructionData, i)
		}
		lockout, err := DecodeLockout(data[offset : offset+12])
		if err != nil {
			return err
		}
		t.Lockouts[i] = *lockout
		offset += 12
	}

	// Root option (1 byte flag + 8 bytes if present)
	if offset+1 > len(data) {
		return fmt.Errorf("%w: TowerSync missing root flag", ErrInvalidInstructionData)
	}
	if data[offset] == 1 {
		offset++
		if offset+8 > len(data) {
			return fmt.Errorf("%w: TowerSync missing root value", ErrInvalidInstructionData)
		}
		root := binary.LittleEndian.Uint64(data[offset : offset+8])
		t.Root = &root
		offset += 8
	} else {
		t.Root = nil
		offset++
	}

	// Hash (32 bytes)
	if offset+32 > len(data) {
		return fmt.Errorf("%w: TowerSync missing hash", ErrInvalidInstructionData)
	}
	copy(t.Hash[:], data[offset:offset+32])
	offset += 32

	// Timestamp option (1 byte flag + 8 bytes if present)
	if offset+1 > len(data) {
		return fmt.Errorf("%w: TowerSync missing timestamp flag", ErrInvalidInstructionData)
	}
	if data[offset] == 1 {
		offset++
		if offset+8 > len(data) {
			return fmt.Errorf("%w: TowerSync missing timestamp value", ErrInvalidInstructionData)
		}
		ts := int64(binary.LittleEndian.Uint64(data[offset : offset+8]))
		t.Timestamp = &ts
		offset += 8
	} else {
		t.Timestamp = nil
		offset++
	}

	// BlockID (32 bytes)
	if offset+32 > len(data) {
		return fmt.Errorf("%w: TowerSync missing block ID", ErrInvalidInstructionData)
	}
	copy(t.BlockID[:], data[offset:offset+32])

	return nil
}

// Encode encodes a TowerSync to bytes.
func (t *TowerSync) Encode() []byte {
	size := 4 + len(t.Lockouts)*12 + 1 + 32 + 1 + 32
	if t.Root != nil {
		size += 8
	}
	if t.Timestamp != nil {
		size += 8
	}
	data := make([]byte, size)
	offset := 0

	// Number of lockouts
	binary.LittleEndian.PutUint32(data[offset:offset+4], uint32(len(t.Lockouts)))
	offset += 4

	// Lockouts
	for _, lockout := range t.Lockouts {
		copy(data[offset:offset+12], lockout.Encode())
		offset += 12
	}

	// Root option
	if t.Root != nil {
		data[offset] = 1
		offset++
		binary.LittleEndian.PutUint64(data[offset:offset+8], *t.Root)
		offset += 8
	} else {
		data[offset] = 0
		offset++
	}

	// Hash
	copy(data[offset:offset+32], t.Hash[:])
	offset += 32

	// Timestamp option
	if t.Timestamp != nil {
		data[offset] = 1
		offset++
		binary.LittleEndian.PutUint64(data[offset:offset+8], uint64(*t.Timestamp))
		offset += 8
	} else {
		data[offset] = 0
		offset++
	}

	// BlockID
	copy(data[offset:offset+32], t.BlockID[:])

	return data
}

// TowerSyncInstruction represents a TowerSync instruction.
type TowerSyncInstruction struct {
	TowerSync TowerSync
}

// Decode decodes a TowerSync instruction from bytes.
func (inst *TowerSyncInstruction) Decode(data []byte) error {
	return inst.TowerSync.Decode(data)
}

// Encode encodes a TowerSync instruction to bytes.
func (inst *TowerSyncInstruction) Encode() []byte {
	towerData := inst.TowerSync.Encode()
	data := make([]byte, 4+len(towerData))
	binary.LittleEndian.PutUint32(data[0:4], InstructionTowerSync)
	copy(data[4:], towerData)
	return data
}

// TowerSyncSwitchInstruction represents a TowerSyncSwitch instruction.
type TowerSyncSwitchInstruction struct {
	TowerSync TowerSync
	Hash      types.Hash
}

// Decode decodes a TowerSyncSwitch instruction from bytes.
func (inst *TowerSyncSwitchInstruction) Decode(data []byte) error {
	if err := inst.TowerSync.Decode(data); err != nil {
		return err
	}
	// Calculate offset where hash should be
	offset := 4 + len(inst.TowerSync.Lockouts)*12 + 1 + 32 + 1 + 32
	if inst.TowerSync.Root != nil {
		offset += 8
	}
	if inst.TowerSync.Timestamp != nil {
		offset += 8
	}
	if offset+32 > len(data) {
		return fmt.Errorf("%w: TowerSyncSwitch missing hash", ErrInvalidInstructionData)
	}
	copy(inst.Hash[:], data[offset:offset+32])
	return nil
}

// Encode encodes a TowerSyncSwitch instruction to bytes.
func (inst *TowerSyncSwitchInstruction) Encode() []byte {
	towerData := inst.TowerSync.Encode()
	data := make([]byte, 4+len(towerData)+32)
	binary.LittleEndian.PutUint32(data[0:4], InstructionTowerSyncSwitch)
	copy(data[4:4+len(towerData)], towerData)
	copy(data[4+len(towerData):], inst.Hash[:])
	return data
}

// ParseInstructionDiscriminator extracts the instruction discriminator from instruction data.
func ParseInstructionDiscriminator(data []byte) (uint32, error) {
	if len(data) < 4 {
		return 0, fmt.Errorf("%w: instruction data too short", ErrInvalidInstructionData)
	}
	return binary.LittleEndian.Uint32(data[0:4]), nil
}
