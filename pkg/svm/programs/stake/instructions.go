package stake

import (
	"encoding/binary"
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// Stake Program instruction discriminators (first 4 bytes of instruction data)
const (
	InstructionInitialize              uint32 = 0
	InstructionAuthorize               uint32 = 1
	InstructionDelegateStake           uint32 = 2
	InstructionSplit                   uint32 = 3
	InstructionWithdraw                uint32 = 4
	InstructionDeactivate              uint32 = 5
	InstructionSetLockup               uint32 = 6
	InstructionMerge                   uint32 = 7
	InstructionAuthorizeWithSeed       uint32 = 8
	InstructionInitializeChecked       uint32 = 9
	InstructionAuthorizeChecked        uint32 = 10
	InstructionAuthorizeCheckedWithSeed uint32 = 11
	InstructionSetLockupChecked        uint32 = 12
	InstructionGetMinimumDelegation    uint32 = 13
	InstructionDeactivateDelinquent    uint32 = 14
	InstructionRedelegate              uint32 = 15
)

// InitializeInstruction represents an Initialize instruction.
// Initializes a stake account with the given authorized and lockup.
// Accounts:
//   [0] stake account (writable)
//   [1] rent sysvar
type InitializeInstruction struct {
	Authorized Authorized // Authorized staker and withdrawer
	Lockup     Lockup     // Lockup configuration
}

// Decode decodes an Initialize instruction from bytes.
func (inst *InitializeInstruction) Decode(data []byte) error {
	expectedLen := AuthorizedSize + LockupSize
	if len(data) < expectedLen {
		return fmt.Errorf("%w: Initialize requires %d bytes, got %d", ErrInvalidInstructionData, expectedLen, len(data))
	}
	if err := inst.Authorized.Decode(data[0:AuthorizedSize]); err != nil {
		return err
	}
	if err := inst.Lockup.Decode(data[AuthorizedSize : AuthorizedSize+LockupSize]); err != nil {
		return err
	}
	return nil
}

// Encode encodes an Initialize instruction to bytes.
func (inst *InitializeInstruction) Encode() []byte {
	data := make([]byte, 4+AuthorizedSize+LockupSize)
	binary.LittleEndian.PutUint32(data[0:4], InstructionInitialize)
	copy(data[4:4+AuthorizedSize], inst.Authorized.Encode())
	copy(data[4+AuthorizedSize:], inst.Lockup.Encode())
	return data
}

// AuthorizeInstruction represents an Authorize instruction.
// Changes the authorized staker or withdrawer.
// Accounts:
//   [0] stake account (writable)
//   [1] clock sysvar
//   [2] current authorized (staker or withdrawer) (signer)
//   [3] (optional) lockup custodian (signer)
type AuthorizeInstruction struct {
	NewAuthority   types.Pubkey   // New authorized pubkey
	StakeAuthorize StakeAuthorize // Which authorization to change (Staker or Withdrawer)
}

// Decode decodes an Authorize instruction from bytes.
func (inst *AuthorizeInstruction) Decode(data []byte) error {
	if len(data) < 36 { // 32 bytes pubkey + 4 bytes authorize type
		return fmt.Errorf("%w: Authorize requires 36 bytes, got %d", ErrInvalidInstructionData, len(data))
	}
	copy(inst.NewAuthority[:], data[0:32])
	inst.StakeAuthorize = StakeAuthorize(binary.LittleEndian.Uint32(data[32:36]))
	return nil
}

// Encode encodes an Authorize instruction to bytes.
func (inst *AuthorizeInstruction) Encode() []byte {
	data := make([]byte, 4+36)
	binary.LittleEndian.PutUint32(data[0:4], InstructionAuthorize)
	copy(data[4:36], inst.NewAuthority[:])
	binary.LittleEndian.PutUint32(data[36:40], uint32(inst.StakeAuthorize))
	return data
}

// DelegateStakeInstruction represents a DelegateStake instruction.
// Delegates the stake to a validator vote account.
// Accounts:
//   [0] stake account (writable)
//   [1] vote account
//   [2] clock sysvar
//   [3] stake history sysvar
//   [4] stake config account
//   [5] stake authority (signer)
type DelegateStakeInstruction struct {
	// No additional data
}

// Decode decodes a DelegateStake instruction from bytes.
func (inst *DelegateStakeInstruction) Decode(data []byte) error {
	// No additional data to decode
	return nil
}

// Encode encodes a DelegateStake instruction to bytes.
func (inst *DelegateStakeInstruction) Encode() []byte {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data[0:4], InstructionDelegateStake)
	return data
}

// SplitInstruction represents a Split instruction.
// Splits a stake account into two.
// Accounts:
//   [0] source stake account (writable)
//   [1] destination stake account (writable)
//   [2] stake authority (signer)
type SplitInstruction struct {
	Lamports uint64 // Amount of lamports to split
}

// Decode decodes a Split instruction from bytes.
func (inst *SplitInstruction) Decode(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("%w: Split requires 8 bytes, got %d", ErrInvalidInstructionData, len(data))
	}
	inst.Lamports = binary.LittleEndian.Uint64(data[0:8])
	return nil
}

// Encode encodes a Split instruction to bytes.
func (inst *SplitInstruction) Encode() []byte {
	data := make([]byte, 4+8)
	binary.LittleEndian.PutUint32(data[0:4], InstructionSplit)
	binary.LittleEndian.PutUint64(data[4:12], inst.Lamports)
	return data
}

// WithdrawInstruction represents a Withdraw instruction.
// Withdraws lamports from a stake account.
// Accounts:
//   [0] stake account (writable)
//   [1] destination account (writable)
//   [2] clock sysvar
//   [3] stake history sysvar
//   [4] withdraw authority (signer)
//   [5] (optional) lockup custodian (signer)
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

// DeactivateInstruction represents a Deactivate instruction.
// Deactivates a delegated stake.
// Accounts:
//   [0] stake account (writable)
//   [1] clock sysvar
//   [2] stake authority (signer)
type DeactivateInstruction struct {
	// No additional data
}

// Decode decodes a Deactivate instruction from bytes.
func (inst *DeactivateInstruction) Decode(data []byte) error {
	// No additional data to decode
	return nil
}

// Encode encodes a Deactivate instruction to bytes.
func (inst *DeactivateInstruction) Encode() []byte {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data[0:4], InstructionDeactivate)
	return data
}

// SetLockupInstruction represents a SetLockup instruction.
// Sets the lockup configuration.
// Accounts:
//   [0] stake account (writable)
//   [1] current lockup custodian or withdrawer (signer)
type SetLockupInstruction struct {
	LockupArgs LockupArgs // Optional lockup parameters
}

// Decode decodes a SetLockup instruction from bytes.
func (inst *SetLockupInstruction) Decode(data []byte) error {
	return inst.LockupArgs.Decode(data)
}

// Encode encodes a SetLockup instruction to bytes.
func (inst *SetLockupInstruction) Encode() []byte {
	lockupData := inst.LockupArgs.Encode()
	data := make([]byte, 4+len(lockupData))
	binary.LittleEndian.PutUint32(data[0:4], InstructionSetLockup)
	copy(data[4:], lockupData)
	return data
}

// MergeInstruction represents a Merge instruction.
// Merges two stake accounts.
// Accounts:
//   [0] destination stake account (writable)
//   [1] source stake account (writable)
//   [2] clock sysvar
//   [3] stake history sysvar
//   [4] stake authority (signer)
type MergeInstruction struct {
	// No additional data
}

// Decode decodes a Merge instruction from bytes.
func (inst *MergeInstruction) Decode(data []byte) error {
	// No additional data to decode
	return nil
}

// Encode encodes a Merge instruction to bytes.
func (inst *MergeInstruction) Encode() []byte {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data[0:4], InstructionMerge)
	return data
}

// AuthorizeWithSeedInstruction represents an AuthorizeWithSeed instruction.
// Authorizes with a derived key.
// Accounts:
//   [0] stake account (writable)
//   [1] base account (signer)
//   [2] clock sysvar
//   [3] (optional) lockup custodian (signer)
type AuthorizeWithSeedInstruction struct {
	NewAuthority    types.Pubkey   // New authorized pubkey
	StakeAuthorize  StakeAuthorize // Which authorization to change
	AuthoritySeed   string         // Seed for deriving the authority
	AuthorityOwner  types.Pubkey   // Owner of the derived authority
}

// Decode decodes an AuthorizeWithSeed instruction from bytes.
func (inst *AuthorizeWithSeedInstruction) Decode(data []byte) error {
	if len(data) < 32+4+8 { // pubkey + authorize + seed length
		return fmt.Errorf("%w: AuthorizeWithSeed too short", ErrInvalidInstructionData)
	}
	copy(inst.NewAuthority[:], data[0:32])
	inst.StakeAuthorize = StakeAuthorize(binary.LittleEndian.Uint32(data[32:36]))
	seedLen := binary.LittleEndian.Uint64(data[36:44])
	if seedLen > 32 {
		return fmt.Errorf("%w: seed too long", ErrInvalidInstructionData)
	}
	expectedLen := 44 + int(seedLen) + 32
	if len(data) < expectedLen {
		return fmt.Errorf("%w: AuthorizeWithSeed requires %d bytes, got %d", ErrInvalidInstructionData, expectedLen, len(data))
	}
	inst.AuthoritySeed = string(data[44 : 44+seedLen])
	copy(inst.AuthorityOwner[:], data[44+seedLen:44+seedLen+32])
	return nil
}

// Encode encodes an AuthorizeWithSeed instruction to bytes.
func (inst *AuthorizeWithSeedInstruction) Encode() []byte {
	seedBytes := []byte(inst.AuthoritySeed)
	data := make([]byte, 4+32+4+8+len(seedBytes)+32)
	binary.LittleEndian.PutUint32(data[0:4], InstructionAuthorizeWithSeed)
	copy(data[4:36], inst.NewAuthority[:])
	binary.LittleEndian.PutUint32(data[36:40], uint32(inst.StakeAuthorize))
	binary.LittleEndian.PutUint64(data[40:48], uint64(len(seedBytes)))
	copy(data[48:48+len(seedBytes)], seedBytes)
	copy(data[48+len(seedBytes):], inst.AuthorityOwner[:])
	return data
}

// InitializeCheckedInstruction represents an InitializeChecked instruction.
// Initializes a stake account with checked signers.
// Accounts:
//   [0] stake account (writable)
//   [1] rent sysvar
//   [2] staker (signer)
//   [3] withdrawer (signer)
type InitializeCheckedInstruction struct {
	// No additional data - authorities come from accounts
}

// Decode decodes an InitializeChecked instruction from bytes.
func (inst *InitializeCheckedInstruction) Decode(data []byte) error {
	// No additional data to decode
	return nil
}

// Encode encodes an InitializeChecked instruction to bytes.
func (inst *InitializeCheckedInstruction) Encode() []byte {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data[0:4], InstructionInitializeChecked)
	return data
}

// AuthorizeCheckedInstruction represents an AuthorizeChecked instruction.
// Changes authorization with the new authority as a signer.
// Accounts:
//   [0] stake account (writable)
//   [1] clock sysvar
//   [2] current authorized (signer)
//   [3] new authorized (signer)
//   [4] (optional) lockup custodian (signer)
type AuthorizeCheckedInstruction struct {
	StakeAuthorize StakeAuthorize // Which authorization to change
}

// Decode decodes an AuthorizeChecked instruction from bytes.
func (inst *AuthorizeCheckedInstruction) Decode(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("%w: AuthorizeChecked requires 4 bytes, got %d", ErrInvalidInstructionData, len(data))
	}
	inst.StakeAuthorize = StakeAuthorize(binary.LittleEndian.Uint32(data[0:4]))
	return nil
}

// Encode encodes an AuthorizeChecked instruction to bytes.
func (inst *AuthorizeCheckedInstruction) Encode() []byte {
	data := make([]byte, 4+4)
	binary.LittleEndian.PutUint32(data[0:4], InstructionAuthorizeChecked)
	binary.LittleEndian.PutUint32(data[4:8], uint32(inst.StakeAuthorize))
	return data
}

// AuthorizeCheckedWithSeedInstruction represents an AuthorizeCheckedWithSeed instruction.
// Authorizes with a derived key and new authority as signer.
// Accounts:
//   [0] stake account (writable)
//   [1] base account (signer)
//   [2] clock sysvar
//   [3] new authorized (signer)
//   [4] (optional) lockup custodian (signer)
type AuthorizeCheckedWithSeedInstruction struct {
	StakeAuthorize StakeAuthorize // Which authorization to change
	AuthoritySeed  string         // Seed for deriving the authority
	AuthorityOwner types.Pubkey   // Owner of the derived authority
}

// Decode decodes an AuthorizeCheckedWithSeed instruction from bytes.
func (inst *AuthorizeCheckedWithSeedInstruction) Decode(data []byte) error {
	if len(data) < 4+8 { // authorize + seed length
		return fmt.Errorf("%w: AuthorizeCheckedWithSeed too short", ErrInvalidInstructionData)
	}
	inst.StakeAuthorize = StakeAuthorize(binary.LittleEndian.Uint32(data[0:4]))
	seedLen := binary.LittleEndian.Uint64(data[4:12])
	if seedLen > 32 {
		return fmt.Errorf("%w: seed too long", ErrInvalidInstructionData)
	}
	expectedLen := 12 + int(seedLen) + 32
	if len(data) < expectedLen {
		return fmt.Errorf("%w: AuthorizeCheckedWithSeed requires %d bytes, got %d", ErrInvalidInstructionData, expectedLen, len(data))
	}
	inst.AuthoritySeed = string(data[12 : 12+seedLen])
	copy(inst.AuthorityOwner[:], data[12+seedLen:12+seedLen+32])
	return nil
}

// Encode encodes an AuthorizeCheckedWithSeed instruction to bytes.
func (inst *AuthorizeCheckedWithSeedInstruction) Encode() []byte {
	seedBytes := []byte(inst.AuthoritySeed)
	data := make([]byte, 4+4+8+len(seedBytes)+32)
	binary.LittleEndian.PutUint32(data[0:4], InstructionAuthorizeCheckedWithSeed)
	binary.LittleEndian.PutUint32(data[4:8], uint32(inst.StakeAuthorize))
	binary.LittleEndian.PutUint64(data[8:16], uint64(len(seedBytes)))
	copy(data[16:16+len(seedBytes)], seedBytes)
	copy(data[16+len(seedBytes):], inst.AuthorityOwner[:])
	return data
}

// SetLockupCheckedInstruction represents a SetLockupChecked instruction.
// Sets lockup with the new custodian as a signer.
// Accounts:
//   [0] stake account (writable)
//   [1] current lockup custodian or withdrawer (signer)
//   [2] (optional) new custodian (signer)
type SetLockupCheckedInstruction struct {
	UnixTimestamp *int64  // Optional new unix timestamp
	Epoch         *uint64 // Optional new epoch
}

// Decode decodes a SetLockupChecked instruction from bytes.
func (inst *SetLockupCheckedInstruction) Decode(data []byte) error {
	offset := 0

	// Unix timestamp
	if len(data) < offset+1 {
		return fmt.Errorf("%w: SetLockupChecked too short", ErrInvalidInstructionData)
	}
	if data[offset] == 1 {
		offset++
		if len(data) < offset+8 {
			return fmt.Errorf("%w: SetLockupChecked unix_timestamp too short", ErrInvalidInstructionData)
		}
		ts := int64(binary.LittleEndian.Uint64(data[offset : offset+8]))
		inst.UnixTimestamp = &ts
		offset += 8
	} else {
		offset++
		inst.UnixTimestamp = nil
	}

	// Epoch
	if len(data) < offset+1 {
		return fmt.Errorf("%w: SetLockupChecked too short for epoch", ErrInvalidInstructionData)
	}
	if data[offset] == 1 {
		offset++
		if len(data) < offset+8 {
			return fmt.Errorf("%w: SetLockupChecked epoch too short", ErrInvalidInstructionData)
		}
		ep := binary.LittleEndian.Uint64(data[offset : offset+8])
		inst.Epoch = &ep
	} else {
		inst.Epoch = nil
	}

	return nil
}

// Encode encodes a SetLockupChecked instruction to bytes.
func (inst *SetLockupCheckedInstruction) Encode() []byte {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data[0:4], InstructionSetLockupChecked)

	// Unix timestamp
	if inst.UnixTimestamp != nil {
		data = append(data, 1)
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, uint64(*inst.UnixTimestamp))
		data = append(data, buf...)
	} else {
		data = append(data, 0)
	}

	// Epoch
	if inst.Epoch != nil {
		data = append(data, 1)
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, *inst.Epoch)
		data = append(data, buf...)
	} else {
		data = append(data, 0)
	}

	return data
}

// GetMinimumDelegationInstruction represents a GetMinimumDelegation instruction.
// Returns the minimum delegation amount.
// Accounts: (none)
type GetMinimumDelegationInstruction struct {
	// No additional data
}

// Decode decodes a GetMinimumDelegation instruction from bytes.
func (inst *GetMinimumDelegationInstruction) Decode(data []byte) error {
	// No additional data to decode
	return nil
}

// Encode encodes a GetMinimumDelegation instruction to bytes.
func (inst *GetMinimumDelegationInstruction) Encode() []byte {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data[0:4], InstructionGetMinimumDelegation)
	return data
}

// DeactivateDelinquentInstruction represents a DeactivateDelinquent instruction.
// Deactivates stake delegated to a delinquent validator.
// Accounts:
//   [0] stake account (writable)
//   [1] vote account
//   [2] reference vote account
type DeactivateDelinquentInstruction struct {
	// No additional data
}

// Decode decodes a DeactivateDelinquent instruction from bytes.
func (inst *DeactivateDelinquentInstruction) Decode(data []byte) error {
	// No additional data to decode
	return nil
}

// Encode encodes a DeactivateDelinquent instruction to bytes.
func (inst *DeactivateDelinquentInstruction) Encode() []byte {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data[0:4], InstructionDeactivateDelinquent)
	return data
}

// RedelegateInstruction represents a Redelegate instruction.
// Redelegates stake to a different validator.
// Accounts:
//   [0] stake account (writable)
//   [1] uninitialized stake account (writable)
//   [2] vote account
//   [3] stake config account
//   [4] stake authority (signer)
type RedelegateInstruction struct {
	// No additional data
}

// Decode decodes a Redelegate instruction from bytes.
func (inst *RedelegateInstruction) Decode(data []byte) error {
	// No additional data to decode
	return nil
}

// Encode encodes a Redelegate instruction to bytes.
func (inst *RedelegateInstruction) Encode() []byte {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data[0:4], InstructionRedelegate)
	return data
}

// ParseInstructionDiscriminator extracts the instruction discriminator from instruction data.
func ParseInstructionDiscriminator(data []byte) (uint32, error) {
	if len(data) < 4 {
		return 0, fmt.Errorf("%w: instruction data too short", ErrInvalidInstructionData)
	}
	return binary.LittleEndian.Uint32(data[0:4]), nil
}
