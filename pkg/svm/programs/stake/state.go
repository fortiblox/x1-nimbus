package stake

import (
	"encoding/binary"
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// StakeStateType represents the type of stake state.
type StakeStateType uint32

const (
	// StakeStateUninitialized indicates an uninitialized stake account.
	StakeStateUninitialized StakeStateType = 0
	// StakeStateInitialized indicates an initialized stake account with meta but no delegation.
	StakeStateInitialized StakeStateType = 1
	// StakeStateStake indicates a delegated stake account.
	StakeStateStake StakeStateType = 2
	// StakeStateRewardsPool indicates a rewards pool account.
	StakeStateRewardsPool StakeStateType = 3
)

// String returns the string representation of the stake state type.
func (s StakeStateType) String() string {
	switch s {
	case StakeStateUninitialized:
		return "Uninitialized"
	case StakeStateInitialized:
		return "Initialized"
	case StakeStateStake:
		return "Stake"
	case StakeStateRewardsPool:
		return "RewardsPool"
	default:
		return fmt.Sprintf("Unknown(%d)", s)
	}
}

// StakeAuthorize represents the authorization type.
type StakeAuthorize uint32

const (
	// StakeAuthorizeStaker authorizes staking operations.
	StakeAuthorizeStaker StakeAuthorize = 0
	// StakeAuthorizeWithdrawer authorizes withdrawal operations.
	StakeAuthorizeWithdrawer StakeAuthorize = 1
)

// String returns the string representation of the stake authorize type.
func (s StakeAuthorize) String() string {
	switch s {
	case StakeAuthorizeStaker:
		return "Staker"
	case StakeAuthorizeWithdrawer:
		return "Withdrawer"
	default:
		return fmt.Sprintf("Unknown(%d)", s)
	}
}

// Authorized represents the authorized staker and withdrawer.
type Authorized struct {
	Staker     types.Pubkey // Public key of the staker
	Withdrawer types.Pubkey // Public key of the withdrawer
}

// AuthorizedSize is the serialized size of Authorized.
const AuthorizedSize = 64 // 32 + 32

// Encode serializes the Authorized to bytes.
func (a *Authorized) Encode() []byte {
	data := make([]byte, AuthorizedSize)
	copy(data[0:32], a.Staker[:])
	copy(data[32:64], a.Withdrawer[:])
	return data
}

// Decode deserializes the Authorized from bytes.
func (a *Authorized) Decode(data []byte) error {
	if len(data) < AuthorizedSize {
		return fmt.Errorf("%w: Authorized requires %d bytes, got %d", ErrInvalidInstructionData, AuthorizedSize, len(data))
	}
	copy(a.Staker[:], data[0:32])
	copy(a.Withdrawer[:], data[32:64])
	return nil
}

// Lockup represents the stake lockup configuration.
type Lockup struct {
	UnixTimestamp int64        // Unix timestamp of lockup expiration
	Epoch         uint64       // Epoch of lockup expiration
	Custodian     types.Pubkey // Custodian who can modify the lockup
}

// LockupSize is the serialized size of Lockup.
const LockupSize = 48 // 8 + 8 + 32

// IsInForce checks if the lockup is currently in effect.
func (l *Lockup) IsInForce(currentTimestamp int64, currentEpoch uint64, custodianPubkey *types.Pubkey) bool {
	// If custodian is provided and matches, lockup can be bypassed
	if custodianPubkey != nil && *custodianPubkey == l.Custodian {
		return false
	}
	// Lockup is in force if we haven't reached the timestamp or epoch
	return currentTimestamp < l.UnixTimestamp || currentEpoch < l.Epoch
}

// Encode serializes the Lockup to bytes.
func (l *Lockup) Encode() []byte {
	data := make([]byte, LockupSize)
	binary.LittleEndian.PutUint64(data[0:8], uint64(l.UnixTimestamp))
	binary.LittleEndian.PutUint64(data[8:16], l.Epoch)
	copy(data[16:48], l.Custodian[:])
	return data
}

// Decode deserializes the Lockup from bytes.
func (l *Lockup) Decode(data []byte) error {
	if len(data) < LockupSize {
		return fmt.Errorf("%w: Lockup requires %d bytes, got %d", ErrInvalidInstructionData, LockupSize, len(data))
	}
	l.UnixTimestamp = int64(binary.LittleEndian.Uint64(data[0:8]))
	l.Epoch = binary.LittleEndian.Uint64(data[8:16])
	copy(l.Custodian[:], data[16:48])
	return nil
}

// Meta represents the stake account metadata.
type Meta struct {
	RentExemptReserve uint64     // Rent exempt reserve in lamports
	Authorized        Authorized // Authorized staker and withdrawer
	Lockup            Lockup     // Lockup configuration
}

// MetaSize is the serialized size of Meta.
const MetaSize = 8 + AuthorizedSize + LockupSize // 8 + 64 + 48 = 120

// Encode serializes the Meta to bytes.
func (m *Meta) Encode() []byte {
	data := make([]byte, MetaSize)
	binary.LittleEndian.PutUint64(data[0:8], m.RentExemptReserve)
	copy(data[8:8+AuthorizedSize], m.Authorized.Encode())
	copy(data[8+AuthorizedSize:], m.Lockup.Encode())
	return data
}

// Decode deserializes the Meta from bytes.
func (m *Meta) Decode(data []byte) error {
	if len(data) < MetaSize {
		return fmt.Errorf("%w: Meta requires %d bytes, got %d", ErrInvalidInstructionData, MetaSize, len(data))
	}
	m.RentExemptReserve = binary.LittleEndian.Uint64(data[0:8])
	if err := m.Authorized.Decode(data[8 : 8+AuthorizedSize]); err != nil {
		return err
	}
	if err := m.Lockup.Decode(data[8+AuthorizedSize : 8+AuthorizedSize+LockupSize]); err != nil {
		return err
	}
	return nil
}

// Delegation represents the stake delegation.
type Delegation struct {
	VoterPubkey        types.Pubkey // Vote account to which the stake is delegated
	Stake              uint64       // Delegated stake amount in lamports
	ActivationEpoch    uint64       // Epoch when the stake was activated
	DeactivationEpoch  uint64       // Epoch when the stake was deactivated (max uint64 if active)
	WarmupCooldownRate float64      // Rate of warmup/cooldown (typically 0.25)
}

// DelegationSize is the serialized size of Delegation.
const DelegationSize = 32 + 8 + 8 + 8 + 8 // 64

// DeactivationEpochMax indicates the stake is active (not deactivated).
const DeactivationEpochMax = ^uint64(0)

// IsActive returns true if the delegation is active.
func (d *Delegation) IsActive() bool {
	return d.DeactivationEpoch == DeactivationEpochMax
}

// IsDeactivating returns true if the delegation is deactivating.
func (d *Delegation) IsDeactivating(currentEpoch uint64) bool {
	return d.DeactivationEpoch != DeactivationEpochMax && d.DeactivationEpoch <= currentEpoch
}

// IsActivating returns true if the delegation is still warming up.
func (d *Delegation) IsActivating(currentEpoch uint64) bool {
	return d.ActivationEpoch > currentEpoch
}

// Encode serializes the Delegation to bytes.
func (d *Delegation) Encode() []byte {
	data := make([]byte, DelegationSize)
	copy(data[0:32], d.VoterPubkey[:])
	binary.LittleEndian.PutUint64(data[32:40], d.Stake)
	binary.LittleEndian.PutUint64(data[40:48], d.ActivationEpoch)
	binary.LittleEndian.PutUint64(data[48:56], d.DeactivationEpoch)
	// Encode float64 as uint64 bits
	binary.LittleEndian.PutUint64(data[56:64], uint64(d.WarmupCooldownRate*1e9))
	return data
}

// Decode deserializes the Delegation from bytes.
func (d *Delegation) Decode(data []byte) error {
	if len(data) < DelegationSize {
		return fmt.Errorf("%w: Delegation requires %d bytes, got %d", ErrInvalidInstructionData, DelegationSize, len(data))
	}
	copy(d.VoterPubkey[:], data[0:32])
	d.Stake = binary.LittleEndian.Uint64(data[32:40])
	d.ActivationEpoch = binary.LittleEndian.Uint64(data[40:48])
	d.DeactivationEpoch = binary.LittleEndian.Uint64(data[48:56])
	// Decode float64 from uint64 bits
	d.WarmupCooldownRate = float64(binary.LittleEndian.Uint64(data[56:64])) / 1e9
	return nil
}

// Stake represents the stake portion of a stake account.
type Stake struct {
	Delegation      Delegation // Delegation information
	CreditsObserved uint64     // Credits observed at last reward collection
}

// StakeSize is the serialized size of Stake.
const StakeSize = DelegationSize + 8 // 64 + 8 = 72

// Encode serializes the Stake to bytes.
func (s *Stake) Encode() []byte {
	data := make([]byte, StakeSize)
	copy(data[0:DelegationSize], s.Delegation.Encode())
	binary.LittleEndian.PutUint64(data[DelegationSize:DelegationSize+8], s.CreditsObserved)
	return data
}

// Decode deserializes the Stake from bytes.
func (s *Stake) Decode(data []byte) error {
	if len(data) < StakeSize {
		return fmt.Errorf("%w: Stake requires %d bytes, got %d", ErrInvalidInstructionData, StakeSize, len(data))
	}
	if err := s.Delegation.Decode(data[0:DelegationSize]); err != nil {
		return err
	}
	s.CreditsObserved = binary.LittleEndian.Uint64(data[DelegationSize : DelegationSize+8])
	return nil
}

// StakeState represents the full state of a stake account.
type StakeState struct {
	Type  StakeStateType // Type of stake state
	Meta  Meta           // Metadata (for Initialized and Stake states)
	Stake Stake          // Stake info (for Stake state only)
}

// StakeStateSize is the size of the stake account data.
const StakeStateSize = 4 + MetaSize + StakeSize // 4 + 120 + 72 = 196

// Encode serializes the StakeState to bytes.
func (s *StakeState) Encode() []byte {
	data := make([]byte, StakeStateSize)
	binary.LittleEndian.PutUint32(data[0:4], uint32(s.Type))
	copy(data[4:4+MetaSize], s.Meta.Encode())
	copy(data[4+MetaSize:], s.Stake.Encode())
	return data
}

// Decode deserializes the StakeState from bytes.
func (s *StakeState) Decode(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("%w: StakeState requires at least 4 bytes, got %d", ErrInvalidInstructionData, len(data))
	}
	s.Type = StakeStateType(binary.LittleEndian.Uint32(data[0:4]))

	switch s.Type {
	case StakeStateUninitialized, StakeStateRewardsPool:
		// No additional data needed
		return nil
	case StakeStateInitialized:
		if len(data) < 4+MetaSize {
			return fmt.Errorf("%w: Initialized StakeState requires %d bytes, got %d", ErrInvalidInstructionData, 4+MetaSize, len(data))
		}
		return s.Meta.Decode(data[4 : 4+MetaSize])
	case StakeStateStake:
		if len(data) < StakeStateSize {
			return fmt.Errorf("%w: Stake StakeState requires %d bytes, got %d", ErrInvalidInstructionData, StakeStateSize, len(data))
		}
		if err := s.Meta.Decode(data[4 : 4+MetaSize]); err != nil {
			return err
		}
		return s.Stake.Decode(data[4+MetaSize:])
	default:
		return fmt.Errorf("%w: unknown stake state type %d", ErrInvalidStakeState, s.Type)
	}
}

// IsInitialized returns true if the stake account is initialized.
func (s *StakeState) IsInitialized() bool {
	return s.Type == StakeStateInitialized || s.Type == StakeStateStake
}

// IsDelegated returns true if the stake account is delegated.
func (s *StakeState) IsDelegated() bool {
	return s.Type == StakeStateStake
}

// LockupArgs represents optional lockup parameters for SetLockup.
type LockupArgs struct {
	UnixTimestamp *int64        // Optional new unix timestamp
	Epoch         *uint64       // Optional new epoch
	Custodian     *types.Pubkey // Optional new custodian
}

// LockupArgsSize is the maximum serialized size of LockupArgs.
const LockupArgsSize = 1 + 8 + 1 + 8 + 1 + 32 // presence flags + values = 51

// Encode serializes the LockupArgs to bytes.
func (l *LockupArgs) Encode() []byte {
	data := make([]byte, 0, LockupArgsSize)

	// Unix timestamp (Option<i64>)
	if l.UnixTimestamp != nil {
		data = append(data, 1)
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, uint64(*l.UnixTimestamp))
		data = append(data, buf...)
	} else {
		data = append(data, 0)
	}

	// Epoch (Option<u64>)
	if l.Epoch != nil {
		data = append(data, 1)
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, *l.Epoch)
		data = append(data, buf...)
	} else {
		data = append(data, 0)
	}

	// Custodian (Option<Pubkey>)
	if l.Custodian != nil {
		data = append(data, 1)
		data = append(data, l.Custodian[:]...)
	} else {
		data = append(data, 0)
	}

	return data
}

// Decode deserializes the LockupArgs from bytes.
func (l *LockupArgs) Decode(data []byte) error {
	offset := 0

	// Unix timestamp
	if len(data) < offset+1 {
		return fmt.Errorf("%w: LockupArgs too short", ErrInvalidInstructionData)
	}
	if data[offset] == 1 {
		offset++
		if len(data) < offset+8 {
			return fmt.Errorf("%w: LockupArgs unix_timestamp too short", ErrInvalidInstructionData)
		}
		ts := int64(binary.LittleEndian.Uint64(data[offset : offset+8]))
		l.UnixTimestamp = &ts
		offset += 8
	} else {
		offset++
		l.UnixTimestamp = nil
	}

	// Epoch
	if len(data) < offset+1 {
		return fmt.Errorf("%w: LockupArgs too short for epoch", ErrInvalidInstructionData)
	}
	if data[offset] == 1 {
		offset++
		if len(data) < offset+8 {
			return fmt.Errorf("%w: LockupArgs epoch too short", ErrInvalidInstructionData)
		}
		ep := binary.LittleEndian.Uint64(data[offset : offset+8])
		l.Epoch = &ep
		offset += 8
	} else {
		offset++
		l.Epoch = nil
	}

	// Custodian
	if len(data) < offset+1 {
		return fmt.Errorf("%w: LockupArgs too short for custodian", ErrInvalidInstructionData)
	}
	if data[offset] == 1 {
		offset++
		if len(data) < offset+32 {
			return fmt.Errorf("%w: LockupArgs custodian too short", ErrInvalidInstructionData)
		}
		var custodian types.Pubkey
		copy(custodian[:], data[offset:offset+32])
		l.Custodian = &custodian
	} else {
		l.Custodian = nil
	}

	return nil
}

// MinimumDelegation is the minimum stake that can be delegated.
const MinimumDelegation uint64 = 1_000_000 // 0.001 SOL

// DefaultWarmupCooldownRate is the default rate for stake warmup/cooldown.
const DefaultWarmupCooldownRate float64 = 0.25
