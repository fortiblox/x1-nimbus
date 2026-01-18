package vote

import (
	"encoding/binary"
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// Vote state constants
const (
	// MaxLockoutHistory is the maximum number of votes in the vote history.
	MaxLockoutHistory = 31

	// MaxEpochCredits is the maximum number of epoch credits entries.
	MaxEpochCredits = 64

	// InitialLockout is the initial lockout value for a new vote.
	InitialLockout = 2

	// MaxLockout is the maximum lockout value.
	MaxLockout = 1 << MaxLockoutHistory

	// VoteStateSize is the size of a serialized VoteState.
	// This is an approximation; actual size may vary.
	VoteStateSize = 3762
)

// VoteAuthorize represents the type of authorization to change.
type VoteAuthorize uint8

const (
	// VoteAuthorizeVoter authorizes a new voter.
	VoteAuthorizeVoter VoteAuthorize = 0
	// VoteAuthorizeWithdrawer authorizes a new withdrawer.
	VoteAuthorizeWithdrawer VoteAuthorize = 1
)

// String returns the string representation of VoteAuthorize.
func (v VoteAuthorize) String() string {
	switch v {
	case VoteAuthorizeVoter:
		return "Voter"
	case VoteAuthorizeWithdrawer:
		return "Withdrawer"
	default:
		return fmt.Sprintf("Unknown(%d)", v)
	}
}

// Lockout represents a vote lockout.
type Lockout struct {
	Slot              uint64 // The slot that was voted on
	ConfirmationCount uint32 // Number of confirmations (lockout = 2^confirmation_count)
}

// LockoutDuration returns the lockout duration in slots.
func (l *Lockout) LockoutDuration() uint64 {
	return 1 << l.ConfirmationCount
}

// LastLockedOutSlot returns the last slot that this lockout would prevent voting on.
func (l *Lockout) LastLockedOutSlot() uint64 {
	return l.Slot + l.LockoutDuration()
}

// IsLockedOutAtSlot returns true if this lockout prevents voting at the given slot.
func (l *Lockout) IsLockedOutAtSlot(slot uint64) bool {
	return l.LastLockedOutSlot() >= slot
}

// IncrementConfirmationCount increments the confirmation count, capped at MaxLockoutHistory.
func (l *Lockout) IncrementConfirmationCount() {
	if l.ConfirmationCount < MaxLockoutHistory {
		l.ConfirmationCount++
	}
}

// Encode encodes a Lockout to bytes.
func (l *Lockout) Encode() []byte {
	data := make([]byte, 12)
	binary.LittleEndian.PutUint64(data[0:8], l.Slot)
	binary.LittleEndian.PutUint32(data[8:12], l.ConfirmationCount)
	return data
}

// DecodeLockout decodes a Lockout from bytes.
func DecodeLockout(data []byte) (*Lockout, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("lockout data too short: need 12 bytes, got %d", len(data))
	}
	return &Lockout{
		Slot:              binary.LittleEndian.Uint64(data[0:8]),
		ConfirmationCount: binary.LittleEndian.Uint32(data[8:12]),
	}, nil
}

// BlockTimestamp represents a timestamp for a block.
type BlockTimestamp struct {
	Slot      uint64 // Slot when timestamp was recorded
	Timestamp int64  // Unix timestamp
}

// Encode encodes a BlockTimestamp to bytes.
func (bt *BlockTimestamp) Encode() []byte {
	data := make([]byte, 16)
	binary.LittleEndian.PutUint64(data[0:8], bt.Slot)
	binary.LittleEndian.PutUint64(data[8:16], uint64(bt.Timestamp))
	return data
}

// DecodeBlockTimestamp decodes a BlockTimestamp from bytes.
func DecodeBlockTimestamp(data []byte) (*BlockTimestamp, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("block timestamp data too short: need 16 bytes, got %d", len(data))
	}
	return &BlockTimestamp{
		Slot:      binary.LittleEndian.Uint64(data[0:8]),
		Timestamp: int64(binary.LittleEndian.Uint64(data[8:16])),
	}, nil
}

// EpochCredits represents credits earned in an epoch.
type EpochCredits struct {
	Epoch       uint64 // Epoch number
	Credits     uint64 // Total credits at end of epoch
	PrevCredits uint64 // Credits at start of epoch
}

// Encode encodes EpochCredits to bytes.
func (ec *EpochCredits) Encode() []byte {
	data := make([]byte, 24)
	binary.LittleEndian.PutUint64(data[0:8], ec.Epoch)
	binary.LittleEndian.PutUint64(data[8:16], ec.Credits)
	binary.LittleEndian.PutUint64(data[16:24], ec.PrevCredits)
	return data
}

// DecodeEpochCredits decodes EpochCredits from bytes.
func DecodeEpochCredits(data []byte) (*EpochCredits, error) {
	if len(data) < 24 {
		return nil, fmt.Errorf("epoch credits data too short: need 24 bytes, got %d", len(data))
	}
	return &EpochCredits{
		Epoch:       binary.LittleEndian.Uint64(data[0:8]),
		Credits:     binary.LittleEndian.Uint64(data[8:16]),
		PrevCredits: binary.LittleEndian.Uint64(data[16:24]),
	}, nil
}

// AuthorizedVoters represents a history of authorized voters keyed by epoch.
type AuthorizedVoters struct {
	Authorized map[uint64]types.Pubkey // epoch -> authorized voter
}

// NewAuthorizedVoters creates a new AuthorizedVoters.
func NewAuthorizedVoters(initialVoter types.Pubkey, epoch uint64) *AuthorizedVoters {
	return &AuthorizedVoters{
		Authorized: map[uint64]types.Pubkey{epoch: initialVoter},
	}
}

// GetAuthorizedVoter returns the authorized voter for the given epoch.
func (av *AuthorizedVoters) GetAuthorizedVoter(epoch uint64) (types.Pubkey, bool) {
	// Find the most recent authorized voter at or before the given epoch
	var latestEpoch uint64
	var found bool
	var voter types.Pubkey

	for e, v := range av.Authorized {
		if e <= epoch && (!found || e > latestEpoch) {
			latestEpoch = e
			voter = v
			found = true
		}
	}
	return voter, found
}

// Contains checks if the voter is authorized at the given epoch.
func (av *AuthorizedVoters) Contains(epoch uint64) bool {
	_, ok := av.Authorized[epoch]
	return ok
}

// Insert inserts a new authorized voter at the given epoch.
func (av *AuthorizedVoters) Insert(epoch uint64, voter types.Pubkey) {
	av.Authorized[epoch] = voter
}

// PurgeAuthorizedVoters removes all authorized voters for epochs prior to the given epoch.
func (av *AuthorizedVoters) PurgeAuthorizedVoters(currentEpoch uint64) {
	for epoch := range av.Authorized {
		if epoch < currentEpoch {
			delete(av.Authorized, epoch)
		}
	}
}

// VoteState represents the state of a vote account.
type VoteState struct {
	// Node identity
	NodePubkey types.Pubkey

	// Authorized withdrawer
	AuthorizedWithdrawer types.Pubkey

	// Commission percentage (0-100)
	Commission uint8

	// Vote history (recent votes)
	Votes []Lockout

	// Root slot (oldest slot that has reached max lockout)
	RootSlot *uint64

	// Authorized voters by epoch
	AuthorizedVoters *AuthorizedVoters

	// Prior authorized voters
	PriorVoters []PriorVoter

	// Epoch credits history
	EpochCredits []EpochCredits

	// Last recorded timestamp
	LastTimestamp BlockTimestamp
}

// PriorVoter represents a prior authorized voter.
type PriorVoter struct {
	AuthorizedPubkey types.Pubkey
	EpochStart       uint64
	EpochEnd         uint64
}

// NewVoteState creates a new VoteState with the given initialization parameters.
func NewVoteState(init *VoteInit, currentEpoch uint64) *VoteState {
	return &VoteState{
		NodePubkey:           init.NodePubkey,
		AuthorizedWithdrawer: init.AuthorizedWithdrawer,
		Commission:           init.Commission,
		Votes:                make([]Lockout, 0, MaxLockoutHistory),
		RootSlot:             nil,
		AuthorizedVoters:     NewAuthorizedVoters(init.AuthorizedVoter, currentEpoch),
		PriorVoters:          make([]PriorVoter, 0),
		EpochCredits:         make([]EpochCredits, 0, MaxEpochCredits),
		LastTimestamp:        BlockTimestamp{},
	}
}

// GetAuthorizedVoter returns the authorized voter for the given epoch.
func (vs *VoteState) GetAuthorizedVoter(epoch uint64) (types.Pubkey, bool) {
	return vs.AuthorizedVoters.GetAuthorizedVoter(epoch)
}

// SetNewAuthorizedVoter sets a new authorized voter for the given epoch.
func (vs *VoteState) SetNewAuthorizedVoter(
	newVoter types.Pubkey,
	currentEpoch uint64,
	targetEpoch uint64,
	verify func(types.Pubkey) error,
) error {
	currentVoter, found := vs.AuthorizedVoters.GetAuthorizedVoter(currentEpoch)
	if !found {
		return ErrUnauthorized
	}

	// Verify the current voter authorized this change
	if err := verify(currentVoter); err != nil {
		return err
	}

	// Record the prior voter
	if currentVoter != newVoter {
		vs.PriorVoters = append(vs.PriorVoters, PriorVoter{
			AuthorizedPubkey: currentVoter,
			EpochStart:       currentEpoch,
			EpochEnd:         targetEpoch,
		})
	}

	vs.AuthorizedVoters.Insert(targetEpoch, newVoter)
	return nil
}

// ProcessVote processes a vote, updating the vote history and root slot.
func (vs *VoteState) ProcessVote(vote *Vote, slot uint64, epoch uint64) error {
	if len(vote.Slots) == 0 {
		return ErrEmptySlots
	}
	if len(vote.Slots) > MaxLockoutHistory {
		return ErrTooManyVotes
	}

	// Verify slots are ordered
	for i := 1; i < len(vote.Slots); i++ {
		if vote.Slots[i] <= vote.Slots[i-1] {
			return ErrSlotsNotOrdered
		}
	}

	// Process each vote slot
	for _, voteSlot := range vote.Slots {
		vs.processSlot(voteSlot, epoch)
	}

	// Update timestamp if provided
	if vote.Timestamp != nil {
		if err := vs.processTimestamp(slot, *vote.Timestamp); err != nil {
			return err
		}
	}

	return nil
}

// processSlot processes a single slot vote.
func (vs *VoteState) processSlot(slot uint64, epoch uint64) {
	// Pop expired lockouts
	for len(vs.Votes) > 0 {
		last := vs.Votes[len(vs.Votes)-1]
		if last.IsLockedOutAtSlot(slot) {
			break
		}
		vs.Votes = vs.Votes[:len(vs.Votes)-1]
	}

	// Pop and root votes that would be double-confirmed
	newRoot := vs.RootSlot
	for len(vs.Votes) > 0 && vs.Votes[0].ConfirmationCount >= MaxLockoutHistory {
		rootSlot := vs.Votes[0].Slot
		newRoot = &rootSlot
		vs.Votes = vs.Votes[1:]
	}
	vs.RootSlot = newRoot

	// Increment confirmation counts for all votes
	for i := range vs.Votes {
		vs.Votes[i].IncrementConfirmationCount()
	}

	// Add the new vote
	vs.Votes = append(vs.Votes, Lockout{
		Slot:              slot,
		ConfirmationCount: 1,
	})

	// Increment credits
	vs.incrementCredits(epoch, 1)
}

// incrementCredits increments the credits for the current epoch.
func (vs *VoteState) incrementCredits(epoch uint64, credits uint64) {
	if len(vs.EpochCredits) == 0 || vs.EpochCredits[len(vs.EpochCredits)-1].Epoch < epoch {
		var prevCredits uint64
		if len(vs.EpochCredits) > 0 {
			prevCredits = vs.EpochCredits[len(vs.EpochCredits)-1].Credits
		}
		vs.EpochCredits = append(vs.EpochCredits, EpochCredits{
			Epoch:       epoch,
			Credits:     prevCredits + credits,
			PrevCredits: prevCredits,
		})

		// Trim to max size
		if len(vs.EpochCredits) > MaxEpochCredits {
			vs.EpochCredits = vs.EpochCredits[len(vs.EpochCredits)-MaxEpochCredits:]
		}
	} else if vs.EpochCredits[len(vs.EpochCredits)-1].Epoch == epoch {
		vs.EpochCredits[len(vs.EpochCredits)-1].Credits += credits
	}
}

// processTimestamp processes a timestamp vote.
func (vs *VoteState) processTimestamp(slot uint64, timestamp int64) error {
	if slot < vs.LastTimestamp.Slot || timestamp < vs.LastTimestamp.Timestamp {
		return ErrTimestampTooOld
	}
	vs.LastTimestamp = BlockTimestamp{
		Slot:      slot,
		Timestamp: timestamp,
	}
	return nil
}

// Credits returns the total credits earned by this vote account.
func (vs *VoteState) Credits() uint64 {
	if len(vs.EpochCredits) == 0 {
		return 0
	}
	return vs.EpochCredits[len(vs.EpochCredits)-1].Credits
}

// LastVotedSlot returns the last slot that was voted on.
func (vs *VoteState) LastVotedSlot() *uint64 {
	if len(vs.Votes) == 0 {
		return nil
	}
	slot := vs.Votes[len(vs.Votes)-1].Slot
	return &slot
}

// Serialize serializes the VoteState to bytes.
func (vs *VoteState) Serialize() ([]byte, error) {
	// Estimate size: fixed fields + variable length arrays
	size := 32 + 32 + 1 + // node_pubkey + authorized_withdrawer + commission
		4 + len(vs.Votes)*12 + // votes array
		1 + 8 + // root_slot option
		4 + len(vs.AuthorizedVoters.Authorized)*(8+32) + // authorized_voters
		4 + len(vs.PriorVoters)*(32+8+8) + // prior_voters
		4 + len(vs.EpochCredits)*24 + // epoch_credits
		16 // last_timestamp

	data := make([]byte, 0, size)

	// NodePubkey (32 bytes)
	data = append(data, vs.NodePubkey[:]...)

	// AuthorizedWithdrawer (32 bytes)
	data = append(data, vs.AuthorizedWithdrawer[:]...)

	// Commission (1 byte)
	data = append(data, vs.Commission)

	// Votes array (4 byte length prefix + 12 bytes per vote)
	votesLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(votesLen, uint32(len(vs.Votes)))
	data = append(data, votesLen...)
	for _, vote := range vs.Votes {
		data = append(data, vote.Encode()...)
	}

	// RootSlot option (1 byte flag + 8 byte slot if present)
	if vs.RootSlot != nil {
		data = append(data, 1)
		rootSlotBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(rootSlotBytes, *vs.RootSlot)
		data = append(data, rootSlotBytes...)
	} else {
		data = append(data, 0)
	}

	// AuthorizedVoters (4 byte length + entries)
	avLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(avLen, uint32(len(vs.AuthorizedVoters.Authorized)))
	data = append(data, avLen...)
	for epoch, voter := range vs.AuthorizedVoters.Authorized {
		epochBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(epochBytes, epoch)
		data = append(data, epochBytes...)
		data = append(data, voter[:]...)
	}

	// PriorVoters (4 byte length + entries)
	pvLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(pvLen, uint32(len(vs.PriorVoters)))
	data = append(data, pvLen...)
	for _, pv := range vs.PriorVoters {
		data = append(data, pv.AuthorizedPubkey[:]...)
		epochStart := make([]byte, 8)
		binary.LittleEndian.PutUint64(epochStart, pv.EpochStart)
		data = append(data, epochStart...)
		epochEnd := make([]byte, 8)
		binary.LittleEndian.PutUint64(epochEnd, pv.EpochEnd)
		data = append(data, epochEnd...)
	}

	// EpochCredits (4 byte length + entries)
	ecLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(ecLen, uint32(len(vs.EpochCredits)))
	data = append(data, ecLen...)
	for _, ec := range vs.EpochCredits {
		data = append(data, ec.Encode()...)
	}

	// LastTimestamp (16 bytes)
	data = append(data, vs.LastTimestamp.Encode()...)

	return data, nil
}

// DeserializeVoteState deserializes a VoteState from bytes.
func DeserializeVoteState(data []byte) (*VoteState, error) {
	if len(data) < 65 { // Minimum: 32 + 32 + 1
		return nil, fmt.Errorf("vote state data too short: need at least 65 bytes, got %d", len(data))
	}

	offset := 0

	// NodePubkey (32 bytes)
	var nodePubkey types.Pubkey
	copy(nodePubkey[:], data[offset:offset+32])
	offset += 32

	// AuthorizedWithdrawer (32 bytes)
	var authorizedWithdrawer types.Pubkey
	copy(authorizedWithdrawer[:], data[offset:offset+32])
	offset += 32

	// Commission (1 byte)
	commission := data[offset]
	offset++

	// Votes array
	if offset+4 > len(data) {
		return nil, fmt.Errorf("truncated votes length")
	}
	votesLen := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	votes := make([]Lockout, votesLen)
	for i := uint32(0); i < votesLen; i++ {
		if offset+12 > len(data) {
			return nil, fmt.Errorf("truncated vote %d", i)
		}
		vote, err := DecodeLockout(data[offset : offset+12])
		if err != nil {
			return nil, fmt.Errorf("decode vote %d: %w", i, err)
		}
		votes[i] = *vote
		offset += 12
	}

	// RootSlot option
	if offset+1 > len(data) {
		return nil, fmt.Errorf("truncated root slot flag")
	}
	var rootSlot *uint64
	if data[offset] == 1 {
		offset++
		if offset+8 > len(data) {
			return nil, fmt.Errorf("truncated root slot")
		}
		slot := binary.LittleEndian.Uint64(data[offset : offset+8])
		rootSlot = &slot
		offset += 8
	} else {
		offset++
	}

	// AuthorizedVoters
	if offset+4 > len(data) {
		return nil, fmt.Errorf("truncated authorized voters length")
	}
	avLen := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	authorizedVoters := &AuthorizedVoters{
		Authorized: make(map[uint64]types.Pubkey),
	}
	for i := uint32(0); i < avLen; i++ {
		if offset+40 > len(data) {
			return nil, fmt.Errorf("truncated authorized voter %d", i)
		}
		epoch := binary.LittleEndian.Uint64(data[offset : offset+8])
		offset += 8
		var voter types.Pubkey
		copy(voter[:], data[offset:offset+32])
		offset += 32
		authorizedVoters.Authorized[epoch] = voter
	}

	// PriorVoters
	if offset+4 > len(data) {
		return nil, fmt.Errorf("truncated prior voters length")
	}
	pvLen := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	priorVoters := make([]PriorVoter, pvLen)
	for i := uint32(0); i < pvLen; i++ {
		if offset+48 > len(data) {
			return nil, fmt.Errorf("truncated prior voter %d", i)
		}
		var authPubkey types.Pubkey
		copy(authPubkey[:], data[offset:offset+32])
		offset += 32
		epochStart := binary.LittleEndian.Uint64(data[offset : offset+8])
		offset += 8
		epochEnd := binary.LittleEndian.Uint64(data[offset : offset+8])
		offset += 8
		priorVoters[i] = PriorVoter{
			AuthorizedPubkey: authPubkey,
			EpochStart:       epochStart,
			EpochEnd:         epochEnd,
		}
	}

	// EpochCredits
	if offset+4 > len(data) {
		return nil, fmt.Errorf("truncated epoch credits length")
	}
	ecLen := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	epochCredits := make([]EpochCredits, ecLen)
	for i := uint32(0); i < ecLen; i++ {
		if offset+24 > len(data) {
			return nil, fmt.Errorf("truncated epoch credits %d", i)
		}
		ec, err := DecodeEpochCredits(data[offset : offset+24])
		if err != nil {
			return nil, fmt.Errorf("decode epoch credits %d: %w", i, err)
		}
		epochCredits[i] = *ec
		offset += 24
	}

	// LastTimestamp
	if offset+16 > len(data) {
		return nil, fmt.Errorf("truncated last timestamp")
	}
	lastTimestamp, err := DecodeBlockTimestamp(data[offset : offset+16])
	if err != nil {
		return nil, fmt.Errorf("decode last timestamp: %w", err)
	}

	return &VoteState{
		NodePubkey:           nodePubkey,
		AuthorizedWithdrawer: authorizedWithdrawer,
		Commission:           commission,
		Votes:                votes,
		RootSlot:             rootSlot,
		AuthorizedVoters:     authorizedVoters,
		PriorVoters:          priorVoters,
		EpochCredits:         epochCredits,
		LastTimestamp:        *lastTimestamp,
	}, nil
}

// IsInitialized returns true if the vote state appears to be initialized.
func IsInitialized(data []byte) bool {
	if len(data) < 65 {
		return false
	}
	// Check if node pubkey is non-zero
	var nodePubkey types.Pubkey
	copy(nodePubkey[:], data[0:32])
	return nodePubkey != types.ZeroPubkey
}
