package types

import (
	"fmt"
)

// Transaction represents a complete transaction with signatures.
type Transaction struct {
	Signatures []Signature
	Message    Message
}

// Message represents a transaction message (the part that gets signed).
type Message struct {
	Header          MessageHeader
	AccountKeys     []Pubkey
	RecentBlockhash Hash
	Instructions    []CompiledInstruction
}

// MessageHeader contains counts for account types.
type MessageHeader struct {
	NumRequiredSignatures       uint8
	NumReadonlySignedAccounts   uint8
	NumReadonlyUnsignedAccounts uint8
}

// CompiledInstruction is an instruction with account indices.
type CompiledInstruction struct {
	ProgramIDIndex uint8
	AccountIndices []uint8
	Data           []byte
}

// Instruction is an expanded instruction with full account info.
type Instruction struct {
	ProgramID Pubkey
	Accounts  []AccountMeta
	Data      []byte
}

// VersionedTransaction supports both legacy and v0 transactions.
type VersionedTransaction struct {
	Signatures []Signature
	Message    VersionedMessage
}

// VersionedMessage can be legacy or v0.
type VersionedMessage struct {
	Version uint8 // 0 = legacy (no version byte), 127 = v0
	Legacy  *Message
	V0      *MessageV0
}

// MessageV0 is a v0 message with address lookup tables.
type MessageV0 struct {
	Header              MessageHeader
	AccountKeys         []Pubkey
	RecentBlockhash     Hash
	Instructions        []CompiledInstruction
	AddressTableLookups []AddressTableLookup
}

// AddressTableLookup references addresses from a lookup table.
type AddressTableLookup struct {
	AccountKey      Pubkey
	WritableIndexes []uint8
	ReadonlyIndexes []uint8
}

// IsLegacy returns true if this is a legacy message.
func (m *VersionedMessage) IsLegacy() bool {
	return m.Legacy != nil
}

// IsV0 returns true if this is a v0 message.
func (m *VersionedMessage) IsV0() bool {
	return m.V0 != nil
}

// GetAccountKeys returns account keys from the message.
func (m *VersionedMessage) GetAccountKeys() []Pubkey {
	if m.Legacy != nil {
		return m.Legacy.AccountKeys
	}
	if m.V0 != nil {
		return m.V0.AccountKeys
	}
	return nil
}

// GetRecentBlockhash returns the recent blockhash.
func (m *VersionedMessage) GetRecentBlockhash() Hash {
	if m.Legacy != nil {
		return m.Legacy.RecentBlockhash
	}
	if m.V0 != nil {
		return m.V0.RecentBlockhash
	}
	return ZeroHash
}

// GetInstructions returns instructions from the message.
func (m *VersionedMessage) GetInstructions() []CompiledInstruction {
	if m.Legacy != nil {
		return m.Legacy.Instructions
	}
	if m.V0 != nil {
		return m.V0.Instructions
	}
	return nil
}

// NumSignatures returns the number of required signatures.
func (m *VersionedMessage) NumSignatures() int {
	if m.Legacy != nil {
		return int(m.Legacy.Header.NumRequiredSignatures)
	}
	if m.V0 != nil {
		return int(m.V0.Header.NumRequiredSignatures)
	}
	return 0
}

// GetSigners returns the pubkeys of accounts that must sign.
func (m *VersionedMessage) GetSigners() []Pubkey {
	keys := m.GetAccountKeys()
	numSigners := m.NumSignatures()
	if numSigners > len(keys) {
		numSigners = len(keys)
	}
	return keys[:numSigners]
}

// Serialize serializes the message for signing.
func (m *Message) Serialize() ([]byte, error) {
	buf := make([]byte, 0, 256)

	// Header
	buf = append(buf, m.Header.NumRequiredSignatures)
	buf = append(buf, m.Header.NumReadonlySignedAccounts)
	buf = append(buf, m.Header.NumReadonlyUnsignedAccounts)

	// Account keys count (compact-u16)
	buf = appendCompactU16(buf, len(m.AccountKeys))

	// Account keys
	for _, key := range m.AccountKeys {
		buf = append(buf, key[:]...)
	}

	// Recent blockhash
	buf = append(buf, m.RecentBlockhash[:]...)

	// Instructions count (compact-u16)
	buf = appendCompactU16(buf, len(m.Instructions))

	// Instructions
	for _, ix := range m.Instructions {
		// Program ID index
		buf = append(buf, ix.ProgramIDIndex)

		// Account indices (compact-u16 + indices)
		buf = appendCompactU16(buf, len(ix.AccountIndices))
		buf = append(buf, ix.AccountIndices...)

		// Data (compact-u16 + data)
		buf = appendCompactU16(buf, len(ix.Data))
		buf = append(buf, ix.Data...)
	}

	return buf, nil
}

// appendCompactU16 appends a compact u16 encoding.
func appendCompactU16(buf []byte, val int) []byte {
	if val < 0x80 {
		return append(buf, byte(val))
	}
	if val < 0x4000 {
		return append(buf, byte(val&0x7f|0x80), byte(val>>7))
	}
	return append(buf, byte(val&0x7f|0x80), byte((val>>7)&0x7f|0x80), byte(val>>14))
}

// TransactionResult represents the result of executing a transaction.
type TransactionResult struct {
	Success      bool
	Error        error
	Logs         []string
	ComputeUnits ComputeUnits
	ReturnData   []byte
	AccountDeltas []AccountDelta
}

// Entry represents a PoH entry (batch of transactions).
type Entry struct {
	NumHashes    uint64        // PoH iterations since last entry
	Hash         Hash          // Entry hash (PoH hash after this entry)
	Transactions []Transaction // Transactions in this entry (empty for tick)
}

// IsTick returns true if this is a tick entry (no transactions).
func (e *Entry) IsTick() bool {
	return len(e.Transactions) == 0
}

// Block represents a complete block.
type Block struct {
	Slot              Slot
	ParentSlot        Slot
	Blockhash         Hash
	PreviousBlockhash Hash
	Entries           []Entry
	BlockTime         *int64 // Unix timestamp (optional)
	BlockHeight       *uint64
}

// NumTransactions returns the total number of transactions in the block.
func (b *Block) NumTransactions() int {
	count := 0
	for _, entry := range b.Entries {
		count += len(entry.Transactions)
	}
	return count
}

// AllTransactions returns all transactions in the block.
func (b *Block) AllTransactions() []Transaction {
	var txs []Transaction
	for _, entry := range b.Entries {
		txs = append(txs, entry.Transactions...)
	}
	return txs
}

// ParseCompactU16 parses a compact-u16 from a byte slice.
func ParseCompactU16(data []byte) (val uint16, bytesRead int, err error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("empty data")
	}

	b0 := data[0]
	if b0 < 0x80 {
		return uint16(b0), 1, nil
	}

	if len(data) < 2 {
		return 0, 0, fmt.Errorf("incomplete compact-u16")
	}
	b1 := data[1]
	if b1 < 0x80 {
		return uint16(b0&0x7f) | uint16(b1)<<7, 2, nil
	}

	if len(data) < 3 {
		return 0, 0, fmt.Errorf("incomplete compact-u16")
	}
	b2 := data[2]
	return uint16(b0&0x7f) | uint16(b1&0x7f)<<7 | uint16(b2)<<14, 3, nil
}

// SerializeCompactU16 serializes a uint16 in compact format.
func SerializeCompactU16(val uint16) []byte {
	if val < 0x80 {
		return []byte{byte(val)}
	}
	if val < 0x4000 {
		return []byte{byte(val&0x7f | 0x80), byte(val >> 7)}
	}
	return []byte{byte(val&0x7f | 0x80), byte((val>>7)&0x7f | 0x80), byte(val >> 14)}
}

// DeserializeTransaction deserializes a transaction from bytes.
func DeserializeTransaction(data []byte) (*Transaction, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("transaction too short")
	}

	offset := 0

	// Number of signatures (compact-u16)
	numSigs, n, err := ParseCompactU16(data[offset:])
	if err != nil {
		return nil, fmt.Errorf("parse num signatures: %w", err)
	}
	offset += n

	// Read signatures
	sigs := make([]Signature, numSigs)
	for i := range sigs {
		if offset+64 > len(data) {
			return nil, fmt.Errorf("truncated signature %d", i)
		}
		copy(sigs[i][:], data[offset:offset+64])
		offset += 64
	}

	// Parse message
	msg, err := deserializeMessage(data[offset:])
	if err != nil {
		return nil, fmt.Errorf("parse message: %w", err)
	}

	return &Transaction{
		Signatures: sigs,
		Message:    *msg,
	}, nil
}

func deserializeMessage(data []byte) (*Message, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("message too short")
	}

	offset := 0

	// Header
	header := MessageHeader{
		NumRequiredSignatures:       data[offset],
		NumReadonlySignedAccounts:   data[offset+1],
		NumReadonlyUnsignedAccounts: data[offset+2],
	}
	offset += 3

	// Number of account keys (compact-u16)
	numKeys, n, err := ParseCompactU16(data[offset:])
	if err != nil {
		return nil, fmt.Errorf("parse num account keys: %w", err)
	}
	offset += n

	// Account keys
	keys := make([]Pubkey, numKeys)
	for i := range keys {
		if offset+32 > len(data) {
			return nil, fmt.Errorf("truncated account key %d", i)
		}
		copy(keys[i][:], data[offset:offset+32])
		offset += 32
	}

	// Recent blockhash
	if offset+32 > len(data) {
		return nil, fmt.Errorf("truncated blockhash")
	}
	var blockhash Hash
	copy(blockhash[:], data[offset:offset+32])
	offset += 32

	// Number of instructions (compact-u16)
	numIx, n, err := ParseCompactU16(data[offset:])
	if err != nil {
		return nil, fmt.Errorf("parse num instructions: %w", err)
	}
	offset += n

	// Instructions
	instructions := make([]CompiledInstruction, numIx)
	for i := range instructions {
		ix, bytesRead, err := deserializeInstruction(data[offset:])
		if err != nil {
			return nil, fmt.Errorf("parse instruction %d: %w", i, err)
		}
		instructions[i] = *ix
		offset += bytesRead
	}

	return &Message{
		Header:          header,
		AccountKeys:     keys,
		RecentBlockhash: blockhash,
		Instructions:    instructions,
	}, nil
}

func deserializeInstruction(data []byte) (*CompiledInstruction, int, error) {
	offset := 0

	// Program ID index
	if len(data) < 1 {
		return nil, 0, fmt.Errorf("empty instruction")
	}
	programIDIndex := data[offset]
	offset++

	// Account indices (compact-u16 + bytes)
	numAccounts, n, err := ParseCompactU16(data[offset:])
	if err != nil {
		return nil, 0, fmt.Errorf("parse num accounts: %w", err)
	}
	offset += n

	if offset+int(numAccounts) > len(data) {
		return nil, 0, fmt.Errorf("truncated account indices")
	}
	accountIndices := make([]uint8, numAccounts)
	copy(accountIndices, data[offset:offset+int(numAccounts)])
	offset += int(numAccounts)

	// Data (compact-u16 + bytes)
	dataLen, n, err := ParseCompactU16(data[offset:])
	if err != nil {
		return nil, 0, fmt.Errorf("parse data len: %w", err)
	}
	offset += n

	if offset+int(dataLen) > len(data) {
		return nil, 0, fmt.Errorf("truncated instruction data")
	}
	ixData := make([]byte, dataLen)
	copy(ixData, data[offset:offset+int(dataLen)])
	offset += int(dataLen)

	return &CompiledInstruction{
		ProgramIDIndex: programIDIndex,
		AccountIndices: accountIndices,
		Data:           ixData,
	}, offset, nil
}

// FeePayer returns the fee payer (first signer).
func (tx *Transaction) FeePayer() Pubkey {
	if len(tx.Message.AccountKeys) == 0 {
		return ZeroPubkey
	}
	return tx.Message.AccountKeys[0]
}

// ID returns the transaction signature (first signature).
func (tx *Transaction) ID() Signature {
	if len(tx.Signatures) == 0 {
		return ZeroSignature
	}
	return tx.Signatures[0]
}
