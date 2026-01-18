package accounts

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// Serialization format:
// - lamports:   8 bytes (little-endian uint64)
// - data_len:   4 bytes (little-endian uint32)
// - data:       data_len bytes
// - owner:      32 bytes
// - executable: 1 byte (0 or 1)
// - rent_epoch: 8 bytes (little-endian uint64)
//
// Total fixed size: 8 + 4 + 32 + 1 + 8 = 53 bytes + variable data

const (
	serializationHeaderSize = 8 + 4           // lamports + data_len
	serializationFooterSize = 32 + 1 + 8      // owner + executable + rent_epoch
	serializationMinSize    = serializationHeaderSize + serializationFooterSize
)

var (
	// ErrInvalidAccountData is returned when account data is malformed.
	ErrInvalidAccountData = errors.New("invalid account data")
)

// SerializeAccount serializes an account to binary format.
func SerializeAccount(account *types.Account) ([]byte, error) {
	if account == nil {
		return nil, errors.New("cannot serialize nil account")
	}

	dataLen := len(account.Data)
	totalSize := serializationMinSize + dataLen
	buf := make([]byte, totalSize)

	offset := 0

	// Write lamports (8 bytes, little-endian)
	binary.LittleEndian.PutUint64(buf[offset:], uint64(account.Lamports))
	offset += 8

	// Write data_len (4 bytes, little-endian)
	binary.LittleEndian.PutUint32(buf[offset:], uint32(dataLen))
	offset += 4

	// Write data
	if dataLen > 0 {
		copy(buf[offset:], account.Data)
		offset += dataLen
	}

	// Write owner (32 bytes)
	copy(buf[offset:], account.Owner[:])
	offset += 32

	// Write executable (1 byte)
	if account.Executable {
		buf[offset] = 1
	} else {
		buf[offset] = 0
	}
	offset++

	// Write rent_epoch (8 bytes, little-endian)
	binary.LittleEndian.PutUint64(buf[offset:], uint64(account.RentEpoch))

	return buf, nil
}

// DeserializeAccount deserializes an account from binary format.
func DeserializeAccount(data []byte) (*types.Account, error) {
	if len(data) < serializationMinSize {
		return nil, fmt.Errorf("%w: data too short, need at least %d bytes, got %d",
			ErrInvalidAccountData, serializationMinSize, len(data))
	}

	offset := 0

	// Read lamports (8 bytes, little-endian)
	lamports := types.Lamports(binary.LittleEndian.Uint64(data[offset:]))
	offset += 8

	// Read data_len (4 bytes, little-endian)
	dataLen := binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	// Validate total size
	expectedSize := serializationMinSize + int(dataLen)
	if len(data) < expectedSize {
		return nil, fmt.Errorf("%w: data length mismatch, expected %d bytes, got %d",
			ErrInvalidAccountData, expectedSize, len(data))
	}

	// Read data
	var accountData []byte
	if dataLen > 0 {
		accountData = make([]byte, dataLen)
		copy(accountData, data[offset:offset+int(dataLen)])
		offset += int(dataLen)
	}

	// Read owner (32 bytes)
	var owner types.Pubkey
	copy(owner[:], data[offset:offset+32])
	offset += 32

	// Read executable (1 byte)
	executable := data[offset] != 0
	offset++

	// Read rent_epoch (8 bytes, little-endian)
	rentEpoch := types.Epoch(binary.LittleEndian.Uint64(data[offset:]))

	return &types.Account{
		Lamports:   lamports,
		Data:       accountData,
		Owner:      owner,
		Executable: executable,
		RentEpoch:  rentEpoch,
	}, nil
}
