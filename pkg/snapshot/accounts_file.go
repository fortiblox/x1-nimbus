package snapshot

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// AppendVec file format (Solana's account storage format):
//
// Each account entry in an AppendVec has the following layout:
// - stored_meta (StoredMeta): metadata about the account
// - account_meta (AccountMeta): account state
// - padding: alignment padding
// - pubkey: 32 bytes
// - data: variable length account data
//
// StoredMeta layout (64 bytes):
// - write_version: 8 bytes (u64)
// - data_len: 8 bytes (u64)
// - pubkey: 32 bytes
// - padding: 16 bytes
//
// AccountMeta layout (variable, depends on version):
// - lamports: 8 bytes (u64)
// - rent_epoch: 8 bytes (u64)
// - owner: 32 bytes
// - executable: 1 byte (bool)
// - padding to 8-byte alignment

const (
	// StoredMetaSize is the size of the StoredMeta header.
	StoredMetaSize = 64
	// AccountMetaBaseSize is the base size of AccountMeta (without padding).
	AccountMetaBaseSize = 8 + 8 + 32 + 1 // lamports + rent_epoch + owner + executable
	// Alignment for account entries
	AppendVecAlignment = 8
)

var (
	// ErrInvalidAppendVec is returned when the AppendVec format is invalid.
	ErrInvalidAppendVec = errors.New("invalid AppendVec format")
	// ErrEndOfFile is returned when the end of the file is reached.
	ErrEndOfFile = errors.New("end of file")
)

// StoredMeta contains metadata about a stored account.
type StoredMeta struct {
	WriteVersion uint64
	DataLen      uint64
	Pubkey       types.Pubkey
}

// AccountEntry represents an account read from an AppendVec.
type AccountEntry struct {
	StoredMeta StoredMeta
	Account    *types.Account
	Offset     uint64 // Offset within the file
}

// AccountsFileReader reads accounts from an AppendVec file.
type AccountsFileReader struct {
	file     *os.File
	fileSize int64
	offset   int64
}

// NewAccountsFileReader creates a new reader for an AppendVec file.
func NewAccountsFileReader(path string) (*AccountsFileReader, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open AppendVec file: %w", err)
	}

	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	return &AccountsFileReader{
		file:     file,
		fileSize: stat.Size(),
		offset:   0,
	}, nil
}

// NewAccountsFileReaderFromBytes creates a new reader from bytes.
func NewAccountsFileReaderFromBytes(data []byte) *AccountsFileReaderBytes {
	return &AccountsFileReaderBytes{
		data:   data,
		offset: 0,
	}
}

// AccountsFileReaderBytes reads accounts from an in-memory AppendVec.
type AccountsFileReaderBytes struct {
	data   []byte
	offset int64
}

// ReadNext reads the next account from the AppendVec.
func (r *AccountsFileReaderBytes) ReadNext() (*AccountEntry, error) {
	if r.offset >= int64(len(r.data)) {
		return nil, ErrEndOfFile
	}

	startOffset := r.offset

	// Read StoredMeta
	if r.offset+StoredMetaSize > int64(len(r.data)) {
		return nil, ErrEndOfFile
	}

	meta := r.data[r.offset : r.offset+StoredMetaSize]
	storedMeta := StoredMeta{
		WriteVersion: binary.LittleEndian.Uint64(meta[0:8]),
		DataLen:      binary.LittleEndian.Uint64(meta[8:16]),
	}
	copy(storedMeta.Pubkey[:], meta[16:48])
	r.offset += StoredMetaSize

	// Read AccountMeta
	if r.offset+AccountMetaBaseSize > int64(len(r.data)) {
		return nil, fmt.Errorf("%w: not enough data for AccountMeta", ErrInvalidAppendVec)
	}

	accountMeta := r.data[r.offset : r.offset+AccountMetaBaseSize]
	lamports := types.Lamports(binary.LittleEndian.Uint64(accountMeta[0:8]))
	rentEpoch := types.Epoch(binary.LittleEndian.Uint64(accountMeta[8:16]))
	var owner types.Pubkey
	copy(owner[:], accountMeta[16:48])
	executable := accountMeta[48] != 0
	r.offset += AccountMetaBaseSize

	// Align to 8 bytes
	r.offset = alignTo(r.offset, AppendVecAlignment)

	// Read account data
	if r.offset+int64(storedMeta.DataLen) > int64(len(r.data)) {
		return nil, fmt.Errorf("%w: not enough data for account data", ErrInvalidAppendVec)
	}

	var accountData []byte
	if storedMeta.DataLen > 0 {
		accountData = make([]byte, storedMeta.DataLen)
		copy(accountData, r.data[r.offset:r.offset+int64(storedMeta.DataLen)])
		r.offset += int64(storedMeta.DataLen)
	}

	// Align for next entry
	r.offset = alignTo(r.offset, AppendVecAlignment)

	return &AccountEntry{
		StoredMeta: storedMeta,
		Account: &types.Account{
			Lamports:   lamports,
			Data:       accountData,
			Owner:      owner,
			Executable: executable,
			RentEpoch:  rentEpoch,
		},
		Offset: uint64(startOffset),
	}, nil
}

// Reset resets the reader to the beginning.
func (r *AccountsFileReaderBytes) Reset() {
	r.offset = 0
}

// ReadNext reads the next account from the AppendVec.
func (r *AccountsFileReader) ReadNext() (*AccountEntry, error) {
	if r.offset >= r.fileSize {
		return nil, ErrEndOfFile
	}

	startOffset := r.offset

	// Read StoredMeta
	metaBuf := make([]byte, StoredMetaSize)
	n, err := r.file.Read(metaBuf)
	if err == io.EOF {
		return nil, ErrEndOfFile
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read StoredMeta: %w", err)
	}
	if n < StoredMetaSize {
		return nil, ErrEndOfFile
	}
	r.offset += int64(n)

	storedMeta := StoredMeta{
		WriteVersion: binary.LittleEndian.Uint64(metaBuf[0:8]),
		DataLen:      binary.LittleEndian.Uint64(metaBuf[8:16]),
	}
	copy(storedMeta.Pubkey[:], metaBuf[16:48])

	// Read AccountMeta
	accountMetaBuf := make([]byte, AccountMetaBaseSize)
	n, err = r.file.Read(accountMetaBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to read AccountMeta: %w", err)
	}
	if n < AccountMetaBaseSize {
		return nil, fmt.Errorf("%w: not enough data for AccountMeta", ErrInvalidAppendVec)
	}
	r.offset += int64(n)

	lamports := types.Lamports(binary.LittleEndian.Uint64(accountMetaBuf[0:8]))
	rentEpoch := types.Epoch(binary.LittleEndian.Uint64(accountMetaBuf[8:16]))
	var owner types.Pubkey
	copy(owner[:], accountMetaBuf[16:48])
	executable := accountMetaBuf[48] != 0

	// Skip padding to align to 8 bytes
	alignedOffset := alignTo(r.offset, AppendVecAlignment)
	if alignedOffset > r.offset {
		padding := alignedOffset - r.offset
		if _, err := r.file.Seek(padding, io.SeekCurrent); err != nil {
			return nil, fmt.Errorf("failed to skip padding: %w", err)
		}
		r.offset = alignedOffset
	}

	// Read account data
	var accountData []byte
	if storedMeta.DataLen > 0 {
		accountData = make([]byte, storedMeta.DataLen)
		n, err = io.ReadFull(r.file, accountData)
		if err != nil {
			return nil, fmt.Errorf("failed to read account data: %w", err)
		}
		r.offset += int64(n)
	}

	// Align for next entry
	alignedOffset = alignTo(r.offset, AppendVecAlignment)
	if alignedOffset > r.offset {
		padding := alignedOffset - r.offset
		if _, err := r.file.Seek(padding, io.SeekCurrent); err != nil {
			return nil, fmt.Errorf("failed to skip padding: %w", err)
		}
		r.offset = alignedOffset
	}

	return &AccountEntry{
		StoredMeta: storedMeta,
		Account: &types.Account{
			Lamports:   lamports,
			Data:       accountData,
			Owner:      owner,
			Executable: executable,
			RentEpoch:  rentEpoch,
		},
		Offset: uint64(startOffset),
	}, nil
}

// Reset resets the reader to the beginning.
func (r *AccountsFileReader) Reset() error {
	_, err := r.file.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("failed to seek: %w", err)
	}
	r.offset = 0
	return nil
}

// Close closes the reader.
func (r *AccountsFileReader) Close() error {
	return r.file.Close()
}

// Offset returns the current offset in the file.
func (r *AccountsFileReader) Offset() int64 {
	return r.offset
}

// FileSize returns the file size.
func (r *AccountsFileReader) FileSize() int64 {
	return r.fileSize
}

// ReadAll reads all accounts from the AppendVec.
func (r *AccountsFileReader) ReadAll() ([]*AccountEntry, error) {
	if err := r.Reset(); err != nil {
		return nil, err
	}

	var accounts []*AccountEntry
	for {
		entry, err := r.ReadNext()
		if err == ErrEndOfFile {
			break
		}
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, entry)
	}

	return accounts, nil
}

// alignTo aligns offset to the given alignment.
func alignTo(offset int64, alignment int64) int64 {
	remainder := offset % alignment
	if remainder == 0 {
		return offset
	}
	return offset + (alignment - remainder)
}

// ParseAccountsFilePath parses an AppendVec filename to extract slot and ID.
// Format: <slot>.<id>
func ParseAccountsFilePath(filename string) (slot uint64, id uint64, err error) {
	// Format: slot.id
	var parsedSlot, parsedID uint64
	_, err = fmt.Sscanf(filename, "%d.%d", &parsedSlot, &parsedID)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid AppendVec filename format: %s", filename)
	}
	return parsedSlot, parsedID, nil
}

// AccountsFileIterator provides an iterator interface for reading accounts.
type AccountsFileIterator struct {
	reader  *AccountsFileReader
	current *AccountEntry
	err     error
}

// NewAccountsFileIterator creates a new iterator for an AppendVec file.
func NewAccountsFileIterator(path string) (*AccountsFileIterator, error) {
	reader, err := NewAccountsFileReader(path)
	if err != nil {
		return nil, err
	}
	return &AccountsFileIterator{reader: reader}, nil
}

// Next advances to the next account.
func (it *AccountsFileIterator) Next() bool {
	entry, err := it.reader.ReadNext()
	if err == ErrEndOfFile {
		return false
	}
	if err != nil {
		it.err = err
		return false
	}
	it.current = entry
	return true
}

// Account returns the current account entry.
func (it *AccountsFileIterator) Account() *AccountEntry {
	return it.current
}

// Err returns any error that occurred during iteration.
func (it *AccountsFileIterator) Err() error {
	return it.err
}

// Close closes the iterator.
func (it *AccountsFileIterator) Close() error {
	return it.reader.Close()
}
