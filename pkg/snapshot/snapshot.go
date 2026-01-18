// Package snapshot provides snapshot loading capability for X1-Nimbus.
// Snapshots allow fast sync by loading a pre-verified state instead of replaying from genesis.
package snapshot

import (
	"archive/tar"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/fortiblox/x1-nimbus/pkg/types"
	"github.com/klauspost/compress/zstd"
)

var (
	// ErrInvalidManifest is returned when the manifest is malformed.
	ErrInvalidManifest = errors.New("invalid manifest")
	// ErrInvalidArchive is returned when the archive is malformed.
	ErrInvalidArchive = errors.New("invalid archive")
	// ErrSnapshotNotFound is returned when a snapshot cannot be found.
	ErrSnapshotNotFound = errors.New("snapshot not found")
	// ErrHashMismatch is returned when a hash verification fails.
	ErrHashMismatch = errors.New("hash mismatch")
)

// SnapshotType represents the type of snapshot.
type SnapshotType int

const (
	// SnapshotTypeFull represents a full snapshot.
	SnapshotTypeFull SnapshotType = iota
	// SnapshotTypeIncremental represents an incremental snapshot.
	SnapshotTypeIncremental
)

// SnapshotManifest contains metadata about a snapshot.
type SnapshotManifest struct {
	Slot          uint64     `json:"slot"`
	Hash          types.Hash `json:"hash"`
	AccountsCount uint64     `json:"accounts_count"`
	LamportsTotal uint64     `json:"lamports_total"`
	BankHash      types.Hash `json:"bank_hash"`
	AccountsHash  types.Hash `json:"accounts_hash"`
	Version       uint32     `json:"version"`
	SnapshotType  SnapshotType `json:"snapshot_type"`
	// For incremental snapshots
	BaseSlot uint64 `json:"base_slot,omitempty"`
}

// MarshalJSON implements custom JSON marshaling for SnapshotManifest.
func (m *SnapshotManifest) MarshalJSON() ([]byte, error) {
	type Alias SnapshotManifest
	return json.Marshal(&struct {
		Hash         string `json:"hash"`
		BankHash     string `json:"bank_hash"`
		AccountsHash string `json:"accounts_hash"`
		*Alias
	}{
		Hash:         m.Hash.String(),
		BankHash:     m.BankHash.String(),
		AccountsHash: m.AccountsHash.String(),
		Alias:        (*Alias)(m),
	})
}

// UnmarshalJSON implements custom JSON unmarshaling for SnapshotManifest.
func (m *SnapshotManifest) UnmarshalJSON(data []byte) error {
	type Alias SnapshotManifest
	aux := &struct {
		Hash         string `json:"hash"`
		BankHash     string `json:"bank_hash"`
		AccountsHash string `json:"accounts_hash"`
		*Alias
	}{
		Alias: (*Alias)(m),
	}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	var err error
	if aux.Hash != "" {
		m.Hash, err = types.HashFromBase58(aux.Hash)
		if err != nil {
			return fmt.Errorf("invalid hash: %w", err)
		}
	}
	if aux.BankHash != "" {
		m.BankHash, err = types.HashFromBase58(aux.BankHash)
		if err != nil {
			return fmt.Errorf("invalid bank hash: %w", err)
		}
	}
	if aux.AccountsHash != "" {
		m.AccountsHash, err = types.HashFromBase58(aux.AccountsHash)
		if err != nil {
			return fmt.Errorf("invalid accounts hash: %w", err)
		}
	}
	return nil
}

// SerializeBinary serializes the manifest to binary format.
func (m *SnapshotManifest) SerializeBinary() ([]byte, error) {
	// Format:
	// - version: 4 bytes
	// - snapshot_type: 1 byte
	// - slot: 8 bytes
	// - base_slot: 8 bytes
	// - hash: 32 bytes
	// - bank_hash: 32 bytes
	// - accounts_hash: 32 bytes
	// - accounts_count: 8 bytes
	// - lamports_total: 8 bytes
	// Total: 133 bytes
	buf := make([]byte, 133)
	offset := 0

	binary.LittleEndian.PutUint32(buf[offset:], m.Version)
	offset += 4

	buf[offset] = byte(m.SnapshotType)
	offset++

	binary.LittleEndian.PutUint64(buf[offset:], m.Slot)
	offset += 8

	binary.LittleEndian.PutUint64(buf[offset:], m.BaseSlot)
	offset += 8

	copy(buf[offset:], m.Hash[:])
	offset += 32

	copy(buf[offset:], m.BankHash[:])
	offset += 32

	copy(buf[offset:], m.AccountsHash[:])
	offset += 32

	binary.LittleEndian.PutUint64(buf[offset:], m.AccountsCount)
	offset += 8

	binary.LittleEndian.PutUint64(buf[offset:], m.LamportsTotal)

	return buf, nil
}

// DeserializeManifestBinary deserializes a manifest from binary format.
func DeserializeManifestBinary(data []byte) (*SnapshotManifest, error) {
	if len(data) < 133 {
		return nil, fmt.Errorf("%w: data too short, need 133 bytes, got %d", ErrInvalidManifest, len(data))
	}

	m := &SnapshotManifest{}
	offset := 0

	m.Version = binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	m.SnapshotType = SnapshotType(data[offset])
	offset++

	m.Slot = binary.LittleEndian.Uint64(data[offset:])
	offset += 8

	m.BaseSlot = binary.LittleEndian.Uint64(data[offset:])
	offset += 8

	copy(m.Hash[:], data[offset:offset+32])
	offset += 32

	copy(m.BankHash[:], data[offset:offset+32])
	offset += 32

	copy(m.AccountsHash[:], data[offset:offset+32])
	offset += 32

	m.AccountsCount = binary.LittleEndian.Uint64(data[offset:])
	offset += 8

	m.LamportsTotal = binary.LittleEndian.Uint64(data[offset:])

	return m, nil
}

// SnapshotArchive provides reading access to a snapshot archive (tar.zst).
type SnapshotArchive struct {
	path     string
	file     *os.File
	decoder  *zstd.Decoder
	tarReader *tar.Reader
	manifest *SnapshotManifest
}

// OpenSnapshotArchive opens a snapshot archive for reading.
func OpenSnapshotArchive(path string) (*SnapshotArchive, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open archive: %w", err)
	}

	decoder, err := zstd.NewReader(file)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to create zstd decoder: %w", err)
	}

	tarReader := tar.NewReader(decoder)

	archive := &SnapshotArchive{
		path:      path,
		file:      file,
		decoder:   decoder,
		tarReader: tarReader,
	}

	return archive, nil
}

// Path returns the archive path.
func (a *SnapshotArchive) Path() string {
	return a.path
}

// Manifest returns the parsed manifest. Must call ReadManifest first.
func (a *SnapshotArchive) Manifest() *SnapshotManifest {
	return a.manifest
}

// ReadManifest reads and parses the manifest from the archive.
func (a *SnapshotArchive) ReadManifest() (*SnapshotManifest, error) {
	// Reset to beginning
	if err := a.Reset(); err != nil {
		return nil, err
	}

	for {
		header, err := a.tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read tar header: %w", err)
		}

		if header.Name == "manifest" || header.Name == "snapshots/status_cache" {
			if header.Name == "manifest" {
				data, err := io.ReadAll(a.tarReader)
				if err != nil {
					return nil, fmt.Errorf("failed to read manifest: %w", err)
				}

				// Try JSON first, then binary
				manifest := &SnapshotManifest{}
				if err := json.Unmarshal(data, manifest); err != nil {
					manifest, err = DeserializeManifestBinary(data)
					if err != nil {
						return nil, fmt.Errorf("failed to parse manifest: %w", err)
					}
				}

				a.manifest = manifest
				return manifest, nil
			}
		}
	}

	return nil, fmt.Errorf("%w: manifest not found in archive", ErrInvalidArchive)
}

// Next returns the next tar entry.
func (a *SnapshotArchive) Next() (*tar.Header, error) {
	return a.tarReader.Next()
}

// Read reads from the current tar entry.
func (a *SnapshotArchive) Read(p []byte) (int, error) {
	return a.tarReader.Read(p)
}

// Reset resets the archive reader to the beginning.
func (a *SnapshotArchive) Reset() error {
	a.decoder.Close()

	if _, err := a.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek: %w", err)
	}

	decoder, err := zstd.NewReader(a.file)
	if err != nil {
		return fmt.Errorf("failed to create zstd decoder: %w", err)
	}

	a.decoder = decoder
	a.tarReader = tar.NewReader(decoder)
	return nil
}

// Close closes the archive.
func (a *SnapshotArchive) Close() error {
	if a.decoder != nil {
		a.decoder.Close()
	}
	if a.file != nil {
		return a.file.Close()
	}
	return nil
}

// ExtractTo extracts the archive contents to a directory.
func (a *SnapshotArchive) ExtractTo(destDir string) error {
	if err := a.Reset(); err != nil {
		return err
	}

	for {
		header, err := a.tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		target := filepath.Join(destDir, header.Name)

		// Ensure the target is within destDir (security check)
		if !isWithinDir(destDir, target) {
			return fmt.Errorf("%w: path traversal detected: %s", ErrInvalidArchive, header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
		case tar.TypeReg:
			// Ensure parent directory exists
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("failed to create parent directory: %w", err)
			}

			file, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("failed to create file: %w", err)
			}

			if _, err := io.Copy(file, a.tarReader); err != nil {
				file.Close()
				return fmt.Errorf("failed to write file: %w", err)
			}
			file.Close()
		}
	}

	return nil
}

// isWithinDir checks if target is within the directory dir.
func isWithinDir(dir, target string) bool {
	rel, err := filepath.Rel(dir, target)
	if err != nil {
		return false
	}
	return !filepath.IsAbs(rel) && rel != ".." && len(rel) > 0 && rel[0] != '.'
}

// SnapshotInfo contains information about an available snapshot.
type SnapshotInfo struct {
	Slot     uint64
	Hash     types.Hash
	FileSize uint64
	URL      string
	Type     SnapshotType
	BaseSlot uint64 // For incremental snapshots
}
