package snapshot

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// VerifyResult contains the result of snapshot verification.
type VerifyResult struct {
	// ManifestValid indicates if the manifest is valid.
	ManifestValid bool
	// AccountsHashValid indicates if the accounts hash matches.
	AccountsHashValid bool
	// BankHashValid indicates if the bank hash matches.
	BankHashValid bool
	// AccountsCount is the number of accounts verified.
	AccountsCount uint64
	// LamportsTotal is the total lamports verified.
	LamportsTotal uint64
	// ComputedAccountsHash is the computed accounts hash.
	ComputedAccountsHash types.Hash
	// ComputedBankHash is the computed bank hash.
	ComputedBankHash types.Hash
	// FailedAccounts contains pubkeys of accounts that failed verification.
	FailedAccounts []types.Pubkey
}

// VerifyConfig contains configuration for verification.
type VerifyConfig struct {
	// VerifyAccountsHash enables verification of the accounts hash.
	VerifyAccountsHash bool
	// VerifyBankHash enables verification of the bank hash.
	VerifyBankHash bool
	// VerifyIndividualAccounts enables verification of each account's hash.
	VerifyIndividualAccounts bool
	// ProgressCallback is called with verification progress.
	ProgressCallback ProgressCallback
}

// DefaultVerifyConfig returns a default verification configuration.
func DefaultVerifyConfig() VerifyConfig {
	return VerifyConfig{
		VerifyAccountsHash:       true,
		VerifyBankHash:           true,
		VerifyIndividualAccounts: false, // Disabled by default for performance
	}
}

// VerifySnapshot verifies the integrity of a snapshot.
func VerifySnapshot(path string) error {
	result, err := VerifySnapshotWithResult(path)
	if err != nil {
		return err
	}

	if !result.ManifestValid {
		return fmt.Errorf("%w: manifest verification failed", ErrHashMismatch)
	}
	if !result.AccountsHashValid {
		return fmt.Errorf("%w: accounts hash verification failed", ErrHashMismatch)
	}
	if !result.BankHashValid {
		return fmt.Errorf("%w: bank hash verification failed", ErrHashMismatch)
	}

	return nil
}

// VerifySnapshotWithResult verifies a snapshot and returns detailed results.
func VerifySnapshotWithResult(path string) (*VerifyResult, error) {
	return VerifySnapshotWithConfig(path, DefaultVerifyConfig())
}

// VerifySnapshotWithConfig verifies a snapshot with custom configuration.
func VerifySnapshotWithConfig(path string, config VerifyConfig) (*VerifyResult, error) {
	result := &VerifyResult{}

	// Check if path is an archive or extracted directory
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat path: %w", err)
	}

	if info.IsDir() {
		return verifyDirectory(path, config, result)
	}

	return verifyArchive(path, config, result)
}

// VerifySnapshotIntegrity performs a full verification of a snapshot.
// This is the comprehensive verification function that checks:
// - Manifest integrity
// - Individual account hashes
// - Accounts hash (16-ary Merkle tree)
// - Bank hash
func VerifySnapshotIntegrity(snapshotPath string) (*VerifyResult, error) {
	config := VerifyConfig{
		VerifyAccountsHash:       true,
		VerifyBankHash:           true,
		VerifyIndividualAccounts: true,
	}
	return VerifySnapshotWithConfig(snapshotPath, config)
}

// verifyArchive verifies a snapshot archive.
func verifyArchive(archivePath string, config VerifyConfig, result *VerifyResult) (*VerifyResult, error) {
	archive, err := OpenSnapshotArchive(archivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open archive: %w", err)
	}
	defer archive.Close()

	// Read and verify manifest
	manifest, err := archive.ReadManifest()
	if err != nil {
		return result, fmt.Errorf("failed to read manifest: %w", err)
	}
	result.ManifestValid = true

	if config.VerifyAccountsHash || config.VerifyBankHash {
		// Reset archive to read accounts
		if err := archive.Reset(); err != nil {
			return result, fmt.Errorf("failed to reset archive: %w", err)
		}

		// Collect all accounts with their hashes for verification
		var accountRefs []accountHashRef
		var accountsCount uint64
		var lamportsTotal uint64

		for {
			header, err := archive.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return result, fmt.Errorf("failed to read archive: %w", err)
			}

			if !isAccountsFile(header.Name) {
				continue
			}

			// Read and parse accounts file
			data, err := io.ReadAll(archive)
			if err != nil {
				return result, fmt.Errorf("failed to read accounts file: %w", err)
			}

			reader := NewAccountsFileReaderFromBytes(data)
			for {
				entry, err := reader.ReadNext()
				if err == ErrEndOfFile {
					break
				}
				if err != nil {
					return result, fmt.Errorf("failed to read account: %w", err)
				}

				accountsCount++
				lamportsTotal += uint64(entry.Account.Lamports)

				// Compute account hash
				hash := ComputeAccountHash(entry.Account, entry.StoredMeta.Pubkey)

				// Verify individual account if enabled
				if config.VerifyIndividualAccounts {
					expectedHash := entry.Account.Hash(entry.StoredMeta.Pubkey)
					if hash != expectedHash {
						result.FailedAccounts = append(result.FailedAccounts, entry.StoredMeta.Pubkey)
					}
				}

				accountRefs = append(accountRefs, accountHashRef{
					pubkey: entry.StoredMeta.Pubkey,
					hash:   hash,
				})
			}
		}

		result.AccountsCount = accountsCount
		result.LamportsTotal = lamportsTotal

		// Compute and verify accounts hash using 16-ary Merkle tree
		if config.VerifyAccountsHash {
			computedHash := computeAccountsHashMerkle16(accountRefs)
			result.ComputedAccountsHash = computedHash
			result.AccountsHashValid = computedHash == manifest.AccountsHash
		}

		// Compute and verify bank hash
		if config.VerifyBankHash {
			computedBankHash := computeBankHashFromAccounts(accountRefs, manifest)
			result.ComputedBankHash = computedBankHash
			result.BankHashValid = computedBankHash == manifest.BankHash
		}
	}

	return result, nil
}

// verifyDirectory verifies an extracted snapshot directory.
func verifyDirectory(dirPath string, config VerifyConfig, result *VerifyResult) (*VerifyResult, error) {
	// Read manifest
	manifestPath := filepath.Join(dirPath, "manifest")
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return result, fmt.Errorf("failed to read manifest: %w", err)
	}

	manifest, err := DeserializeManifestBinary(manifestData)
	if err != nil {
		return result, fmt.Errorf("failed to parse manifest: %w", err)
	}
	result.ManifestValid = true

	if config.VerifyAccountsHash || config.VerifyBankHash {
		// Find accounts directory
		accountsDir := filepath.Join(dirPath, "accounts")
		if _, err := os.Stat(accountsDir); os.IsNotExist(err) {
			accountsDir = filepath.Join(dirPath, "snapshots", fmt.Sprintf("%d", manifest.Slot), "accounts")
		}

		// Collect all accounts with their hashes
		var accountRefs []accountHashRef
		var accountsCount uint64
		var lamportsTotal uint64

		// List and process account files
		accountFiles, err := filepath.Glob(filepath.Join(accountsDir, "*.*"))
		if err != nil {
			return result, fmt.Errorf("failed to list account files: %w", err)
		}

		for _, filePath := range accountFiles {
			reader, err := NewAccountsFileReader(filePath)
			if err != nil {
				return result, fmt.Errorf("failed to open account file: %w", err)
			}

			for {
				entry, err := reader.ReadNext()
				if err == ErrEndOfFile {
					break
				}
				if err != nil {
					reader.Close()
					return result, fmt.Errorf("failed to read account: %w", err)
				}

				accountsCount++
				lamportsTotal += uint64(entry.Account.Lamports)

				// Compute account hash
				hash := ComputeAccountHash(entry.Account, entry.StoredMeta.Pubkey)

				// Verify individual account if enabled
				if config.VerifyIndividualAccounts {
					expectedHash := entry.Account.Hash(entry.StoredMeta.Pubkey)
					if hash != expectedHash {
						result.FailedAccounts = append(result.FailedAccounts, entry.StoredMeta.Pubkey)
					}
				}

				accountRefs = append(accountRefs, accountHashRef{
					pubkey: entry.StoredMeta.Pubkey,
					hash:   hash,
				})
			}
			reader.Close()
		}

		result.AccountsCount = accountsCount
		result.LamportsTotal = lamportsTotal

		// Compute and verify accounts hash using 16-ary Merkle tree
		if config.VerifyAccountsHash {
			computedHash := computeAccountsHashMerkle16(accountRefs)
			result.ComputedAccountsHash = computedHash
			result.AccountsHashValid = computedHash == manifest.AccountsHash
		}

		// Compute and verify bank hash
		if config.VerifyBankHash {
			computedBankHash := computeBankHashFromAccounts(accountRefs, manifest)
			result.ComputedBankHash = computedBankHash
			result.BankHashValid = computedBankHash == manifest.BankHash
		}
	}

	return result, nil
}

// accountHashRef holds a pubkey and its computed hash for sorting.
type accountHashRef struct {
	pubkey types.Pubkey
	hash   types.Hash
}

// VerifyManifestHash verifies the hash of the manifest data against an expected hash.
func VerifyManifestHash(manifest *SnapshotManifest, expectedHash types.Hash) error {
	// Serialize the manifest to binary
	data, err := manifest.SerializeBinary()
	if err != nil {
		return fmt.Errorf("failed to serialize manifest: %w", err)
	}

	computedHash := types.SHA256(data)
	if computedHash != expectedHash {
		return fmt.Errorf("%w: manifest hash mismatch, expected %s, got %s",
			ErrHashMismatch, expectedHash.String(), computedHash.String())
	}

	return nil
}

// VerifyManifestFileHash verifies the hash of a manifest file on disk.
func VerifyManifestFileHash(manifestPath string, expectedHash types.Hash) error {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to read manifest: %w", err)
	}

	computedHash := types.SHA256(data)
	if computedHash != expectedHash {
		return fmt.Errorf("%w: manifest hash mismatch, expected %s, got %s",
			ErrHashMismatch, expectedHash.String(), computedHash.String())
	}

	return nil
}

// ComputeAccountHash computes the hash of an account.
// Format: SHA256(lamports || rent_epoch || data || executable || owner || pubkey)
// All values are little-endian encoded.
func ComputeAccountHash(account *types.Account, pubkey types.Pubkey) types.Hash {
	h := sha256.New()

	// Write lamports (8 bytes, little-endian)
	var lamportsBuf [8]byte
	binary.LittleEndian.PutUint64(lamportsBuf[:], uint64(account.Lamports))
	h.Write(lamportsBuf[:])

	// Write rent epoch (8 bytes, little-endian)
	var rentEpochBuf [8]byte
	binary.LittleEndian.PutUint64(rentEpochBuf[:], uint64(account.RentEpoch))
	h.Write(rentEpochBuf[:])

	// Write data
	h.Write(account.Data)

	// Write executable (1 byte)
	if account.Executable {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}

	// Write owner (32 bytes)
	h.Write(account.Owner[:])

	// Write pubkey (32 bytes)
	h.Write(pubkey[:])

	var result types.Hash
	copy(result[:], h.Sum(nil))
	return result
}

// VerifyAccountHash verifies the hash of a single account matches the expected hash.
func VerifyAccountHash(account *types.Account, pubkey types.Pubkey, expectedHash types.Hash) error {
	computedHash := ComputeAccountHash(account, pubkey)
	if computedHash != expectedHash {
		return fmt.Errorf("%w: account hash mismatch for %s, expected %s, got %s",
			ErrHashMismatch, pubkey.String(), expectedHash.String(), computedHash.String())
	}
	return nil
}

// VerifyBankHash verifies the bank hash computed from all accounts matches the expected hash.
// The bank hash is computed as a 16-ary Merkle tree of sorted account hashes.
func VerifyBankHash(accounts []types.AccountRef, expectedBankHash types.Hash) error {
	// Convert to accountHashRef for internal processing
	refs := make([]accountHashRef, len(accounts))
	for i, acc := range accounts {
		refs[i] = accountHashRef{
			pubkey: acc.Pubkey,
			hash:   ComputeAccountHash(acc.Account, acc.Pubkey),
		}
	}

	computedHash := computeAccountsHashMerkle16(refs)
	if computedHash != expectedBankHash {
		return fmt.Errorf("%w: bank hash mismatch, expected %s, got %s",
			ErrHashMismatch, expectedBankHash.String(), computedHash.String())
	}
	return nil
}

// computeAccountsHashMerkle16 computes the 16-ary Merkle tree hash of account hashes.
// Accounts are sorted by pubkey before computing.
func computeAccountsHashMerkle16(accountRefs []accountHashRef) types.Hash {
	if len(accountRefs) == 0 {
		return types.ZeroHash
	}

	// Sort by pubkey
	sort.Slice(accountRefs, func(i, j int) bool {
		return bytes.Compare(accountRefs[i].pubkey[:], accountRefs[j].pubkey[:]) < 0
	})

	// Extract just the hashes in sorted order
	hashes := make([]types.Hash, len(accountRefs))
	for i, ref := range accountRefs {
		hashes[i] = ref.hash
	}

	// Build 16-ary Merkle tree
	return computeMerkle16Root(hashes)
}

// computeMerkle16Root computes the root of a 16-ary Merkle tree.
func computeMerkle16Root(hashes []types.Hash) types.Hash {
	if len(hashes) == 0 {
		return types.ZeroHash
	}
	if len(hashes) == 1 {
		return hashes[0]
	}

	const arity = 16

	// Process level by level until we have a single root
	for len(hashes) > 1 {
		numParents := (len(hashes) + arity - 1) / arity
		parents := make([]types.Hash, numParents)

		for i := 0; i < numParents; i++ {
			start := i * arity
			end := start + arity
			if end > len(hashes) {
				end = len(hashes)
			}
			parents[i] = hashMerkle16Children(hashes[start:end])
		}

		hashes = parents
	}

	return hashes[0]
}

// hashMerkle16Children hashes a group of up to 16 child nodes.
func hashMerkle16Children(children []types.Hash) types.Hash {
	if len(children) == 0 {
		return types.ZeroHash
	}
	if len(children) == 1 {
		return children[0]
	}

	// Concatenate all child hashes and compute SHA256
	h := sha256.New()
	for _, child := range children {
		h.Write(child[:])
	}

	var result types.Hash
	copy(result[:], h.Sum(nil))
	return result
}

// computeBankHashFromAccounts computes the bank hash from account hashes and manifest data.
// The bank hash incorporates the accounts hash along with other bank state.
func computeBankHashFromAccounts(accountRefs []accountHashRef, manifest *SnapshotManifest) types.Hash {
	// Compute accounts hash first
	accountsHash := computeAccountsHashMerkle16(accountRefs)

	// Bank hash = SHA256(accounts_hash || slot || parent_bank_hash)
	// For snapshots, we use a simplified version based on accounts hash
	// The full bank hash would require additional state (parent hash, etc.)
	h := sha256.New()
	h.Write(accountsHash[:])

	// Write slot
	var slotBuf [8]byte
	binary.LittleEndian.PutUint64(slotBuf[:], manifest.Slot)
	h.Write(slotBuf[:])

	// Write accounts count
	var countBuf [8]byte
	binary.LittleEndian.PutUint64(countBuf[:], manifest.AccountsCount)
	h.Write(countBuf[:])

	// Write total lamports
	var lamportsBuf [8]byte
	binary.LittleEndian.PutUint64(lamportsBuf[:], manifest.LamportsTotal)
	h.Write(lamportsBuf[:])

	var result types.Hash
	copy(result[:], h.Sum(nil))
	return result
}

// ComputeSnapshotHash computes the overall snapshot hash for verification.
func ComputeSnapshotHash(manifest *SnapshotManifest) types.Hash {
	// Serialize manifest to binary
	data, err := manifest.SerializeBinary()
	if err != nil {
		return types.ZeroHash
	}
	return types.SHA256(data)
}

// VerifyFileIntegrity verifies the integrity of a file using its hash.
func VerifyFileIntegrity(filePath string, expectedHash types.Hash) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	var computedHash types.Hash
	copy(computedHash[:], hasher.Sum(nil))

	if computedHash != expectedHash {
		return fmt.Errorf("%w: file hash mismatch, expected %s, got %s",
			ErrHashMismatch, expectedHash.String(), computedHash.String())
	}

	return nil
}

// QuickVerify performs a quick verification by checking only the manifest.
func QuickVerify(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat path: %w", err)
	}

	if info.IsDir() {
		manifestPath := filepath.Join(path, "manifest")
		if _, err := os.Stat(manifestPath); err != nil {
			return fmt.Errorf("manifest not found: %w", err)
		}

		data, err := os.ReadFile(manifestPath)
		if err != nil {
			return fmt.Errorf("failed to read manifest: %w", err)
		}

		_, err = DeserializeManifestBinary(data)
		if err != nil {
			return fmt.Errorf("failed to parse manifest: %w", err)
		}

		return nil
	}

	archive, err := OpenSnapshotArchive(path)
	if err != nil {
		return fmt.Errorf("failed to open archive: %w", err)
	}
	defer archive.Close()

	_, err = archive.ReadManifest()
	if err != nil {
		return fmt.Errorf("failed to read manifest: %w", err)
	}

	return nil
}

// VerifyIncrementalChain verifies that an incremental snapshot properly builds on a base.
func VerifyIncrementalChain(basePath, incrementalPath string) error {
	// Verify base snapshot
	baseArchive, err := OpenSnapshotArchive(basePath)
	if err != nil {
		return fmt.Errorf("failed to open base archive: %w", err)
	}
	defer baseArchive.Close()

	baseManifest, err := baseArchive.ReadManifest()
	if err != nil {
		return fmt.Errorf("failed to read base manifest: %w", err)
	}

	// Verify incremental snapshot
	incrArchive, err := OpenSnapshotArchive(incrementalPath)
	if err != nil {
		return fmt.Errorf("failed to open incremental archive: %w", err)
	}
	defer incrArchive.Close()

	incrManifest, err := incrArchive.ReadManifest()
	if err != nil {
		return fmt.Errorf("failed to read incremental manifest: %w", err)
	}

	// Verify chain
	if incrManifest.BaseSlot != baseManifest.Slot {
		return fmt.Errorf("incremental snapshot base slot %d does not match base snapshot slot %d",
			incrManifest.BaseSlot, baseManifest.Slot)
	}

	if incrManifest.Slot <= baseManifest.Slot {
		return fmt.Errorf("incremental snapshot slot %d must be greater than base slot %d",
			incrManifest.Slot, baseManifest.Slot)
	}

	return nil
}

// VerifyAccountEntry verifies a single account entry from an AppendVec file.
func VerifyAccountEntry(entry *AccountEntry) error {
	computedHash := ComputeAccountHash(entry.Account, entry.StoredMeta.Pubkey)
	expectedHash := entry.Account.Hash(entry.StoredMeta.Pubkey)

	if computedHash != expectedHash {
		return fmt.Errorf("%w: account entry hash mismatch for %s",
			ErrHashMismatch, entry.StoredMeta.Pubkey.String())
	}
	return nil
}

// ComputeAccountsHash computes the Merkle root of all account hashes.
// This is exposed for external use when the caller already has account data.
func ComputeAccountsHash(accounts []types.AccountRef) types.Hash {
	if len(accounts) == 0 {
		return types.ZeroHash
	}

	refs := make([]accountHashRef, len(accounts))
	for i, acc := range accounts {
		refs[i] = accountHashRef{
			pubkey: acc.Pubkey,
			hash:   ComputeAccountHash(acc.Account, acc.Pubkey),
		}
	}

	return computeAccountsHashMerkle16(refs)
}
