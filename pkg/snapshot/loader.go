package snapshot

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/fortiblox/x1-nimbus/pkg/accounts"
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// LoadResult contains the result of loading a snapshot.
type LoadResult struct {
	// Manifest is the snapshot manifest.
	Manifest *SnapshotManifest
	// AccountsLoaded is the number of accounts loaded.
	AccountsLoaded uint64
	// LamportsTotal is the total lamports loaded.
	LamportsTotal uint64
	// AccountsHash is the computed accounts hash.
	AccountsHash types.Hash
	// Verified indicates if the snapshot was verified.
	Verified bool
}

// LoadProgress represents the progress of loading a snapshot.
type LoadProgress struct {
	// Stage is the current loading stage.
	Stage string
	// AccountsProcessed is the number of accounts processed.
	AccountsProcessed uint64
	// AccountsTotal is the total number of accounts (from manifest).
	AccountsTotal uint64
	// BytesProcessed is the number of bytes processed.
	BytesProcessed uint64
	// BytesTotal is the total bytes to process.
	BytesTotal uint64
}

// ProgressCallback is called with load progress updates.
type ProgressCallback func(progress LoadProgress)

// LoadConfig contains configuration for loading a snapshot.
type LoadConfig struct {
	// VerifyHashes enables hash verification during load.
	VerifyHashes bool
	// VerifyBeforeLoad enables full verification before loading accounts.
	// This is more thorough but slower as it reads the snapshot twice.
	VerifyBeforeLoad bool
	// ProgressCallback is called with progress updates.
	ProgressCallback ProgressCallback
	// BatchSize is the number of accounts to batch before inserting.
	BatchSize int
	// NumWorkers is the number of parallel workers for loading.
	NumWorkers int
}

// DefaultLoadConfig returns a default load configuration.
func DefaultLoadConfig() LoadConfig {
	return LoadConfig{
		VerifyHashes:     true,
		VerifyBeforeLoad: false, // Disabled by default for performance
		BatchSize:        1000,
		NumWorkers:       4,
	}
}

// StrictLoadConfig returns a strict load configuration with full verification.
func StrictLoadConfig() LoadConfig {
	return LoadConfig{
		VerifyHashes:     true,
		VerifyBeforeLoad: true,
		BatchSize:        1000,
		NumWorkers:       4,
	}
}

// SnapshotLoader loads snapshots into an AccountsDB.
type SnapshotLoader struct {
	config LoadConfig
	db     accounts.AccountsDB
}

// NewSnapshotLoader creates a new snapshot loader.
func NewSnapshotLoader(db accounts.AccountsDB, config LoadConfig) *SnapshotLoader {
	return &SnapshotLoader{
		config: config,
		db:     db,
	}
}

// LoadSnapshot loads a snapshot from a path into the database.
func LoadSnapshot(path string, db accounts.AccountsDB) (*LoadResult, error) {
	loader := NewSnapshotLoader(db, DefaultLoadConfig())
	return loader.Load(path)
}

// LoadSnapshotWithConfig loads a snapshot with custom configuration.
func LoadSnapshotWithConfig(path string, db accounts.AccountsDB, config LoadConfig) (*LoadResult, error) {
	loader := NewSnapshotLoader(db, config)
	return loader.Load(path)
}

// Load loads a snapshot from a path.
func (l *SnapshotLoader) Load(path string) (*LoadResult, error) {
	// Check if path is an archive or extracted directory
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat path: %w", err)
	}

	// Verify snapshot integrity before loading if enabled
	if l.config.VerifyBeforeLoad {
		l.reportProgress("Verifying snapshot integrity", 0, 0, 0, 0)
		verifyResult, err := VerifySnapshotIntegrity(path)
		if err != nil {
			return nil, fmt.Errorf("snapshot verification failed: %w", err)
		}
		if !verifyResult.ManifestValid {
			return nil, fmt.Errorf("%w: manifest verification failed before load", ErrHashMismatch)
		}
		if !verifyResult.AccountsHashValid {
			return nil, fmt.Errorf("%w: accounts hash verification failed before load", ErrHashMismatch)
		}
		if len(verifyResult.FailedAccounts) > 0 {
			return nil, fmt.Errorf("%w: %d accounts failed hash verification before load",
				ErrHashMismatch, len(verifyResult.FailedAccounts))
		}
		l.reportProgress("Verification passed", verifyResult.AccountsCount, verifyResult.AccountsCount, 0, 0)
	}

	if info.IsDir() {
		return l.loadFromDirectory(path)
	}

	return l.loadFromArchive(path)
}

// loadFromArchive loads a snapshot from a tar.zst archive.
func (l *SnapshotLoader) loadFromArchive(archivePath string) (*LoadResult, error) {
	archive, err := OpenSnapshotArchive(archivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open archive: %w", err)
	}
	defer archive.Close()

	// Read manifest
	l.reportProgress("Reading manifest", 0, 0, 0, 0)
	manifest, err := archive.ReadManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	result := &LoadResult{
		Manifest: manifest,
	}

	// Reset archive to read accounts
	if err := archive.Reset(); err != nil {
		return nil, fmt.Errorf("failed to reset archive: %w", err)
	}

	// Process accounts from archive
	var accountsLoaded uint64
	var lamportsTotal uint64
	var accountHashes []types.Hash

	accountsChan := make(chan *AccountEntry, l.config.BatchSize)
	hashChan := make(chan types.Hash, l.config.BatchSize)
	errChan := make(chan error, 1)
	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < l.config.NumWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for entry := range accountsChan {
				if err := l.db.SetAccount(entry.StoredMeta.Pubkey, entry.Account); err != nil {
					select {
					case errChan <- err:
					default:
					}
					return
				}
				atomic.AddUint64(&accountsLoaded, 1)
				atomic.AddUint64(&lamportsTotal, uint64(entry.Account.Lamports))

				// Compute account hash if verification is enabled
				if l.config.VerifyHashes {
					hash := entry.Account.Hash(entry.StoredMeta.Pubkey)
					hashChan <- hash
				}
			}
		}()
	}

	// Hash collector goroutine
	var hashWg sync.WaitGroup
	if l.config.VerifyHashes {
		hashWg.Add(1)
		go func() {
			defer hashWg.Done()
			for hash := range hashChan {
				accountHashes = append(accountHashes, hash)
			}
		}()
	}

	// Read accounts from archive
	l.reportProgress("Loading accounts", 0, manifest.AccountsCount, 0, 0)
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			close(accountsChan)
			close(hashChan)
			return nil, fmt.Errorf("failed to read archive: %w", err)
		}

		// Check if this is an accounts file
		if !isAccountsFile(header.Name) {
			continue
		}

		// Read the entire file into memory for parsing
		data, err := io.ReadAll(archive)
		if err != nil {
			close(accountsChan)
			close(hashChan)
			return nil, fmt.Errorf("failed to read accounts file: %w", err)
		}

		// Parse accounts from the file
		reader := NewAccountsFileReaderFromBytes(data)
		for {
			entry, err := reader.ReadNext()
			if err == ErrEndOfFile {
				break
			}
			if err != nil {
				close(accountsChan)
				close(hashChan)
				return nil, fmt.Errorf("failed to read account: %w", err)
			}

			// Check for errors from workers
			select {
			case err := <-errChan:
				close(accountsChan)
				close(hashChan)
				return nil, fmt.Errorf("worker error: %w", err)
			default:
			}

			accountsChan <- entry

			// Report progress
			current := atomic.LoadUint64(&accountsLoaded)
			if current%10000 == 0 {
				l.reportProgress("Loading accounts", current, manifest.AccountsCount, 0, 0)
			}
		}
	}

	close(accountsChan)
	wg.Wait()
	close(hashChan)
	hashWg.Wait()

	// Check for any final errors
	select {
	case err := <-errChan:
		return nil, fmt.Errorf("worker error: %w", err)
	default:
	}

	result.AccountsLoaded = accountsLoaded
	result.LamportsTotal = lamportsTotal

	// Verify accounts hash if enabled
	if l.config.VerifyHashes && len(accountHashes) > 0 {
		l.reportProgress("Verifying accounts hash", 0, 0, 0, 0)
		computedHash := computeAccountsHash(accountHashes)
		result.AccountsHash = computedHash

		if computedHash != manifest.AccountsHash {
			return result, fmt.Errorf("%w: accounts hash mismatch", ErrHashMismatch)
		}
		result.Verified = true
	}

	l.reportProgress("Complete", accountsLoaded, accountsLoaded, 0, 0)
	return result, nil
}

// loadFromDirectory loads a snapshot from an extracted directory.
func (l *SnapshotLoader) loadFromDirectory(dirPath string) (*LoadResult, error) {
	// Read manifest
	l.reportProgress("Reading manifest", 0, 0, 0, 0)
	manifestPath := filepath.Join(dirPath, "manifest")
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	manifest, err := DeserializeManifestBinary(manifestData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}

	result := &LoadResult{
		Manifest: manifest,
	}

	// Find accounts directory
	accountsDir := filepath.Join(dirPath, "accounts")
	if _, err := os.Stat(accountsDir); os.IsNotExist(err) {
		// Try alternative path
		accountsDir = filepath.Join(dirPath, "snapshots", fmt.Sprintf("%d", manifest.Slot), "accounts")
	}

	// List account files
	accountFiles, err := filepath.Glob(filepath.Join(accountsDir, "*.*"))
	if err != nil {
		return nil, fmt.Errorf("failed to list account files: %w", err)
	}

	var accountsLoaded uint64
	var lamportsTotal uint64
	var accountHashes []types.Hash
	var hashMu sync.Mutex

	// Process account files with parallel workers
	filesChan := make(chan string, len(accountFiles))
	errChan := make(chan error, 1)
	var wg sync.WaitGroup

	for i := 0; i < l.config.NumWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for filePath := range filesChan {
				if err := l.loadAccountFile(filePath, &accountsLoaded, &lamportsTotal, &accountHashes, &hashMu); err != nil {
					select {
					case errChan <- err:
					default:
					}
					return
				}
			}
		}()
	}

	// Send files to workers
	l.reportProgress("Loading accounts", 0, manifest.AccountsCount, 0, 0)
	for _, filePath := range accountFiles {
		filesChan <- filePath
	}
	close(filesChan)

	wg.Wait()

	// Check for errors
	select {
	case err := <-errChan:
		return nil, fmt.Errorf("failed to load account file: %w", err)
	default:
	}

	result.AccountsLoaded = accountsLoaded
	result.LamportsTotal = lamportsTotal

	// Verify accounts hash if enabled
	if l.config.VerifyHashes && len(accountHashes) > 0 {
		l.reportProgress("Verifying accounts hash", 0, 0, 0, 0)
		computedHash := computeAccountsHash(accountHashes)
		result.AccountsHash = computedHash

		if computedHash != manifest.AccountsHash {
			return result, fmt.Errorf("%w: accounts hash mismatch", ErrHashMismatch)
		}
		result.Verified = true
	}

	l.reportProgress("Complete", accountsLoaded, accountsLoaded, 0, 0)
	return result, nil
}

// loadAccountFile loads accounts from a single AppendVec file.
func (l *SnapshotLoader) loadAccountFile(filePath string, accountsLoaded, lamportsTotal *uint64, accountHashes *[]types.Hash, hashMu *sync.Mutex) error {
	reader, err := NewAccountsFileReader(filePath)
	if err != nil {
		return err
	}
	defer reader.Close()

	for {
		entry, err := reader.ReadNext()
		if err == ErrEndOfFile {
			break
		}
		if err != nil {
			return err
		}

		if err := l.db.SetAccount(entry.StoredMeta.Pubkey, entry.Account); err != nil {
			return err
		}

		atomic.AddUint64(accountsLoaded, 1)
		atomic.AddUint64(lamportsTotal, uint64(entry.Account.Lamports))

		// Compute account hash if verification is enabled
		if l.config.VerifyHashes {
			hash := entry.Account.Hash(entry.StoredMeta.Pubkey)
			hashMu.Lock()
			*accountHashes = append(*accountHashes, hash)
			hashMu.Unlock()
		}
	}

	return nil
}

// reportProgress reports loading progress if a callback is set.
func (l *SnapshotLoader) reportProgress(stage string, accountsProcessed, accountsTotal, bytesProcessed, bytesTotal uint64) {
	if l.config.ProgressCallback != nil {
		l.config.ProgressCallback(LoadProgress{
			Stage:             stage,
			AccountsProcessed: accountsProcessed,
			AccountsTotal:     accountsTotal,
			BytesProcessed:    bytesProcessed,
			BytesTotal:        bytesTotal,
		})
	}
}

// isAccountsFile checks if a tar entry is an accounts file.
func isAccountsFile(name string) bool {
	// Accounts files are in the accounts/ directory with format: slot.id
	if !strings.Contains(name, "accounts/") {
		return false
	}
	base := filepath.Base(name)
	// Check for slot.id format
	if len(base) > 0 && base[0] >= '0' && base[0] <= '9' {
		return strings.Contains(base, ".")
	}
	return false
}

// computeAccountsHash computes the 16-ary merkle root of account hashes.
// This matches the Solana accounts hash computation.
func computeAccountsHash(hashes []types.Hash) types.Hash {
	if len(hashes) == 0 {
		return types.ZeroHash
	}
	if len(hashes) == 1 {
		return hashes[0]
	}

	const arity = 16

	// Build 16-ary merkle tree
	for len(hashes) > 1 {
		numParents := (len(hashes) + arity - 1) / arity
		parents := make([]types.Hash, numParents)

		for i := 0; i < numParents; i++ {
			start := i * arity
			end := start + arity
			if end > len(hashes) {
				end = len(hashes)
			}
			parents[i] = hashMerkleChildren(hashes[start:end])
		}

		hashes = parents
	}

	return hashes[0]
}

// hashMerkleChildren hashes a group of up to 16 child nodes.
func hashMerkleChildren(children []types.Hash) types.Hash {
	if len(children) == 0 {
		return types.ZeroHash
	}
	if len(children) == 1 {
		return children[0]
	}

	// Concatenate all child hashes and compute SHA256
	data := make([]byte, 0, len(children)*32)
	for _, child := range children {
		data = append(data, child[:]...)
	}

	return types.SHA256(data)
}

// LoadIncrementalSnapshot loads an incremental snapshot on top of a base snapshot.
func LoadIncrementalSnapshot(basePath, incrementalPath string, db accounts.AccountsDB) (*LoadResult, error) {
	loader := NewSnapshotLoader(db, DefaultLoadConfig())
	return loader.LoadIncremental(basePath, incrementalPath)
}

// LoadIncremental loads an incremental snapshot on top of a base snapshot.
func (l *SnapshotLoader) LoadIncremental(basePath, incrementalPath string) (*LoadResult, error) {
	// First load the base snapshot
	l.reportProgress("Loading base snapshot", 0, 0, 0, 0)
	baseResult, err := l.Load(basePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load base snapshot: %w", err)
	}

	// Then load the incremental snapshot
	l.reportProgress("Loading incremental snapshot", 0, 0, 0, 0)
	incrResult, err := l.Load(incrementalPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load incremental snapshot: %w", err)
	}

	// Combine results
	return &LoadResult{
		Manifest:       incrResult.Manifest,
		AccountsLoaded: baseResult.AccountsLoaded + incrResult.AccountsLoaded,
		LamportsTotal:  incrResult.LamportsTotal, // Use incremental's total as it's the final state
		AccountsHash:   incrResult.AccountsHash,
		Verified:       baseResult.Verified && incrResult.Verified,
	}, nil
}
