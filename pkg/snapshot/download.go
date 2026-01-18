package snapshot

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// DownloadConfig contains configuration for snapshot downloads.
type DownloadConfig struct {
	// RPCEndpoints is a list of RPC endpoints to try for downloading.
	RPCEndpoints []string
	// MaxRetries is the maximum number of retries per endpoint.
	MaxRetries int
	// Timeout is the timeout for the entire download operation.
	Timeout time.Duration
	// ProgressCallback is called with download progress updates.
	ProgressCallback func(downloaded, total uint64)
	// PreferIncremental prefers incremental snapshots over full snapshots.
	PreferIncremental bool
	// BaseSlot is required when downloading incremental snapshots.
	BaseSlot uint64
}

// DefaultDownloadConfig returns a default download configuration.
func DefaultDownloadConfig() DownloadConfig {
	return DownloadConfig{
		RPCEndpoints: []string{
			"https://api.mainnet-beta.solana.com",
		},
		MaxRetries: 3,
		Timeout:    30 * time.Minute,
	}
}

// SnapshotDownloader handles downloading snapshots from RPC endpoints.
type SnapshotDownloader struct {
	config DownloadConfig
	client *http.Client
}

// NewSnapshotDownloader creates a new snapshot downloader.
func NewSnapshotDownloader(config DownloadConfig) *SnapshotDownloader {
	return &SnapshotDownloader{
		config: config,
		client: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

// DownloadSnapshot downloads a snapshot for the given slot to the destination directory.
func DownloadSnapshot(ctx context.Context, slot uint64, destDir string) error {
	downloader := NewSnapshotDownloader(DefaultDownloadConfig())
	return downloader.Download(ctx, slot, destDir)
}

// Download downloads a snapshot for the given slot to the destination directory.
func (d *SnapshotDownloader) Download(ctx context.Context, slot uint64, destDir string) error {
	// Find the snapshot info
	info, err := d.findSnapshot(ctx, slot)
	if err != nil {
		return fmt.Errorf("failed to find snapshot: %w", err)
	}

	// Create destination directory
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Determine filename
	filename := fmt.Sprintf("snapshot-%d-%s.tar.zst", info.Slot, info.Hash.String()[:16])
	destPath := filepath.Join(destDir, filename)

	// Download the file
	if err := d.downloadFile(ctx, info.URL, destPath); err != nil {
		return fmt.Errorf("failed to download snapshot: %w", err)
	}

	return nil
}

// FindLatestSnapshot finds the latest available snapshot from RPC endpoints.
func FindLatestSnapshot(ctx context.Context, rpcEndpoint string) (*SnapshotInfo, error) {
	downloader := NewSnapshotDownloader(DownloadConfig{
		RPCEndpoints: []string{rpcEndpoint},
		Timeout:      30 * time.Second,
	})
	return downloader.FindLatest(ctx)
}

// FindLatest finds the latest available snapshot.
func (d *SnapshotDownloader) FindLatest(ctx context.Context) (*SnapshotInfo, error) {
	var lastErr error

	for _, endpoint := range d.config.RPCEndpoints {
		info, err := d.findLatestFromEndpoint(ctx, endpoint)
		if err != nil {
			lastErr = err
			continue
		}
		return info, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("failed to find snapshot from any endpoint: %w", lastErr)
	}
	return nil, ErrSnapshotNotFound
}

// findLatestFromEndpoint queries an RPC endpoint for the latest snapshot.
func (d *SnapshotDownloader) findLatestFromEndpoint(ctx context.Context, endpoint string) (*SnapshotInfo, error) {
	// Query the RPC for snapshot info using getHighestSnapshotSlot
	req := rpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "getHighestSnapshotSlot",
		Params:  []interface{}{},
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(string(reqBody)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var rpcResp rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error: %s", rpcResp.Error.Message)
	}

	// Parse the result
	result, ok := rpcResp.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result format")
	}

	fullSlot, ok := result["full"].(float64)
	if !ok {
		return nil, fmt.Errorf("missing full slot in response")
	}

	info := &SnapshotInfo{
		Slot: uint64(fullSlot),
		Type: SnapshotTypeFull,
		URL:  buildSnapshotURL(endpoint, uint64(fullSlot)),
	}

	// Check for incremental snapshot
	if incremental, ok := result["incremental"].(float64); ok && d.config.PreferIncremental {
		info.Slot = uint64(incremental)
		info.Type = SnapshotTypeIncremental
		info.BaseSlot = uint64(fullSlot)
	}

	return info, nil
}

// findSnapshot finds a specific snapshot by slot.
func (d *SnapshotDownloader) findSnapshot(ctx context.Context, slot uint64) (*SnapshotInfo, error) {
	var lastErr error

	for _, endpoint := range d.config.RPCEndpoints {
		// First check if the exact slot is available
		info, err := d.checkSnapshotAvailable(ctx, endpoint, slot)
		if err != nil {
			lastErr = err
			continue
		}
		return info, nil
	}

	// If exact slot not found, try to find the closest available slot
	for _, endpoint := range d.config.RPCEndpoints {
		info, err := d.findClosestSnapshot(ctx, endpoint, slot)
		if err != nil {
			lastErr = err
			continue
		}
		return info, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("failed to find snapshot: %w", lastErr)
	}
	return nil, ErrSnapshotNotFound
}

// checkSnapshotAvailable checks if a snapshot for the given slot is available.
func (d *SnapshotDownloader) checkSnapshotAvailable(ctx context.Context, endpoint string, slot uint64) (*SnapshotInfo, error) {
	url := buildSnapshotURL(endpoint, slot)

	// Do a HEAD request to check availability
	httpReq, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := d.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("snapshot not available: status %d", resp.StatusCode)
	}

	var fileSize uint64
	if contentLength := resp.Header.Get("Content-Length"); contentLength != "" {
		fileSize, _ = strconv.ParseUint(contentLength, 10, 64)
	}

	return &SnapshotInfo{
		Slot:     slot,
		FileSize: fileSize,
		URL:      url,
		Type:     SnapshotTypeFull,
	}, nil
}

// findClosestSnapshot finds the closest available snapshot to the given slot.
func (d *SnapshotDownloader) findClosestSnapshot(ctx context.Context, endpoint string, targetSlot uint64) (*SnapshotInfo, error) {
	// Get list of available snapshots
	snapshots, err := d.listAvailableSnapshots(ctx, endpoint)
	if err != nil {
		return nil, err
	}

	if len(snapshots) == 0 {
		return nil, ErrSnapshotNotFound
	}

	// Sort by slot descending
	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].Slot > snapshots[j].Slot
	})

	// Find the closest slot that is <= targetSlot
	for _, info := range snapshots {
		if info.Slot <= targetSlot {
			return &info, nil
		}
	}

	// If no slot <= targetSlot, return the oldest available
	return &snapshots[len(snapshots)-1], nil
}

// listAvailableSnapshots lists available snapshots from an endpoint.
func (d *SnapshotDownloader) listAvailableSnapshots(ctx context.Context, endpoint string) ([]SnapshotInfo, error) {
	// This would typically query a snapshot index endpoint
	// For now, we just return the latest snapshot
	info, err := d.findLatestFromEndpoint(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	return []SnapshotInfo{*info}, nil
}

// downloadFile downloads a file from a URL to a local path.
func (d *SnapshotDownloader) downloadFile(ctx context.Context, url, destPath string) error {
	// Create a temporary file
	tmpPath := destPath + ".tmp"
	tmpFile, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer func() {
		tmpFile.Close()
		os.Remove(tmpPath) // Clean up on error
	}()

	// Create request
	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Download
	resp, err := d.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: status %d", resp.StatusCode)
	}

	var total uint64
	if contentLength := resp.Header.Get("Content-Length"); contentLength != "" {
		total, _ = strconv.ParseUint(contentLength, 10, 64)
	}

	// Create progress reader if callback is set
	var reader io.Reader = resp.Body
	if d.config.ProgressCallback != nil && total > 0 {
		reader = &progressReader{
			reader:   resp.Body,
			total:    total,
			callback: d.config.ProgressCallback,
		}
	}

	// Copy to file
	if _, err := io.Copy(tmpFile, reader); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	// Close temp file before rename
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	// Rename to final destination
	if err := os.Rename(tmpPath, destPath); err != nil {
		return fmt.Errorf("failed to rename file: %w", err)
	}

	return nil
}

// DownloadIncrementalSnapshots downloads an incremental snapshot and its base.
func (d *SnapshotDownloader) DownloadIncrementalSnapshots(ctx context.Context, destDir string) (fullPath, incrPath string, err error) {
	// Find the latest snapshot info
	info, err := d.FindLatest(ctx)
	if err != nil {
		return "", "", fmt.Errorf("failed to find latest snapshot: %w", err)
	}

	// Create destination directory
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return "", "", fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Download full snapshot first
	fullFilename := fmt.Sprintf("snapshot-%d-%s.tar.zst", info.BaseSlot, info.Hash.String()[:16])
	fullPath = filepath.Join(destDir, fullFilename)

	fullURL := buildSnapshotURL(d.config.RPCEndpoints[0], info.BaseSlot)
	if err := d.downloadFile(ctx, fullURL, fullPath); err != nil {
		return "", "", fmt.Errorf("failed to download full snapshot: %w", err)
	}

	// If we have an incremental snapshot, download it too
	if info.Type == SnapshotTypeIncremental && info.Slot != info.BaseSlot {
		incrFilename := fmt.Sprintf("incremental-snapshot-%d-%d-%s.tar.zst",
			info.BaseSlot, info.Slot, info.Hash.String()[:16])
		incrPath = filepath.Join(destDir, incrFilename)

		incrURL := buildIncrementalSnapshotURL(d.config.RPCEndpoints[0], info.BaseSlot, info.Slot)
		if err := d.downloadFile(ctx, incrURL, incrPath); err != nil {
			return fullPath, "", fmt.Errorf("failed to download incremental snapshot: %w", err)
		}
	}

	return fullPath, incrPath, nil
}

// buildSnapshotURL builds the URL for downloading a full snapshot.
func buildSnapshotURL(endpoint string, slot uint64) string {
	// Standard Solana snapshot URL format
	baseURL := strings.TrimSuffix(endpoint, "/")
	return fmt.Sprintf("%s/snapshot-%d.tar.zst", baseURL, slot)
}

// buildIncrementalSnapshotURL builds the URL for downloading an incremental snapshot.
func buildIncrementalSnapshotURL(endpoint string, baseSlot, slot uint64) string {
	baseURL := strings.TrimSuffix(endpoint, "/")
	return fmt.Sprintf("%s/incremental-snapshot-%d-%d.tar.zst", baseURL, baseSlot, slot)
}

// rpcRequest represents a JSON-RPC request.
type rpcRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      int           `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

// rpcResponse represents a JSON-RPC response.
type rpcResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Result  interface{} `json:"result"`
	Error   *rpcError   `json:"error"`
}

// rpcError represents a JSON-RPC error.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// progressReader wraps an io.Reader to report progress.
type progressReader struct {
	reader     io.Reader
	downloaded uint64
	total      uint64
	callback   func(downloaded, total uint64)
}

func (r *progressReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		r.downloaded += uint64(n)
		r.callback(r.downloaded, r.total)
	}
	return n, err
}

// GetSnapshotHash computes the hash of a snapshot file for verification.
func GetSnapshotHash(path string) (types.Hash, error) {
	file, err := os.Open(path)
	if err != nil {
		return types.ZeroHash, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Read in chunks and hash
	hash := types.SHA256Multi()
	buf := make([]byte, 1024*1024) // 1MB buffer

	for {
		n, err := file.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return types.ZeroHash, fmt.Errorf("failed to read file: %w", err)
		}
		hash = types.SHA256Multi(hash[:], buf[:n])
	}

	return hash, nil
}
