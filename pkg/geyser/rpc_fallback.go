package geyser

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// RPCClient provides JSON-RPC access to Solana nodes as a fallback when Geyser is unavailable.
type RPCClient struct {
	endpoint   string
	httpClient *http.Client
	requestID  atomic.Uint64
	mu         sync.RWMutex
}

// NewRPCClient creates a new RPC client.
func NewRPCClient(endpoint string) *RPCClient {
	return &RPCClient{
		endpoint: endpoint,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// NewRPCClientWithTimeout creates a new RPC client with a custom timeout.
func NewRPCClientWithTimeout(endpoint string, timeout time.Duration) *RPCClient {
	return &RPCClient{
		endpoint: endpoint,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// rpcRequest represents a JSON-RPC request.
type rpcRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      uint64        `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params,omitempty"`
}

// rpcResponse represents a JSON-RPC response.
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      uint64          `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// rpcError represents a JSON-RPC error.
type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Error implements the error interface.
func (e *rpcError) Error() string {
	return fmt.Sprintf("RPC error %d: %s", e.Code, e.Message)
}

// call makes a JSON-RPC call.
func (c *RPCClient) call(ctx context.Context, method string, params []interface{}) (json.RawMessage, error) {
	reqID := c.requestID.Add(1)

	req := rpcRequest{
		JSONRPC: "2.0",
		ID:      reqID,
		Method:  method,
		Params:  params,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("http status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var rpcResp rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if rpcResp.Error != nil {
		return nil, rpcResp.Error
	}

	return rpcResp.Result, nil
}

// GetSlot returns the current slot.
func (c *RPCClient) GetSlot(ctx context.Context) (uint64, error) {
	result, err := c.call(ctx, "getSlot", []interface{}{
		map[string]string{"commitment": "confirmed"},
	})
	if err != nil {
		return 0, err
	}

	var slot uint64
	if err := json.Unmarshal(result, &slot); err != nil {
		return 0, fmt.Errorf("unmarshal slot: %w", err)
	}

	return slot, nil
}

// GetSlotWithCommitment returns the current slot at a specific commitment level.
func (c *RPCClient) GetSlotWithCommitment(ctx context.Context, commitment string) (uint64, error) {
	result, err := c.call(ctx, "getSlot", []interface{}{
		map[string]string{"commitment": commitment},
	})
	if err != nil {
		return 0, err
	}

	var slot uint64
	if err := json.Unmarshal(result, &slot); err != nil {
		return 0, fmt.Errorf("unmarshal slot: %w", err)
	}

	return slot, nil
}

// blockResponse represents the getBlock response.
type blockResponse struct {
	Blockhash         string               `json:"blockhash"`
	PreviousBlockhash string               `json:"previousBlockhash"`
	ParentSlot        uint64               `json:"parentSlot"`
	BlockTime         *int64               `json:"blockTime"`
	BlockHeight       *uint64              `json:"blockHeight"`
	Transactions      []transactionWrapper `json:"transactions"`
}

// transactionWrapper wraps a transaction in the RPC response.
type transactionWrapper struct {
	Transaction []interface{} `json:"transaction"` // [data, encoding] or object
	Meta        *txMeta       `json:"meta"`
}

// txMeta contains transaction metadata.
type txMeta struct {
	Err               interface{} `json:"err"`
	Fee               uint64      `json:"fee"`
	PreBalances       []uint64    `json:"preBalances"`
	PostBalances      []uint64    `json:"postBalances"`
	LogMessages       []string    `json:"logMessages"`
	ComputeUnitsUsed  *uint64     `json:"computeUnitsConsumed"`
}

// GetBlock returns a block by slot.
func (c *RPCClient) GetBlock(ctx context.Context, slot uint64) (*types.Block, error) {
	result, err := c.call(ctx, "getBlock", []interface{}{
		slot,
		map[string]interface{}{
			"encoding":                       "base64",
			"transactionDetails":             "full",
			"rewards":                        false,
			"maxSupportedTransactionVersion": 0,
		},
	})
	if err != nil {
		return nil, err
	}

	// Handle null result (slot skipped)
	if string(result) == "null" {
		return nil, &SlotSkippedError{Slot: slot}
	}

	var blockResp blockResponse
	if err := json.Unmarshal(result, &blockResp); err != nil {
		return nil, fmt.Errorf("unmarshal block: %w", err)
	}

	// Parse blockhash
	blockhash, err := types.HashFromBase58(blockResp.Blockhash)
	if err != nil {
		return nil, fmt.Errorf("parse blockhash: %w", err)
	}

	// Parse previous blockhash
	prevBlockhash, err := types.HashFromBase58(blockResp.PreviousBlockhash)
	if err != nil {
		return nil, fmt.Errorf("parse previous blockhash: %w", err)
	}

	// Parse transactions
	var transactions []types.Transaction
	for i, txWrapper := range blockResp.Transactions {
		if len(txWrapper.Transaction) < 1 {
			continue
		}

		// Get base64-encoded transaction data
		txDataStr, ok := txWrapper.Transaction[0].(string)
		if !ok {
			continue
		}

		txData, err := base64.StdEncoding.DecodeString(txDataStr)
		if err != nil {
			return nil, fmt.Errorf("decode transaction %d: %w", i, err)
		}

		tx, err := types.DeserializeTransaction(txData)
		if err != nil {
			// Skip transactions we can't parse (e.g., v0 with lookup tables)
			continue
		}

		transactions = append(transactions, *tx)
	}

	// Create a single entry with all transactions
	// Real blocks have multiple entries, but RPC doesn't expose that granularity
	entry := types.Entry{
		NumHashes:    1, // Unknown from RPC
		Hash:         blockhash,
		Transactions: transactions,
	}

	return &types.Block{
		Slot:              types.Slot(slot),
		ParentSlot:        types.Slot(blockResp.ParentSlot),
		Blockhash:         blockhash,
		PreviousBlockhash: prevBlockhash,
		Entries:           []types.Entry{entry},
		BlockTime:         blockResp.BlockTime,
		BlockHeight:       blockResp.BlockHeight,
	}, nil
}

// SlotSkippedError indicates a slot was skipped (no block produced).
type SlotSkippedError struct {
	Slot uint64
}

// Error implements the error interface.
func (e *SlotSkippedError) Error() string {
	return fmt.Sprintf("slot %d was skipped", e.Slot)
}

// GetBlockHeight returns the current block height.
func (c *RPCClient) GetBlockHeight(ctx context.Context) (uint64, error) {
	result, err := c.call(ctx, "getBlockHeight", []interface{}{
		map[string]string{"commitment": "confirmed"},
	})
	if err != nil {
		return 0, err
	}

	var height uint64
	if err := json.Unmarshal(result, &height); err != nil {
		return 0, fmt.Errorf("unmarshal block height: %w", err)
	}

	return height, nil
}

// GetLatestBlockhash returns the latest blockhash.
func (c *RPCClient) GetLatestBlockhash(ctx context.Context) (types.Hash, uint64, error) {
	result, err := c.call(ctx, "getLatestBlockhash", []interface{}{
		map[string]string{"commitment": "confirmed"},
	})
	if err != nil {
		return types.ZeroHash, 0, err
	}

	var resp struct {
		Value struct {
			Blockhash            string `json:"blockhash"`
			LastValidBlockHeight uint64 `json:"lastValidBlockHeight"`
		} `json:"value"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		return types.ZeroHash, 0, fmt.Errorf("unmarshal blockhash response: %w", err)
	}

	hash, err := types.HashFromBase58(resp.Value.Blockhash)
	if err != nil {
		return types.ZeroHash, 0, fmt.Errorf("parse blockhash: %w", err)
	}

	return hash, resp.Value.LastValidBlockHeight, nil
}

// accountInfoResponse represents the getAccountInfo response.
type accountInfoResponse struct {
	Value *struct {
		Data       []string `json:"data"` // [data, encoding]
		Executable bool     `json:"executable"`
		Lamports   uint64   `json:"lamports"`
		Owner      string   `json:"owner"`
		RentEpoch  uint64   `json:"rentEpoch"`
	} `json:"value"`
}

// GetAccountInfo returns account information.
func (c *RPCClient) GetAccountInfo(ctx context.Context, pubkey types.Pubkey) (*types.Account, error) {
	result, err := c.call(ctx, "getAccountInfo", []interface{}{
		pubkey.String(),
		map[string]interface{}{
			"encoding":   "base64",
			"commitment": "confirmed",
		},
	})
	if err != nil {
		return nil, err
	}

	var resp accountInfoResponse
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal account info: %w", err)
	}

	if resp.Value == nil {
		return nil, nil // Account doesn't exist
	}

	// Parse owner
	owner, err := types.PubkeyFromBase58(resp.Value.Owner)
	if err != nil {
		return nil, fmt.Errorf("parse owner: %w", err)
	}

	// Parse data
	var data []byte
	if len(resp.Value.Data) > 0 && resp.Value.Data[0] != "" {
		data, err = base64.StdEncoding.DecodeString(resp.Value.Data[0])
		if err != nil {
			return nil, fmt.Errorf("decode account data: %w", err)
		}
	}

	return &types.Account{
		Lamports:   types.Lamports(resp.Value.Lamports),
		Data:       data,
		Owner:      owner,
		Executable: resp.Value.Executable,
		RentEpoch:  types.Epoch(resp.Value.RentEpoch),
	}, nil
}

// GetTransaction returns a transaction by signature.
func (c *RPCClient) GetTransaction(ctx context.Context, signature types.Signature) (*types.Transaction, error) {
	result, err := c.call(ctx, "getTransaction", []interface{}{
		signature.String(),
		map[string]interface{}{
			"encoding":                       "base64",
			"commitment":                     "confirmed",
			"maxSupportedTransactionVersion": 0,
		},
	})
	if err != nil {
		return nil, err
	}

	if string(result) == "null" {
		return nil, nil // Transaction not found
	}

	var txResp struct {
		Transaction []string `json:"transaction"` // [data, encoding]
		Slot        uint64   `json:"slot"`
	}
	if err := json.Unmarshal(result, &txResp); err != nil {
		return nil, fmt.Errorf("unmarshal transaction: %w", err)
	}

	if len(txResp.Transaction) < 1 {
		return nil, fmt.Errorf("empty transaction data")
	}

	txData, err := base64.StdEncoding.DecodeString(txResp.Transaction[0])
	if err != nil {
		return nil, fmt.Errorf("decode transaction data: %w", err)
	}

	return types.DeserializeTransaction(txData)
}

// GetEpochInfo returns current epoch information.
func (c *RPCClient) GetEpochInfo(ctx context.Context) (*EpochInfo, error) {
	result, err := c.call(ctx, "getEpochInfo", []interface{}{
		map[string]string{"commitment": "confirmed"},
	})
	if err != nil {
		return nil, err
	}

	var info EpochInfo
	if err := json.Unmarshal(result, &info); err != nil {
		return nil, fmt.Errorf("unmarshal epoch info: %w", err)
	}

	return &info, nil
}

// EpochInfo contains epoch information.
type EpochInfo struct {
	AbsoluteSlot     uint64 `json:"absoluteSlot"`
	BlockHeight      uint64 `json:"blockHeight"`
	Epoch            uint64 `json:"epoch"`
	SlotIndex        uint64 `json:"slotIndex"`
	SlotsInEpoch     uint64 `json:"slotsInEpoch"`
	TransactionCount uint64 `json:"transactionCount"`
}

// GetHealth checks if the node is healthy.
func (c *RPCClient) GetHealth(ctx context.Context) error {
	_, err := c.call(ctx, "getHealth", nil)
	return err
}

// SetEndpoint updates the RPC endpoint.
func (c *RPCClient) SetEndpoint(endpoint string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.endpoint = endpoint
}

// Endpoint returns the current RPC endpoint.
func (c *RPCClient) Endpoint() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.endpoint
}
