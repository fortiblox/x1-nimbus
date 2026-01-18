// Package rpc provides a JSON-RPC 2.0 server for X1-Nimbus.
package rpc

import (
	"encoding/json"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// JSON-RPC 2.0 constants
const (
	JSONRPCVersion = "2.0"
)

// Standard JSON-RPC 2.0 error codes
const (
	ParseError     = -32700
	InvalidRequest = -32600
	MethodNotFound = -32601
	InvalidParams  = -32602
	InternalError  = -32603

	// Solana-specific error codes
	BlockCleanedUp        = -32001
	SendTransactionError  = -32002
	TransactionNotFound   = -32003
	SlotSkipped           = -32004
	NoSnapshot            = -32005
	LongTermStorageSlot   = -32006
	KeyExcludedFromIndex  = -32007
	TransactionHistoryErr = -32008
	ScanError             = -32009
	KeyNotFound           = -32010
	UnsupportedEncoding   = -32011
)

// RPCRequest represents a JSON-RPC 2.0 request.
type RPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      interface{}     `json:"id"`
}

// RPCResponse represents a JSON-RPC 2.0 response.
type RPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

// RPCError represents a JSON-RPC 2.0 error.
type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Error implements the error interface.
func (e *RPCError) Error() string {
	return e.Message
}

// NewRPCError creates a new RPC error.
func NewRPCError(code int, message string) *RPCError {
	return &RPCError{
		Code:    code,
		Message: message,
	}
}

// NewRPCErrorWithData creates a new RPC error with additional data.
func NewRPCErrorWithData(code int, message string, data interface{}) *RPCError {
	return &RPCError{
		Code:    code,
		Message: message,
		Data:    data,
	}
}

// Context represents the response context containing slot info.
type Context struct {
	Slot        uint64 `json:"slot"`
	APIVersion  string `json:"apiVersion,omitempty"`
}

// ContextualResult wraps a result with context.
type ContextualResult struct {
	Context Context     `json:"context"`
	Value   interface{} `json:"value"`
}

// AccountInfoResult represents the result of getAccountInfo.
type AccountInfoResult struct {
	Lamports   uint64        `json:"lamports"`
	Data       []interface{} `json:"data"` // [data, encoding] or parsed data
	Owner      string        `json:"owner"`
	Executable bool          `json:"executable"`
	RentEpoch  uint64        `json:"rentEpoch"`
	Space      uint64        `json:"space,omitempty"`
}

// BalanceResult represents the result of getBalance.
type BalanceResult struct {
	Context Context `json:"context"`
	Value   uint64  `json:"value"`
}

// SlotResult is just the slot number.
type SlotResult uint64

// BlockHeightResult is just the block height.
type BlockHeightResult uint64

// HealthResult represents the result of getHealth.
type HealthResult string

// VersionResult represents the result of getVersion.
type VersionResult struct {
	SolanaCore string `json:"solana-core"`
	FeatureSet uint32 `json:"feature-set,omitempty"`
}

// BlockhashResult represents a blockhash with context.
type BlockhashResult struct {
	Blockhash            string `json:"blockhash"`
	LastValidBlockHeight uint64 `json:"lastValidBlockHeight"`
}

// EpochInfoResult represents the result of getEpochInfo.
type EpochInfoResult struct {
	AbsoluteSlot     uint64 `json:"absoluteSlot"`
	BlockHeight      uint64 `json:"blockHeight"`
	Epoch            uint64 `json:"epoch"`
	SlotIndex        uint64 `json:"slotIndex"`
	SlotsInEpoch     uint64 `json:"slotsInEpoch"`
	TransactionCount uint64 `json:"transactionCount,omitempty"`
}

// GetAccountInfoParams represents parameters for getAccountInfo.
type GetAccountInfoParams struct {
	Pubkey  string
	Options *AccountInfoOptions
}

// AccountInfoOptions represents optional parameters for getAccountInfo.
type AccountInfoOptions struct {
	Encoding       string `json:"encoding,omitempty"`       // base58, base64, base64+zstd, jsonParsed
	DataSlice      *DataSlice `json:"dataSlice,omitempty"` // Limit returned data
	MinContextSlot uint64 `json:"minContextSlot,omitempty"`
}

// DataSlice represents a slice of account data.
type DataSlice struct {
	Offset uint64 `json:"offset"`
	Length uint64 `json:"length"`
}

// GetBalanceParams represents parameters for getBalance.
type GetBalanceParams struct {
	Pubkey  string
	Options *BalanceOptions
}

// BalanceOptions represents optional parameters for getBalance.
type BalanceOptions struct {
	MinContextSlot uint64 `json:"minContextSlot,omitempty"`
}

// Commitment levels
type Commitment string

const (
	CommitmentFinalized Commitment = "finalized"
	CommitmentConfirmed Commitment = "confirmed"
	CommitmentProcessed Commitment = "processed"
)

// NodeState holds the current node state for RPC responses.
type NodeState struct {
	Slot              types.Slot
	BlockHeight       uint64
	Epoch             types.Epoch
	SlotIndex         uint64
	SlotsInEpoch      uint64
	LatestBlockhash   types.Hash
	TransactionCount  uint64
}

// DefaultNodeState returns a default node state for testing.
func DefaultNodeState() *NodeState {
	return &NodeState{
		Slot:             0,
		BlockHeight:      0,
		Epoch:            0,
		SlotIndex:        0,
		SlotsInEpoch:     432000, // Mainnet value
		LatestBlockhash:  types.ZeroHash,
		TransactionCount: 0,
	}
}
