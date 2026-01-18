package rpc

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/fortiblox/x1-nimbus/pkg/accounts"
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// Handler is the function signature for RPC method handlers.
type Handler func(params json.RawMessage) (interface{}, *RPCError)

// Handlers manages RPC method handlers and provides access to node state.
type Handlers struct {
	db       accounts.AccountsDB
	state    *NodeState
	stateMu  sync.RWMutex
	handlers map[string]Handler
}

// NewHandlers creates a new Handlers instance.
func NewHandlers(db accounts.AccountsDB) *Handlers {
	h := &Handlers{
		db:       db,
		state:    DefaultNodeState(),
		handlers: make(map[string]Handler),
	}

	// Register all handlers
	h.registerHandlers()

	return h
}

// SetState updates the node state.
func (h *Handlers) SetState(state *NodeState) {
	h.stateMu.Lock()
	defer h.stateMu.Unlock()
	h.state = state
}

// GetState returns the current node state.
func (h *Handlers) GetState() *NodeState {
	h.stateMu.RLock()
	defer h.stateMu.RUnlock()
	return h.state
}

// UpdateSlot updates the current slot in the node state.
func (h *Handlers) UpdateSlot(slot types.Slot) {
	h.stateMu.Lock()
	defer h.stateMu.Unlock()
	h.state.Slot = slot
}

// UpdateBlockhash updates the latest blockhash in the node state.
func (h *Handlers) UpdateBlockhash(blockhash types.Hash) {
	h.stateMu.Lock()
	defer h.stateMu.Unlock()
	h.state.LatestBlockhash = blockhash
}

// GetHandler returns the handler for a method, or nil if not found.
func (h *Handlers) GetHandler(method string) Handler {
	return h.handlers[method]
}

// registerHandlers registers all RPC method handlers.
func (h *Handlers) registerHandlers() {
	h.handlers["getAccountInfo"] = h.handleGetAccountInfo
	h.handlers["getBalance"] = h.handleGetBalance
	h.handlers["getSlot"] = h.handleGetSlot
	h.handlers["getBlockHeight"] = h.handleGetBlockHeight
	h.handlers["getHealth"] = h.handleGetHealth
	h.handlers["getVersion"] = h.handleGetVersion
	h.handlers["getLatestBlockhash"] = h.handleGetLatestBlockhash
	h.handlers["getEpochInfo"] = h.handleGetEpochInfo
}

// handleGetAccountInfo handles the getAccountInfo RPC method.
// Params: [pubkey, {encoding, dataSlice, minContextSlot}]
func (h *Handlers) handleGetAccountInfo(params json.RawMessage) (interface{}, *RPCError) {
	// Parse parameters
	var rawParams []json.RawMessage
	if err := json.Unmarshal(params, &rawParams); err != nil {
		return nil, NewRPCError(InvalidParams, "invalid params: expected array")
	}

	if len(rawParams) < 1 {
		return nil, NewRPCError(InvalidParams, "missing pubkey parameter")
	}

	// Parse pubkey
	var pubkeyStr string
	if err := json.Unmarshal(rawParams[0], &pubkeyStr); err != nil {
		return nil, NewRPCError(InvalidParams, "invalid pubkey parameter")
	}

	pubkey, err := DecodePubkey(pubkeyStr)
	if err != nil {
		return nil, NewRPCError(InvalidParams, fmt.Sprintf("invalid pubkey: %v", err))
	}

	// Parse options
	encoding := EncodingBase64
	var dataSlice *DataSlice

	if len(rawParams) > 1 {
		var options AccountInfoOptions
		if err := json.Unmarshal(rawParams[1], &options); err == nil {
			if options.Encoding != "" {
				if err := ValidateEncoding(options.Encoding); err != nil {
					return nil, NewRPCError(UnsupportedEncoding, err.Error())
				}
				encoding = options.Encoding
			}
			dataSlice = options.DataSlice
		}
	}

	// Get account from database
	account, err := h.db.GetAccount(pubkey)
	if err != nil {
		return nil, NewRPCError(InternalError, fmt.Sprintf("failed to get account: %v", err))
	}

	// Get current state
	state := h.GetState()

	// If account doesn't exist, return null value
	if account == nil {
		return ContextualResult{
			Context: Context{Slot: uint64(state.Slot)},
			Value:   nil,
		}, nil
	}

	// Prepare account data
	data := account.Data
	if dataSlice != nil {
		data = SliceData(data, dataSlice)
	}

	encodedData, err := EncodeAccountData(data, encoding)
	if err != nil {
		return nil, NewRPCError(InternalError, fmt.Sprintf("failed to encode data: %v", err))
	}

	result := AccountInfoResult{
		Lamports:   uint64(account.Lamports),
		Data:       encodedData,
		Owner:      EncodePubkey(account.Owner),
		Executable: account.Executable,
		RentEpoch:  uint64(account.RentEpoch),
		Space:      uint64(len(account.Data)),
	}

	return ContextualResult{
		Context: Context{Slot: uint64(state.Slot)},
		Value:   result,
	}, nil
}

// handleGetBalance handles the getBalance RPC method.
// Params: [pubkey, {minContextSlot}]
func (h *Handlers) handleGetBalance(params json.RawMessage) (interface{}, *RPCError) {
	// Parse parameters
	var rawParams []json.RawMessage
	if err := json.Unmarshal(params, &rawParams); err != nil {
		return nil, NewRPCError(InvalidParams, "invalid params: expected array")
	}

	if len(rawParams) < 1 {
		return nil, NewRPCError(InvalidParams, "missing pubkey parameter")
	}

	// Parse pubkey
	var pubkeyStr string
	if err := json.Unmarshal(rawParams[0], &pubkeyStr); err != nil {
		return nil, NewRPCError(InvalidParams, "invalid pubkey parameter")
	}

	pubkey, err := DecodePubkey(pubkeyStr)
	if err != nil {
		return nil, NewRPCError(InvalidParams, fmt.Sprintf("invalid pubkey: %v", err))
	}

	// Get account from database
	account, err := h.db.GetAccount(pubkey)
	if err != nil {
		return nil, NewRPCError(InternalError, fmt.Sprintf("failed to get account: %v", err))
	}

	// Get current state
	state := h.GetState()

	// Return 0 balance if account doesn't exist
	var balance uint64
	if account != nil {
		balance = uint64(account.Lamports)
	}

	return BalanceResult{
		Context: Context{Slot: uint64(state.Slot)},
		Value:   balance,
	}, nil
}

// handleGetSlot handles the getSlot RPC method.
// Params: [{commitment, minContextSlot}]
func (h *Handlers) handleGetSlot(params json.RawMessage) (interface{}, *RPCError) {
	state := h.GetState()
	return SlotResult(state.Slot), nil
}

// handleGetBlockHeight handles the getBlockHeight RPC method.
// Params: [{commitment, minContextSlot}]
func (h *Handlers) handleGetBlockHeight(params json.RawMessage) (interface{}, *RPCError) {
	state := h.GetState()
	return BlockHeightResult(state.BlockHeight), nil
}

// handleGetHealth handles the getHealth RPC method.
// Params: none
func (h *Handlers) handleGetHealth(params json.RawMessage) (interface{}, *RPCError) {
	// A simple health check - in production this would check more conditions
	return HealthResult("ok"), nil
}

// handleGetVersion handles the getVersion RPC method.
// Params: none
func (h *Handlers) handleGetVersion(params json.RawMessage) (interface{}, *RPCError) {
	return VersionResult{
		SolanaCore: "1.18.0", // X1-Nimbus version
		FeatureSet: 0,
	}, nil
}

// handleGetLatestBlockhash handles the getLatestBlockhash RPC method.
// Params: [{commitment, minContextSlot}]
func (h *Handlers) handleGetLatestBlockhash(params json.RawMessage) (interface{}, *RPCError) {
	state := h.GetState()

	result := BlockhashResult{
		Blockhash:            EncodeHash(state.LatestBlockhash),
		LastValidBlockHeight: state.BlockHeight + 150, // Default validity window
	}

	return ContextualResult{
		Context: Context{Slot: uint64(state.Slot)},
		Value:   result,
	}, nil
}

// handleGetEpochInfo handles the getEpochInfo RPC method.
// Params: [{commitment, minContextSlot}]
func (h *Handlers) handleGetEpochInfo(params json.RawMessage) (interface{}, *RPCError) {
	state := h.GetState()

	return EpochInfoResult{
		AbsoluteSlot:     uint64(state.Slot),
		BlockHeight:      state.BlockHeight,
		Epoch:            uint64(state.Epoch),
		SlotIndex:        state.SlotIndex,
		SlotsInEpoch:     state.SlotsInEpoch,
		TransactionCount: state.TransactionCount,
	}, nil
}
