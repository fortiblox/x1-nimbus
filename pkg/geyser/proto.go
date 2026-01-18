package geyser

import (
	"context"
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// ProtoHelper provides helper functions for Geyser protobuf operations.
// Currently uses RPC as a fallback since actual gRPC requires generated protobuf definitions.
//
// When protobuf definitions are added, this will be updated to use the generated types.
// Expected proto imports would be:
//   - yellowstone_grpc "github.com/rpcpool/yellowstone-grpc/grpc"
type ProtoHelper struct {
	rpc *RPCClient
}

// NewProtoHelper creates a new proto helper with RPC fallback.
func NewProtoHelper(rpcEndpoint string) *ProtoHelper {
	return &ProtoHelper{
		rpc: NewRPCClient(rpcEndpoint),
	}
}

// NewProtoHelperWithRPC creates a proto helper with an existing RPC client.
func NewProtoHelperWithRPC(rpc *RPCClient) *ProtoHelper {
	return &ProtoHelper{
		rpc: rpc,
	}
}

// GetBlock retrieves a block by slot number.
// This is a fallback implementation using JSON-RPC.
// With gRPC, this would use the streaming block subscription.
func (h *ProtoHelper) GetBlock(ctx context.Context, slot uint64) (*types.Block, error) {
	if h.rpc == nil {
		return nil, fmt.Errorf("RPC client not initialized")
	}
	return h.rpc.GetBlock(ctx, slot)
}

// GetSlot retrieves the current slot.
// This is a fallback implementation using JSON-RPC.
func (h *ProtoHelper) GetSlot(ctx context.Context) (uint64, error) {
	if h.rpc == nil {
		return 0, fmt.Errorf("RPC client not initialized")
	}
	return h.rpc.GetSlot(ctx)
}

// GetSlotWithCommitment retrieves the current slot at a specific commitment level.
func (h *ProtoHelper) GetSlotWithCommitment(ctx context.Context, commitment string) (uint64, error) {
	if h.rpc == nil {
		return 0, fmt.Errorf("RPC client not initialized")
	}
	return h.rpc.GetSlotWithCommitment(ctx, commitment)
}

// GetAccountInfo retrieves account information.
// This is a fallback implementation using JSON-RPC.
// With gRPC, this would use the account subscription.
func (h *ProtoHelper) GetAccountInfo(ctx context.Context, pubkey types.Pubkey) (*types.Account, error) {
	if h.rpc == nil {
		return nil, fmt.Errorf("RPC client not initialized")
	}
	return h.rpc.GetAccountInfo(ctx, pubkey)
}

// GetTransaction retrieves a transaction by signature.
// This is a fallback implementation using JSON-RPC.
func (h *ProtoHelper) GetTransaction(ctx context.Context, signature types.Signature) (*types.Transaction, error) {
	if h.rpc == nil {
		return nil, fmt.Errorf("RPC client not initialized")
	}
	return h.rpc.GetTransaction(ctx, signature)
}

// SlotInfo represents slot information from Geyser.
// This mirrors the Yellowstone gRPC SlotUpdate message.
type SlotInfo struct {
	Slot   uint64
	Parent uint64
	Status SlotStatus
}

// BlockInfo represents block information from Geyser.
// This mirrors the Yellowstone gRPC BlockMeta message.
type BlockInfo struct {
	Slot              uint64
	Blockhash         string
	ParentSlot        uint64
	ParentBlockhash   string
	BlockHeight       uint64
	BlockTime         int64
	ExecutedTxCount   uint64
	EntriesCount      uint64
}

// AccountInfo represents account information from Geyser.
// This mirrors the Yellowstone gRPC AccountUpdate message.
type AccountInfo struct {
	Pubkey       []byte
	Lamports     uint64
	Owner        []byte
	Executable   bool
	RentEpoch    uint64
	Data         []byte
	WriteVersion uint64
	Slot         uint64
}

// TransactionInfo represents transaction information from Geyser.
// This mirrors the Yellowstone gRPC TransactionUpdate message.
type TransactionInfo struct {
	Signature   []byte
	IsVote      bool
	Transaction []byte // Serialized transaction
	Meta        *TransactionMeta
	Slot        uint64
	Index       uint64
}

// TransactionMeta represents transaction metadata from Geyser.
type TransactionMeta struct {
	Error            string
	Fee              uint64
	PreBalances      []uint64
	PostBalances     []uint64
	LogMessages      []string
	ComputeUnitsUsed uint64
}

// ConvertSlotInfo converts Geyser SlotInfo to SlotUpdate.
func ConvertSlotInfo(info *SlotInfo) *SlotUpdate {
	if info == nil {
		return nil
	}
	return &SlotUpdate{
		Slot:   types.Slot(info.Slot),
		Parent: types.Slot(info.Parent),
		Status: info.Status,
	}
}

// ConvertAccountInfo converts Geyser AccountInfo to AccountUpdate.
func ConvertAccountInfo(info *AccountInfo) (*AccountUpdate, error) {
	if info == nil {
		return nil, nil
	}

	pubkey, err := types.PubkeyFromBytes(info.Pubkey)
	if err != nil {
		return nil, fmt.Errorf("parse pubkey: %w", err)
	}

	owner, err := types.PubkeyFromBytes(info.Owner)
	if err != nil {
		return nil, fmt.Errorf("parse owner: %w", err)
	}

	account := &types.Account{
		Lamports:   types.Lamports(info.Lamports),
		Data:       info.Data,
		Owner:      owner,
		Executable: info.Executable,
		RentEpoch:  types.Epoch(info.RentEpoch),
	}

	return &AccountUpdate{
		Pubkey:       pubkey,
		Account:      account,
		Slot:         types.Slot(info.Slot),
		WriteVersion: info.WriteVersion,
	}, nil
}

// ConvertTransactionInfo converts Geyser TransactionInfo to TransactionUpdate.
func ConvertTransactionInfo(info *TransactionInfo) (*TransactionUpdate, error) {
	if info == nil {
		return nil, nil
	}

	sig, err := types.SignatureFromBytes(info.Signature)
	if err != nil {
		return nil, fmt.Errorf("parse signature: %w", err)
	}

	var tx *types.Transaction
	if len(info.Transaction) > 0 {
		tx, err = types.DeserializeTransaction(info.Transaction)
		if err != nil {
			// Log but don't fail - some transactions may not be parseable
			tx = nil
		}
	}

	success := true
	if info.Meta != nil && info.Meta.Error != "" {
		success = false
	}

	return &TransactionUpdate{
		Signature:   sig,
		Slot:        types.Slot(info.Slot),
		Transaction: tx,
		IsVote:      info.IsVote,
		Success:     success,
	}, nil
}

// GeyserSubscribeRequest represents a Geyser subscription request.
// This mirrors the Yellowstone gRPC SubscribeRequest message.
type GeyserSubscribeRequest struct {
	Slots        map[string]*SlotFilter        `json:"slots,omitempty"`
	Accounts     map[string]*AccountFilter     `json:"accounts,omitempty"`
	Transactions map[string]*TransactionFilter `json:"transactions,omitempty"`
	Blocks       map[string]*BlockFilter       `json:"blocks,omitempty"`
	BlocksMeta   map[string]*BlockFilter       `json:"blocksMeta,omitempty"`
}

// SlotFilter defines a filter for slot subscriptions.
type SlotFilter struct {
	FilterByCommitment *bool `json:"filterByCommitment,omitempty"`
}

// AccountFilter defines a filter for account subscriptions.
type AccountFilter struct {
	Account []string `json:"account,omitempty"`
	Owner   []string `json:"owner,omitempty"`
	Filters []*AccountDataFilter `json:"filters,omitempty"`
}

// AccountDataFilter defines data filters for accounts.
type AccountDataFilter struct {
	Memcmp   *MemcmpFilter `json:"memcmp,omitempty"`
	Datasize *uint64       `json:"datasize,omitempty"`
}

// MemcmpFilter defines a memory comparison filter.
type MemcmpFilter struct {
	Offset uint64 `json:"offset"`
	Bytes  []byte `json:"bytes"`
}

// TransactionFilter defines a filter for transaction subscriptions.
type TransactionFilter struct {
	Vote            *bool    `json:"vote,omitempty"`
	Failed          *bool    `json:"failed,omitempty"`
	AccountInclude  []string `json:"accountInclude,omitempty"`
	AccountExclude  []string `json:"accountExclude,omitempty"`
	AccountRequired []string `json:"accountRequired,omitempty"`
}

// BlockFilter defines a filter for block subscriptions.
type BlockFilter struct {
	AccountInclude []string `json:"accountInclude,omitempty"`
}

// NewSubscribeRequest creates a new subscription request.
func NewSubscribeRequest() *GeyserSubscribeRequest {
	return &GeyserSubscribeRequest{
		Slots:        make(map[string]*SlotFilter),
		Accounts:     make(map[string]*AccountFilter),
		Transactions: make(map[string]*TransactionFilter),
		Blocks:       make(map[string]*BlockFilter),
		BlocksMeta:   make(map[string]*BlockFilter),
	}
}

// AddSlotSubscription adds a slot subscription.
func (r *GeyserSubscribeRequest) AddSlotSubscription(name string) *GeyserSubscribeRequest {
	r.Slots[name] = &SlotFilter{}
	return r
}

// AddBlockSubscription adds a block subscription.
func (r *GeyserSubscribeRequest) AddBlockSubscription(name string, accounts ...string) *GeyserSubscribeRequest {
	r.Blocks[name] = &BlockFilter{
		AccountInclude: accounts,
	}
	return r
}

// AddAccountSubscription adds an account subscription.
func (r *GeyserSubscribeRequest) AddAccountSubscription(name string, accounts []string, owners []string) *GeyserSubscribeRequest {
	r.Accounts[name] = &AccountFilter{
		Account: accounts,
		Owner:   owners,
	}
	return r
}

// AddTransactionSubscription adds a transaction subscription.
func (r *GeyserSubscribeRequest) AddTransactionSubscription(name string, includeVotes, includeFailed bool, accounts []string) *GeyserSubscribeRequest {
	r.Transactions[name] = &TransactionFilter{
		Vote:           &includeVotes,
		Failed:         &includeFailed,
		AccountInclude: accounts,
	}
	return r
}
