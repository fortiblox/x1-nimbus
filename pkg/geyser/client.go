package geyser

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// Client provides access to Geyser gRPC streaming services.
// When gRPC is unavailable, it falls back to JSON-RPC polling.
type Client struct {
	config     *Config
	rpc        *RPCClient
	subscriber *Subscriber
	proto      *ProtoHelper

	// Connection state
	mu        sync.RWMutex
	connected atomic.Bool
	closed    atomic.Bool

	// gRPC connection (to be added when protobufs are available)
	// conn *grpc.ClientConn
	// grpcClient yellowstone.GeyserClient

	// TLS configuration
	tlsConfig *tls.Config
}

// Option is a functional option for configuring the Client.
type Option func(*Client)

// WithToken sets the authentication token.
func WithToken(token string) Option {
	return func(c *Client) {
		c.config.Token = token
	}
}

// WithTLS enables TLS for the connection.
func WithTLS() Option {
	return func(c *Client) {
		c.config.UseTLS = true
	}
}

// WithTLSConfig sets a custom TLS configuration.
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(c *Client) {
		c.config.UseTLS = true
		c.tlsConfig = tlsConfig
	}
}

// WithRetry configures retry behavior.
func WithRetry(maxRetries int, baseDelay, maxDelay time.Duration) Option {
	return func(c *Client) {
		c.config.MaxRetries = maxRetries
		c.config.RetryBaseDelay = baseDelay
		c.config.RetryMaxDelay = maxDelay
	}
}

// WithAutoReconnect enables or disables automatic reconnection.
func WithAutoReconnect(enabled bool) Option {
	return func(c *Client) {
		c.config.AutoReconnect = enabled
	}
}

// WithBufferSize sets the channel buffer size for subscriptions.
func WithBufferSize(size int) Option {
	return func(c *Client) {
		c.config.BufferSize = size
	}
}

// WithRPCFallback enables RPC fallback when Geyser is unavailable.
func WithRPCFallback(endpoint string) Option {
	return func(c *Client) {
		c.config.EnableRPCFallback = true
		c.config.RPCEndpoint = endpoint
	}
}

// WithRPCPollInterval sets the polling interval for RPC fallback.
func WithRPCPollInterval(interval time.Duration) Option {
	return func(c *Client) {
		c.config.RPCPollInterval = interval
	}
}

// WithTimeout sets connection and request timeouts.
func WithTimeout(connect, request time.Duration) Option {
	return func(c *Client) {
		c.config.ConnectTimeout = connect
		c.config.RequestTimeout = request
	}
}

// NewClient creates a new Geyser client.
func NewClient(endpoint string, opts ...Option) (*Client, error) {
	config := DefaultConfig()
	config.Endpoint = endpoint

	client := &Client{
		config: config,
	}

	// Apply options
	for _, opt := range opts {
		opt(client)
	}

	// Validate configuration
	if err := client.config.Validate(); err != nil {
		return nil, err
	}

	// Initialize RPC client if endpoint is provided
	if client.config.RPCEndpoint != "" {
		client.rpc = NewRPCClientWithTimeout(
			client.config.RPCEndpoint,
			client.config.RequestTimeout,
		)
		client.proto = NewProtoHelperWithRPC(client.rpc)
	}

	return client, nil
}

// NewClientWithConfig creates a new Geyser client with a custom configuration.
func NewClientWithConfig(config *Config) (*Client, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	client := &Client{
		config: config.Clone(),
	}

	// Initialize RPC client if endpoint is provided
	if client.config.RPCEndpoint != "" {
		client.rpc = NewRPCClientWithTimeout(
			client.config.RPCEndpoint,
			client.config.RequestTimeout,
		)
		client.proto = NewProtoHelperWithRPC(client.rpc)
	}

	return client, nil
}

// Connect establishes a connection to the Geyser service.
// Currently uses RPC fallback; gRPC connection will be added when protobufs are available.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed.Load() {
		return fmt.Errorf("client is closed")
	}

	if c.connected.Load() {
		return nil // Already connected
	}

	// For now, we use RPC fallback since gRPC requires protobuf definitions
	// When protobufs are added, this will establish the gRPC connection
	if c.rpc == nil && c.config.RPCEndpoint != "" {
		c.rpc = NewRPCClientWithTimeout(
			c.config.RPCEndpoint,
			c.config.RequestTimeout,
		)
		c.proto = NewProtoHelperWithRPC(c.rpc)
	}

	// Verify connection by getting slot
	if c.rpc != nil {
		_, err := c.rpc.GetSlot(ctx)
		if err != nil {
			return fmt.Errorf("connection check failed: %w", err)
		}
	}

	// Initialize subscriber
	c.subscriber = newSubscriber(c, c.config, c.rpc)

	c.connected.Store(true)
	return nil
}

// Close closes the client and all active subscriptions.
func (c *Client) Close() error {
	if c.closed.Swap(true) {
		return nil // Already closed
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Close subscriber
	if c.subscriber != nil {
		c.subscriber.Close()
	}

	c.connected.Store(false)

	// Close gRPC connection when available
	// if c.conn != nil {
	//     c.conn.Close()
	// }

	return nil
}

// IsConnected returns true if the client is connected.
func (c *Client) IsConnected() bool {
	return c.connected.Load() && !c.closed.Load()
}

// Config returns the client configuration.
func (c *Client) Config() *Config {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.config.Clone()
}

// SubscribeBlocks subscribes to new blocks at the specified commitment level.
func (c *Client) SubscribeBlocks(ctx context.Context, commitment string) (<-chan *types.Block, error) {
	if !c.connected.Load() {
		return nil, fmt.Errorf("client not connected")
	}

	if c.subscriber == nil {
		return nil, fmt.Errorf("subscriber not initialized")
	}

	return c.subscriber.SubscribeBlocks(ctx, commitment)
}

// SubscribeSlots subscribes to slot updates.
func (c *Client) SubscribeSlots(ctx context.Context) (<-chan SlotUpdate, error) {
	if !c.connected.Load() {
		return nil, fmt.Errorf("client not connected")
	}

	if c.subscriber == nil {
		return nil, fmt.Errorf("subscriber not initialized")
	}

	return c.subscriber.SubscribeSlots(ctx)
}

// SubscribeAccounts subscribes to account updates for specific accounts.
func (c *Client) SubscribeAccounts(ctx context.Context, accounts []types.Pubkey) (<-chan *AccountUpdate, error) {
	if !c.connected.Load() {
		return nil, fmt.Errorf("client not connected")
	}

	if c.subscriber == nil {
		return nil, fmt.Errorf("subscriber not initialized")
	}

	return c.subscriber.SubscribeAccounts(ctx, accounts)
}

// SubscribeTransactions subscribes to transactions matching the filter.
func (c *Client) SubscribeTransactions(ctx context.Context, filter *SubscriptionFilter) (<-chan *TransactionUpdate, error) {
	if !c.connected.Load() {
		return nil, fmt.Errorf("client not connected")
	}

	if c.subscriber == nil {
		return nil, fmt.Errorf("subscriber not initialized")
	}

	return c.subscriber.SubscribeTransactions(ctx, filter)
}

// GetBlock retrieves a block by slot number.
func (c *Client) GetBlock(ctx context.Context, slot uint64) (*types.Block, error) {
	if c.proto != nil {
		return c.proto.GetBlock(ctx, slot)
	}
	if c.rpc != nil {
		return c.rpc.GetBlock(ctx, slot)
	}
	return nil, fmt.Errorf("no RPC client available")
}

// GetSlot retrieves the current slot.
func (c *Client) GetSlot(ctx context.Context) (uint64, error) {
	if c.proto != nil {
		return c.proto.GetSlot(ctx)
	}
	if c.rpc != nil {
		return c.rpc.GetSlot(ctx)
	}
	return 0, fmt.Errorf("no RPC client available")
}

// GetSlotWithCommitment retrieves the current slot at a specific commitment level.
func (c *Client) GetSlotWithCommitment(ctx context.Context, commitment string) (uint64, error) {
	if c.proto != nil {
		return c.proto.GetSlotWithCommitment(ctx, commitment)
	}
	if c.rpc != nil {
		return c.rpc.GetSlotWithCommitment(ctx, commitment)
	}
	return 0, fmt.Errorf("no RPC client available")
}

// GetAccountInfo retrieves account information.
func (c *Client) GetAccountInfo(ctx context.Context, pubkey types.Pubkey) (*types.Account, error) {
	if c.proto != nil {
		return c.proto.GetAccountInfo(ctx, pubkey)
	}
	if c.rpc != nil {
		return c.rpc.GetAccountInfo(ctx, pubkey)
	}
	return nil, fmt.Errorf("no RPC client available")
}

// GetTransaction retrieves a transaction by signature.
func (c *Client) GetTransaction(ctx context.Context, signature types.Signature) (*types.Transaction, error) {
	if c.proto != nil {
		return c.proto.GetTransaction(ctx, signature)
	}
	if c.rpc != nil {
		return c.rpc.GetTransaction(ctx, signature)
	}
	return nil, fmt.Errorf("no RPC client available")
}

// GetLatestBlockhash retrieves the latest blockhash.
func (c *Client) GetLatestBlockhash(ctx context.Context) (types.Hash, uint64, error) {
	if c.rpc != nil {
		return c.rpc.GetLatestBlockhash(ctx)
	}
	return types.ZeroHash, 0, fmt.Errorf("no RPC client available")
}

// GetBlockHeight retrieves the current block height.
func (c *Client) GetBlockHeight(ctx context.Context) (uint64, error) {
	if c.rpc != nil {
		return c.rpc.GetBlockHeight(ctx)
	}
	return 0, fmt.Errorf("no RPC client available")
}

// GetEpochInfo retrieves current epoch information.
func (c *Client) GetEpochInfo(ctx context.Context) (*EpochInfo, error) {
	if c.rpc != nil {
		return c.rpc.GetEpochInfo(ctx)
	}
	return nil, fmt.Errorf("no RPC client available")
}

// Health checks if the connection is healthy.
func (c *Client) Health(ctx context.Context) error {
	if c.rpc != nil {
		return c.rpc.GetHealth(ctx)
	}
	return fmt.Errorf("no RPC client available")
}

// Stats returns subscription statistics.
func (c *Client) Stats() StreamStats {
	if c.subscriber != nil {
		return c.subscriber.Stats()
	}
	return StreamStats{}
}

// RPC returns the underlying RPC client for direct access.
func (c *Client) RPC() *RPCClient {
	return c.rpc
}

// Proto returns the protobuf helper for direct access.
func (c *Client) Proto() *ProtoHelper {
	return c.proto
}
