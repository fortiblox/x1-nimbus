package geyser

import (
	"time"
)

// Known Geyser providers.
const (
	ProviderTriton    = "triton"    // Triton One (Dragon's Mouth)
	ProviderHelius    = "helius"    // Helius
	ProviderQuickNode = "quicknode" // QuickNode
	ProviderCustom    = "custom"    // Custom endpoint
)

// Config holds configuration for the Geyser client.
type Config struct {
	// Endpoint is the Geyser gRPC endpoint URL.
	// For Triton: grpc.mainnet.triton.one:443
	// For Helius: mainnet.helius-rpc.com:443
	Endpoint string

	// Token is the authentication token for the Geyser service.
	Token string

	// UseTLS enables TLS for the gRPC connection.
	UseTLS bool

	// Provider identifies the Geyser provider for provider-specific handling.
	Provider string

	// RPCEndpoint is the JSON-RPC endpoint for fallback operations.
	RPCEndpoint string

	// Connection settings
	ConnectTimeout    time.Duration
	RequestTimeout    time.Duration
	KeepAliveInterval time.Duration
	KeepAliveTimeout  time.Duration

	// Retry settings
	MaxRetries        int
	RetryBaseDelay    time.Duration
	RetryMaxDelay     time.Duration
	RetryMultiplier   float64

	// Subscription settings
	BufferSize        int  // Channel buffer size for subscriptions
	AutoReconnect     bool // Automatically reconnect on connection loss
	ReconnectDelay    time.Duration

	// RPC fallback settings
	EnableRPCFallback bool          // Use RPC when Geyser is unavailable
	RPCPollInterval   time.Duration // Polling interval for RPC fallback
}

// DefaultConfig returns a default configuration.
func DefaultConfig() *Config {
	return &Config{
		UseTLS:            true,
		Provider:          ProviderCustom,
		ConnectTimeout:    10 * time.Second,
		RequestTimeout:    30 * time.Second,
		KeepAliveInterval: 30 * time.Second,
		KeepAliveTimeout:  10 * time.Second,
		MaxRetries:        5,
		RetryBaseDelay:    100 * time.Millisecond,
		RetryMaxDelay:     30 * time.Second,
		RetryMultiplier:   2.0,
		BufferSize:        1000,
		AutoReconnect:     true,
		ReconnectDelay:    5 * time.Second,
		EnableRPCFallback: true,
		RPCPollInterval:   400 * time.Millisecond, // ~2.5 blocks/sec
	}
}

// TritonConfig returns a configuration for Triton One (Dragon's Mouth).
func TritonConfig(token string) *Config {
	cfg := DefaultConfig()
	cfg.Endpoint = "grpc.mainnet.triton.one:443"
	cfg.RPCEndpoint = "https://api.mainnet-beta.solana.com"
	cfg.Token = token
	cfg.Provider = ProviderTriton
	cfg.UseTLS = true
	return cfg
}

// TritonDevnetConfig returns a configuration for Triton One devnet.
func TritonDevnetConfig(token string) *Config {
	cfg := DefaultConfig()
	cfg.Endpoint = "grpc.devnet.triton.one:443"
	cfg.RPCEndpoint = "https://api.devnet.solana.com"
	cfg.Token = token
	cfg.Provider = ProviderTriton
	cfg.UseTLS = true
	return cfg
}

// HeliusConfig returns a configuration for Helius.
func HeliusConfig(apiKey string) *Config {
	cfg := DefaultConfig()
	cfg.Endpoint = "mainnet.helius-rpc.com:443"
	cfg.RPCEndpoint = "https://mainnet.helius-rpc.com/?api-key=" + apiKey
	cfg.Token = apiKey
	cfg.Provider = ProviderHelius
	cfg.UseTLS = true
	return cfg
}

// QuickNodeConfig returns a configuration for QuickNode.
func QuickNodeConfig(endpoint, token string) *Config {
	cfg := DefaultConfig()
	cfg.Endpoint = endpoint
	cfg.Token = token
	cfg.Provider = ProviderQuickNode
	cfg.UseTLS = true
	return cfg
}

// LocalConfig returns a configuration for a local validator.
func LocalConfig() *Config {
	cfg := DefaultConfig()
	cfg.Endpoint = "localhost:10000"
	cfg.RPCEndpoint = "http://localhost:8899"
	cfg.UseTLS = false
	cfg.Provider = ProviderCustom
	cfg.AutoReconnect = true
	return cfg
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if c.Endpoint == "" && c.RPCEndpoint == "" {
		return &ConfigError{Field: "Endpoint", Message: "either Endpoint or RPCEndpoint must be set"}
	}
	if c.BufferSize <= 0 {
		c.BufferSize = 1000
	}
	if c.MaxRetries < 0 {
		c.MaxRetries = 0
	}
	if c.RetryBaseDelay <= 0 {
		c.RetryBaseDelay = 100 * time.Millisecond
	}
	if c.RetryMaxDelay <= 0 {
		c.RetryMaxDelay = 30 * time.Second
	}
	if c.RetryMultiplier <= 0 {
		c.RetryMultiplier = 2.0
	}
	if c.RPCPollInterval <= 0 {
		c.RPCPollInterval = 400 * time.Millisecond
	}
	return nil
}

// ConfigError represents a configuration validation error.
type ConfigError struct {
	Field   string
	Message string
}

// Error implements the error interface.
func (e *ConfigError) Error() string {
	return "geyser config: " + e.Field + ": " + e.Message
}

// Clone creates a deep copy of the configuration.
func (c *Config) Clone() *Config {
	clone := *c
	return &clone
}

// WithEndpoint sets the endpoint.
func (c *Config) WithEndpoint(endpoint string) *Config {
	c.Endpoint = endpoint
	return c
}

// WithToken sets the authentication token.
func (c *Config) WithToken(token string) *Config {
	c.Token = token
	return c
}

// WithTLS enables or disables TLS.
func (c *Config) WithTLS(enabled bool) *Config {
	c.UseTLS = enabled
	return c
}

// WithRPCEndpoint sets the RPC endpoint for fallback.
func (c *Config) WithRPCEndpoint(endpoint string) *Config {
	c.RPCEndpoint = endpoint
	return c
}

// WithBufferSize sets the subscription buffer size.
func (c *Config) WithBufferSize(size int) *Config {
	c.BufferSize = size
	return c
}

// WithAutoReconnect enables or disables auto-reconnection.
func (c *Config) WithAutoReconnect(enabled bool) *Config {
	c.AutoReconnect = enabled
	return c
}

// WithRPCFallback enables or disables RPC fallback.
func (c *Config) WithRPCFallback(enabled bool) *Config {
	c.EnableRPCFallback = enabled
	return c
}
