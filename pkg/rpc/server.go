package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/fortiblox/x1-nimbus/pkg/accounts"
)

// ServerConfig holds configuration for the RPC server.
type ServerConfig struct {
	// Address to listen on (e.g., ":8899" or "127.0.0.1:8899")
	Address string

	// ReadTimeout is the maximum duration for reading the entire request.
	ReadTimeout time.Duration

	// WriteTimeout is the maximum duration before timing out writes.
	WriteTimeout time.Duration

	// MaxRequestSize is the maximum size of a request body in bytes.
	MaxRequestSize int64

	// AllowedOrigins for CORS (empty means allow all).
	AllowedOrigins []string

	// EnableRateLimit enables rate limiting.
	EnableRateLimit bool

	// RateLimitRPS is the requests per second limit per IP.
	RateLimitRPS float64

	// RateLimitBurst is the burst capacity for rate limiting.
	RateLimitBurst float64

	// Logger for request logging (nil disables logging).
	Logger *log.Logger
}

// DefaultServerConfig returns a ServerConfig with sensible defaults.
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Address:         ":8899",
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    30 * time.Second,
		MaxRequestSize:  10 * 1024 * 1024, // 10MB
		AllowedOrigins:  []string{"*"},
		EnableRateLimit: false,
		RateLimitRPS:    100,
		RateLimitBurst:  200,
		Logger:          nil,
	}
}

// Server is a JSON-RPC 2.0 server for X1-Nimbus.
type Server struct {
	config   *ServerConfig
	handlers *Handlers
	server   *http.Server
	mu       sync.RWMutex
	running  bool
}

// NewServer creates a new RPC server.
func NewServer(addr string, db accounts.AccountsDB) *Server {
	config := DefaultServerConfig()
	config.Address = addr

	return NewServerWithConfig(config, db)
}

// NewServerWithConfig creates a new RPC server with custom configuration.
func NewServerWithConfig(config *ServerConfig, db accounts.AccountsDB) *Server {
	if config == nil {
		config = DefaultServerConfig()
	}

	s := &Server{
		config:   config,
		handlers: NewHandlers(db),
	}

	return s
}

// Handlers returns the handlers instance for updating state.
func (s *Server) Handlers() *Handlers {
	return s.handlers
}

// Start starts the RPC server.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("server already running")
	}
	s.running = true
	s.mu.Unlock()

	// Build middleware chain
	handler := http.HandlerFunc(s.handleRequest)
	var wrapped http.Handler = handler

	// Apply middleware in reverse order
	middlewares := []Middleware{
		ContentTypeMiddleware(),
		CORSMiddleware(s.config.AllowedOrigins),
	}

	if s.config.Logger != nil {
		middlewares = append(middlewares, LoggingMiddleware(s.config.Logger))
		middlewares = append(middlewares, RecoveryMiddleware(s.config.Logger))
	}

	if s.config.EnableRateLimit {
		middlewares = append(middlewares, RateLimitMiddleware(s.config.RateLimitRPS, s.config.RateLimitBurst))
	}

	wrapped = Chain(handler, middlewares...)

	// Create HTTP server
	mux := http.NewServeMux()
	mux.Handle("/", wrapped)

	s.server = &http.Server{
		Addr:         s.config.Address,
		Handler:      mux,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
	}

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	// Wait for context cancellation or error
	select {
	case err := <-errCh:
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
		return err
	case <-ctx.Done():
		return s.Stop()
	}
}

// Stop gracefully stops the RPC server.
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	s.running = false

	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.server.Shutdown(ctx)
	}

	return nil
}

// IsRunning returns true if the server is running.
func (s *Server) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// handleRequest processes incoming JSON-RPC requests.
func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Only accept POST requests
	if r.Method != http.MethodPost {
		s.writeError(w, nil, NewRPCError(InvalidRequest, "only POST method is allowed"))
		return
	}

	// Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, s.config.MaxRequestSize)

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, nil, NewRPCError(ParseError, "failed to read request body"))
		return
	}

	// Check for batch request
	if len(body) > 0 && body[0] == '[' {
		s.handleBatchRequest(w, body)
		return
	}

	// Handle single request
	response := s.processRequest(body)
	s.writeResponse(w, response)
}

// handleBatchRequest processes a batch of JSON-RPC requests.
func (s *Server) handleBatchRequest(w http.ResponseWriter, body []byte) {
	var requests []json.RawMessage
	if err := json.Unmarshal(body, &requests); err != nil {
		s.writeError(w, nil, NewRPCError(ParseError, "invalid JSON"))
		return
	}

	if len(requests) == 0 {
		s.writeError(w, nil, NewRPCError(InvalidRequest, "empty batch"))
		return
	}

	// Process each request
	responses := make([]RPCResponse, 0, len(requests))
	for _, reqBody := range requests {
		response := s.processRequest(reqBody)
		// Only include responses for requests with IDs (not notifications)
		if response.ID != nil {
			responses = append(responses, response)
		}
	}

	// Write batch response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(responses); err != nil {
		log.Printf("failed to write batch response: %v", err)
	}
}

// processRequest processes a single JSON-RPC request.
func (s *Server) processRequest(body []byte) RPCResponse {
	var request RPCRequest
	if err := json.Unmarshal(body, &request); err != nil {
		return RPCResponse{
			JSONRPC: JSONRPCVersion,
			Error:   NewRPCError(ParseError, "invalid JSON"),
			ID:      nil,
		}
	}

	// Validate JSON-RPC version
	if request.JSONRPC != JSONRPCVersion {
		return RPCResponse{
			JSONRPC: JSONRPCVersion,
			Error:   NewRPCError(InvalidRequest, "invalid jsonrpc version"),
			ID:      request.ID,
		}
	}

	// Get handler for method
	handler := s.handlers.GetHandler(request.Method)
	if handler == nil {
		return RPCResponse{
			JSONRPC: JSONRPCVersion,
			Error:   NewRPCError(MethodNotFound, fmt.Sprintf("method not found: %s", request.Method)),
			ID:      request.ID,
		}
	}

	// Execute handler
	result, rpcErr := handler(request.Params)
	if rpcErr != nil {
		return RPCResponse{
			JSONRPC: JSONRPCVersion,
			Error:   rpcErr,
			ID:      request.ID,
		}
	}

	return RPCResponse{
		JSONRPC: JSONRPCVersion,
		Result:  result,
		ID:      request.ID,
	}
}

// writeResponse writes a JSON-RPC response.
func (s *Server) writeResponse(w http.ResponseWriter, response RPCResponse) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("failed to write response: %v", err)
	}
}

// writeError writes a JSON-RPC error response.
func (s *Server) writeError(w http.ResponseWriter, id interface{}, rpcErr *RPCError) {
	response := RPCResponse{
		JSONRPC: JSONRPCVersion,
		Error:   rpcErr,
		ID:      id,
	}
	s.writeResponse(w, response)
}
