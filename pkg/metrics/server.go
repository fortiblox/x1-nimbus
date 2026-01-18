package metrics

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	// DefaultMetricsAddr is the default address for the metrics server.
	DefaultMetricsAddr = ":9090"
	// DefaultMetricsPath is the default path for the metrics endpoint.
	DefaultMetricsPath = "/metrics"
	// DefaultHealthPath is the default path for the health endpoint.
	DefaultHealthPath = "/health"
	// DefaultReadyPath is the default path for the readiness endpoint.
	DefaultReadyPath = "/ready"
)

// Server is an HTTP server that exposes Prometheus metrics.
type Server struct {
	mu       sync.RWMutex
	server   *http.Server
	metrics  *Metrics
	health   *HealthChecker
	running  bool
	addr     string
	listener net.Listener
}

// ServerOption is a function that configures a Server.
type ServerOption func(*Server)

// WithMetrics sets the metrics instance for the server.
func WithMetrics(m *Metrics) ServerOption {
	return func(s *Server) {
		s.metrics = m
	}
}

// WithHealthChecker sets the health checker for the server.
func WithHealthChecker(h *HealthChecker) ServerOption {
	return func(s *Server) {
		s.health = h
	}
}

// WithAddr sets the address for the server.
func WithAddr(addr string) ServerOption {
	return func(s *Server) {
		s.addr = addr
	}
}

// NewServer creates a new metrics server.
func NewServer(opts ...ServerOption) *Server {
	s := &Server{
		metrics: DefaultMetrics(),
		addr:    DefaultMetricsAddr,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// Start starts the metrics server.
func (s *Server) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("server already running")
	}

	mux := http.NewServeMux()
	mux.HandleFunc(DefaultMetricsPath, s.handleMetrics)
	mux.HandleFunc(DefaultHealthPath, s.handleHealth)
	mux.HandleFunc(DefaultReadyPath, s.handleReady)
	mux.HandleFunc("/", s.handleRoot)

	s.server = &http.Server{
		Addr:              s.addr,
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to listen on %s: %w", s.addr, err)
	}
	s.listener = listener
	s.running = true
	s.mu.Unlock()

	go func() {
		if err := s.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			// Log error but don't block
			fmt.Printf("metrics server error: %v\n", err)
		}
	}()

	return nil
}

// Stop stops the metrics server gracefully.
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	server := s.server
	s.running = false
	s.mu.Unlock()

	if server != nil {
		return server.Shutdown(ctx)
	}
	return nil
}

// Addr returns the address the server is listening on.
func (s *Server) Addr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.addr
}

// IsRunning returns true if the server is running.
func (s *Server) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// handleMetrics handles the /metrics endpoint.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	if s.metrics != nil {
		fmt.Fprint(w, s.metrics.Format())
	}
}

// handleHealth handles the /health endpoint.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if s.health != nil && !s.health.IsHealthy() {
		status := s.health.GetStatus()
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, `{"status":"unhealthy","message":"%s","timestamp":"%s"}`,
			status.Message, status.Timestamp.Format(time.RFC3339))
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"healthy","timestamp":"%s"}`, time.Now().UTC().Format(time.RFC3339))
}

// handleReady handles the /ready endpoint.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if s.health != nil && !s.health.IsReady() {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, `{"ready":false,"timestamp":"%s"}`, time.Now().UTC().Format(time.RFC3339))
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"ready":true,"timestamp":"%s"}`, time.Now().UTC().Format(time.RFC3339))
}

// handleRoot handles the root endpoint.
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head><title>X1-Nimbus Metrics</title></head>
<body>
<h1>X1-Nimbus Verifier Metrics</h1>
<p><a href="/metrics">Metrics</a></p>
<p><a href="/health">Health</a></p>
<p><a href="/ready">Ready</a></p>
</body>
</html>`)
}

// StartMetricsServer starts a metrics server on the specified address.
// This is a convenience function for quick setup.
func StartMetricsServer(addr string) (*Server, error) {
	if addr == "" {
		addr = DefaultMetricsAddr
	}

	server := NewServer(
		WithAddr(addr),
		WithMetrics(DefaultMetrics()),
	)

	if err := server.Start(); err != nil {
		return nil, err
	}

	return server, nil
}

// MetricsHandler returns an http.Handler for the metrics endpoint.
// This can be used to integrate with existing HTTP servers.
func MetricsHandler(m *Metrics) http.Handler {
	if m == nil {
		m = DefaultMetrics()
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, m.Format())
	})
}
