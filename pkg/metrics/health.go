package metrics

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// HealthStatus represents the health status of the system.
type HealthStatus struct {
	Healthy     bool              `json:"healthy"`
	Ready       bool              `json:"ready"`
	Message     string            `json:"message,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
	Checks      map[string]Check  `json:"checks,omitempty"`
	Uptime      time.Duration     `json:"uptime"`
}

// Check represents an individual health check result.
type Check struct {
	Name    string        `json:"name"`
	Healthy bool          `json:"healthy"`
	Message string        `json:"message,omitempty"`
	Latency time.Duration `json:"latency,omitempty"`
}

// HealthCheckFunc is a function that performs a health check.
type HealthCheckFunc func(ctx context.Context) Check

// HealthChecker performs health checks on the system.
type HealthChecker struct {
	mu        sync.RWMutex
	checks    map[string]HealthCheckFunc
	status    atomic.Pointer[HealthStatus]
	metrics   *Metrics
	startTime time.Time
	interval  time.Duration
	running   atomic.Bool
	stopCh    chan struct{}

	// Configuration
	maxSlotsBehind    uint64
	maxMemoryBytes    uint64
	slotFreshnessTime time.Duration

	// State for checks
	lastSlotTime atomic.Int64
}

// HealthCheckerOption is a function that configures a HealthChecker.
type HealthCheckerOption func(*HealthChecker)

// WithMaxSlotsBehind sets the maximum slots behind threshold.
func WithMaxSlotsBehind(n uint64) HealthCheckerOption {
	return func(h *HealthChecker) {
		h.maxSlotsBehind = n
	}
}

// WithMaxMemoryBytes sets the maximum memory threshold.
func WithMaxMemoryBytes(n uint64) HealthCheckerOption {
	return func(h *HealthChecker) {
		h.maxMemoryBytes = n
	}
}

// WithSlotFreshnessTime sets the maximum time since last slot update.
func WithSlotFreshnessTime(d time.Duration) HealthCheckerOption {
	return func(h *HealthChecker) {
		h.slotFreshnessTime = d
	}
}

// WithHealthCheckInterval sets the health check interval.
func WithHealthCheckInterval(d time.Duration) HealthCheckerOption {
	return func(h *HealthChecker) {
		h.interval = d
	}
}

// NewHealthChecker creates a new health checker.
func NewHealthChecker(m *Metrics, opts ...HealthCheckerOption) *HealthChecker {
	h := &HealthChecker{
		checks:            make(map[string]HealthCheckFunc),
		metrics:           m,
		startTime:         time.Now(),
		interval:          10 * time.Second,
		stopCh:            make(chan struct{}),
		maxSlotsBehind:    1000,
		maxMemoryBytes:    8 * 1024 * 1024 * 1024, // 8GB
		slotFreshnessTime: 60 * time.Second,
	}

	for _, opt := range opts {
		opt(h)
	}

	// Set initial status
	initialStatus := &HealthStatus{
		Healthy:   true,
		Ready:     false,
		Timestamp: time.Now(),
		Uptime:    0,
	}
	h.status.Store(initialStatus)

	// Register default checks
	h.RegisterCheck("slot_freshness", h.checkSlotFreshness)
	h.RegisterCheck("memory_usage", h.checkMemoryUsage)
	h.RegisterCheck("slots_behind", h.checkSlotsBehind)

	return h
}

// RegisterCheck registers a health check.
func (h *HealthChecker) RegisterCheck(name string, check HealthCheckFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checks[name] = check
}

// UnregisterCheck removes a health check.
func (h *HealthChecker) UnregisterCheck(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.checks, name)
}

// IsHealthy returns true if the system is healthy.
func (h *HealthChecker) IsHealthy() bool {
	status := h.status.Load()
	if status == nil {
		return true
	}
	return status.Healthy
}

// IsReady returns true if the system is ready to serve.
func (h *HealthChecker) IsReady() bool {
	status := h.status.Load()
	if status == nil {
		return false
	}
	return status.Ready
}

// GetStatus returns the current health status.
func (h *HealthChecker) GetStatus() *HealthStatus {
	status := h.status.Load()
	if status == nil {
		return &HealthStatus{
			Healthy:   true,
			Ready:     false,
			Timestamp: time.Now(),
		}
	}
	return status
}

// SetReady sets the ready state.
func (h *HealthChecker) SetReady(ready bool) {
	current := h.status.Load()
	if current == nil {
		current = &HealthStatus{}
	}
	newStatus := *current
	newStatus.Ready = ready
	newStatus.Timestamp = time.Now()
	h.status.Store(&newStatus)
}

// UpdateSlotTime updates the last slot update time.
func (h *HealthChecker) UpdateSlotTime() {
	h.lastSlotTime.Store(time.Now().UnixNano())
}

// Check runs all health checks and updates the status.
func (h *HealthChecker) Check(ctx context.Context) *HealthStatus {
	h.mu.RLock()
	checks := make(map[string]HealthCheckFunc, len(h.checks))
	for name, fn := range h.checks {
		checks[name] = fn
	}
	h.mu.RUnlock()

	status := &HealthStatus{
		Healthy:   true,
		Ready:     true,
		Timestamp: time.Now(),
		Checks:    make(map[string]Check, len(checks)),
		Uptime:    time.Since(h.startTime),
	}

	var messages []string

	for name, checkFn := range checks {
		result := checkFn(ctx)
		result.Name = name
		status.Checks[name] = result

		if !result.Healthy {
			status.Healthy = false
			status.Ready = false
			if result.Message != "" {
				messages = append(messages, result.Message)
			}
		}
	}

	if len(messages) > 0 {
		status.Message = messages[0]
		if len(messages) > 1 {
			status.Message += " (and more)"
		}
	}

	h.status.Store(status)
	return status
}

// checkSlotFreshness checks if slots are being received recently.
func (h *HealthChecker) checkSlotFreshness(ctx context.Context) Check {
	lastTime := h.lastSlotTime.Load()
	if lastTime == 0 {
		// No slot received yet, might be starting up
		if time.Since(h.startTime) < h.slotFreshnessTime*2 {
			return Check{
				Healthy: true,
				Message: "warming up",
			}
		}
		return Check{
			Healthy: false,
			Message: "no slots received",
		}
	}

	elapsed := time.Since(time.Unix(0, lastTime))
	if elapsed > h.slotFreshnessTime {
		return Check{
			Healthy: false,
			Message: "slot data is stale",
			Latency: elapsed,
		}
	}

	return Check{
		Healthy: true,
		Latency: elapsed,
	}
}

// checkMemoryUsage checks if memory usage is within limits.
func (h *HealthChecker) checkMemoryUsage(ctx context.Context) Check {
	if h.metrics == nil {
		return Check{Healthy: true}
	}

	memBytes := uint64(h.metrics.MemoryBytes.Value())
	if memBytes > h.maxMemoryBytes {
		return Check{
			Healthy: false,
			Message: "memory usage exceeds threshold",
		}
	}

	// Warn if above 80%
	threshold80 := h.maxMemoryBytes * 80 / 100
	if memBytes > threshold80 {
		return Check{
			Healthy: true,
			Message: "memory usage above 80%",
		}
	}

	return Check{Healthy: true}
}

// checkSlotsBehind checks if we're too far behind the network.
func (h *HealthChecker) checkSlotsBehind(ctx context.Context) Check {
	if h.metrics == nil {
		return Check{Healthy: true}
	}

	slotsBehind := uint64(h.metrics.SlotsBehind.Value())
	if slotsBehind > h.maxSlotsBehind {
		return Check{
			Healthy: false,
			Message: "too many slots behind network tip",
		}
	}

	return Check{Healthy: true}
}

// Start starts the periodic health checks.
func (h *HealthChecker) Start(ctx context.Context) {
	if h.running.Swap(true) {
		return
	}

	go func() {
		ticker := time.NewTicker(h.interval)
		defer ticker.Stop()

		// Run initial check
		h.Check(ctx)

		for {
			select {
			case <-ctx.Done():
				h.running.Store(false)
				return
			case <-h.stopCh:
				h.running.Store(false)
				return
			case <-ticker.C:
				h.Check(ctx)
			}
		}
	}()
}

// Stop stops the health checker.
func (h *HealthChecker) Stop() {
	if h.running.Load() {
		close(h.stopCh)
	}
}

// DBHealthCheckProvider is an interface for database health checking.
type DBHealthCheckProvider interface {
	// Ping checks if the database is reachable.
	Ping() error
}

// RegisterDBCheck registers a database health check.
func (h *HealthChecker) RegisterDBCheck(provider DBHealthCheckProvider) {
	h.RegisterCheck("database", func(ctx context.Context) Check {
		if provider == nil {
			return Check{
				Healthy: false,
				Message: "no database provider",
			}
		}

		start := time.Now()
		err := provider.Ping()
		latency := time.Since(start)

		if err != nil {
			return Check{
				Healthy: false,
				Message: "database connection failed: " + err.Error(),
				Latency: latency,
			}
		}

		return Check{
			Healthy: true,
			Latency: latency,
		}
	})
}

// LivenessProbe returns a simple liveness check result.
func (h *HealthChecker) LivenessProbe() bool {
	// Liveness: is the process running?
	return true
}

// ReadinessProbe returns the readiness check result.
func (h *HealthChecker) ReadinessProbe() bool {
	return h.IsReady()
}
