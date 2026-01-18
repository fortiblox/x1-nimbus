package metrics

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Collector is an interface for metrics collectors.
type Collector interface {
	// Collect collects metrics.
	Collect()
	// Start starts the collector.
	Start(ctx context.Context)
	// Stop stops the collector.
	Stop()
}

// RuntimeCollector collects Go runtime statistics.
type RuntimeCollector struct {
	mu       sync.RWMutex
	metrics  *Metrics
	interval time.Duration
	running  atomic.Bool
	stopCh   chan struct{}

	// Additional runtime metrics
	HeapAlloc      *Gauge
	HeapInuse      *Gauge
	HeapObjects    *Gauge
	StackInuse     *Gauge
	GCPauseNs      *Gauge
	NumGC          *Gauge
	NumForcedGC    *Gauge
	GCCPUFraction  *Gauge
	LastGCPauseNs  *Gauge
}

// NewRuntimeCollector creates a new runtime collector.
func NewRuntimeCollector(m *Metrics, interval time.Duration) *RuntimeCollector {
	if interval <= 0 {
		interval = 15 * time.Second
	}

	rc := &RuntimeCollector{
		metrics:  m,
		interval: interval,
		stopCh:   make(chan struct{}),

		HeapAlloc:     NewGauge("nimbus_runtime_heap_alloc_bytes", "Heap allocation in bytes"),
		HeapInuse:     NewGauge("nimbus_runtime_heap_inuse_bytes", "Heap in use in bytes"),
		HeapObjects:   NewGauge("nimbus_runtime_heap_objects", "Number of allocated heap objects"),
		StackInuse:    NewGauge("nimbus_runtime_stack_inuse_bytes", "Stack in use in bytes"),
		GCPauseNs:     NewGauge("nimbus_runtime_gc_pause_total_ns", "Total GC pause time in nanoseconds"),
		NumGC:         NewGauge("nimbus_runtime_gc_completed_cycles", "Number of completed GC cycles"),
		NumForcedGC:   NewGauge("nimbus_runtime_gc_forced_cycles", "Number of forced GC cycles"),
		GCCPUFraction: NewGauge("nimbus_runtime_gc_cpu_fraction", "Fraction of CPU time used by GC (scaled by 1e6)"),
		LastGCPauseNs: NewGauge("nimbus_runtime_gc_last_pause_ns", "Last GC pause duration in nanoseconds"),
	}

	return rc
}

// Collect collects runtime metrics.
func (rc *RuntimeCollector) Collect() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Update core metrics
	if rc.metrics != nil {
		rc.metrics.MemoryBytes.SetUint64(memStats.Alloc)
		rc.metrics.Goroutines.SetUint64(uint64(runtime.NumGoroutine()))
	}

	// Update additional metrics
	rc.HeapAlloc.SetUint64(memStats.HeapAlloc)
	rc.HeapInuse.SetUint64(memStats.HeapInuse)
	rc.HeapObjects.SetUint64(memStats.HeapObjects)
	rc.StackInuse.SetUint64(memStats.StackInuse)
	rc.GCPauseNs.SetUint64(memStats.PauseTotalNs)
	rc.NumGC.SetUint64(uint64(memStats.NumGC))
	rc.NumForcedGC.SetUint64(uint64(memStats.NumForcedGC))
	// Scale GCCPUFraction by 1e6 for better precision in int64
	rc.GCCPUFraction.SetFloat64(memStats.GCCPUFraction * 1e6)

	// Get last GC pause time
	if memStats.NumGC > 0 {
		lastPauseIdx := (memStats.NumGC + 255) % 256
		rc.LastGCPauseNs.SetUint64(memStats.PauseNs[lastPauseIdx])
	}
}

// Start starts periodic collection.
func (rc *RuntimeCollector) Start(ctx context.Context) {
	if rc.running.Swap(true) {
		return // Already running
	}

	go func() {
		ticker := time.NewTicker(rc.interval)
		defer ticker.Stop()

		// Collect immediately
		rc.Collect()

		for {
			select {
			case <-ctx.Done():
				rc.running.Store(false)
				return
			case <-rc.stopCh:
				rc.running.Store(false)
				return
			case <-ticker.C:
				rc.Collect()
			}
		}
	}()
}

// Stop stops the collector.
func (rc *RuntimeCollector) Stop() {
	if rc.running.Load() {
		close(rc.stopCh)
	}
}

// AdditionalMetrics returns additional runtime metrics for registration.
func (rc *RuntimeCollector) AdditionalMetrics() []Metric {
	return []Metric{
		rc.HeapAlloc,
		rc.HeapInuse,
		rc.HeapObjects,
		rc.StackInuse,
		rc.GCPauseNs,
		rc.NumGC,
		rc.NumForcedGC,
		rc.GCCPUFraction,
		rc.LastGCPauseNs,
	}
}

// DBStatsProvider is an interface for providing database statistics.
type DBStatsProvider interface {
	// GetAccountsCount returns the number of accounts.
	GetAccountsCount() uint64
	// GetDBSize returns the database size in bytes (optional, return 0 if unknown).
	GetDBSize() int64
}

// DBCollector collects database statistics.
type DBCollector struct {
	mu       sync.RWMutex
	metrics  *Metrics
	provider DBStatsProvider
	dbPath   string
	interval time.Duration
	running  atomic.Bool
	stopCh   chan struct{}

	// Additional DB metrics
	DBReadLatency  *Histogram
	DBWriteLatency *Histogram
	DBCompactions  *Counter
}

// NewDBCollector creates a new database collector.
func NewDBCollector(m *Metrics, provider DBStatsProvider, dbPath string, interval time.Duration) *DBCollector {
	if interval <= 0 {
		interval = 30 * time.Second
	}

	return &DBCollector{
		metrics:  m,
		provider: provider,
		dbPath:   dbPath,
		interval: interval,
		stopCh:   make(chan struct{}),

		DBReadLatency:  NewHistogram("nimbus_db_read_latency_seconds", "Database read latency in seconds", nil),
		DBWriteLatency: NewHistogram("nimbus_db_write_latency_seconds", "Database write latency in seconds", nil),
		DBCompactions:  NewCounter("nimbus_db_compactions_total", "Total number of database compactions"),
	}
}

// Collect collects database metrics.
func (dc *DBCollector) Collect() {
	if dc.provider != nil {
		// Update accounts count
		count := dc.provider.GetAccountsCount()
		if dc.metrics != nil {
			dc.metrics.AccountsCount.SetUint64(count)
		}

		// Update DB size from provider
		dbSize := dc.provider.GetDBSize()
		if dbSize > 0 && dc.metrics != nil {
			dc.metrics.DBSizeBytes.Set(dbSize)
		}
	}

	// Calculate directory size if path is provided and provider didn't give size
	if dc.dbPath != "" && dc.metrics != nil {
		size := dc.calculateDirSize(dc.dbPath)
		if size > 0 {
			dc.metrics.DBSizeBytes.Set(size)
		}
	}
}

// calculateDirSize calculates the total size of files in a directory.
func (dc *DBCollector) calculateDirSize(path string) int64 {
	var size int64

	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})

	if err != nil {
		return 0
	}

	return size
}

// Start starts periodic collection.
func (dc *DBCollector) Start(ctx context.Context) {
	if dc.running.Swap(true) {
		return // Already running
	}

	go func() {
		ticker := time.NewTicker(dc.interval)
		defer ticker.Stop()

		// Collect immediately
		dc.Collect()

		for {
			select {
			case <-ctx.Done():
				dc.running.Store(false)
				return
			case <-dc.stopCh:
				dc.running.Store(false)
				return
			case <-ticker.C:
				dc.Collect()
			}
		}
	}()
}

// Stop stops the collector.
func (dc *DBCollector) Stop() {
	if dc.running.Load() {
		close(dc.stopCh)
	}
}

// SetProvider sets the database stats provider.
func (dc *DBCollector) SetProvider(provider DBStatsProvider) {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	dc.provider = provider
}

// RecordReadLatency records a database read latency.
func (dc *DBCollector) RecordReadLatency(d time.Duration) {
	dc.DBReadLatency.ObserveDuration(d)
}

// RecordWriteLatency records a database write latency.
func (dc *DBCollector) RecordWriteLatency(d time.Duration) {
	dc.DBWriteLatency.ObserveDuration(d)
}

// AdditionalMetrics returns additional DB metrics for registration.
func (dc *DBCollector) AdditionalMetrics() []Metric {
	return []Metric{
		dc.DBReadLatency,
		dc.DBWriteLatency,
		dc.DBCompactions,
	}
}

// SlotCollector collects slot-related metrics.
type SlotCollector struct {
	mu           sync.RWMutex
	metrics      *Metrics
	getNetworkTip func() uint64
	interval     time.Duration
	running      atomic.Bool
	stopCh       chan struct{}
}

// NewSlotCollector creates a new slot collector.
func NewSlotCollector(m *Metrics, getNetworkTip func() uint64, interval time.Duration) *SlotCollector {
	if interval <= 0 {
		interval = 5 * time.Second
	}

	return &SlotCollector{
		metrics:       m,
		getNetworkTip: getNetworkTip,
		interval:      interval,
		stopCh:        make(chan struct{}),
	}
}

// Collect collects slot metrics.
func (sc *SlotCollector) Collect() {
	if sc.getNetworkTip == nil || sc.metrics == nil {
		return
	}

	networkTip := sc.getNetworkTip()
	currentSlot := uint64(sc.metrics.CurrentSlot.Value())
	sc.metrics.UpdateSlotsBehind(networkTip, currentSlot)
}

// Start starts periodic collection.
func (sc *SlotCollector) Start(ctx context.Context) {
	if sc.running.Swap(true) {
		return // Already running
	}

	go func() {
		ticker := time.NewTicker(sc.interval)
		defer ticker.Stop()

		// Collect immediately
		sc.Collect()

		for {
			select {
			case <-ctx.Done():
				sc.running.Store(false)
				return
			case <-sc.stopCh:
				sc.running.Store(false)
				return
			case <-ticker.C:
				sc.Collect()
			}
		}
	}()
}

// Stop stops the collector.
func (sc *SlotCollector) Stop() {
	if sc.running.Load() {
		close(sc.stopCh)
	}
}

// SetNetworkTipProvider sets the function to get the network tip.
func (sc *SlotCollector) SetNetworkTipProvider(fn func() uint64) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.getNetworkTip = fn
}

// CollectorManager manages multiple collectors.
type CollectorManager struct {
	mu         sync.RWMutex
	collectors []Collector
	ctx        context.Context
	cancel     context.CancelFunc
	running    bool
}

// NewCollectorManager creates a new collector manager.
func NewCollectorManager() *CollectorManager {
	return &CollectorManager{
		collectors: make([]Collector, 0),
	}
}

// Add adds a collector to the manager.
func (cm *CollectorManager) Add(c Collector) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.collectors = append(cm.collectors, c)
}

// Start starts all collectors.
func (cm *CollectorManager) Start() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.running {
		return
	}

	cm.ctx, cm.cancel = context.WithCancel(context.Background())
	cm.running = true

	for _, c := range cm.collectors {
		c.Start(cm.ctx)
	}
}

// Stop stops all collectors.
func (cm *CollectorManager) Stop() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if !cm.running {
		return
	}

	cm.cancel()
	cm.running = false

	for _, c := range cm.collectors {
		c.Stop()
	}
}

// CollectAll triggers collection on all collectors.
func (cm *CollectorManager) CollectAll() {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	for _, c := range cm.collectors {
		c.Collect()
	}
}
