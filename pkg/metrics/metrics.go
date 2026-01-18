// Package metrics provides Prometheus-compatible metrics for X1-Nimbus verifier monitoring.
package metrics

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MetricType defines the type of a metric.
type MetricType string

const (
	// TypeCounter is a monotonically increasing counter.
	TypeCounter MetricType = "counter"
	// TypeGauge is a value that can go up and down.
	TypeGauge MetricType = "gauge"
	// TypeHistogram is a histogram with configurable buckets.
	TypeHistogram MetricType = "histogram"
)

// Counter is a thread-safe counter metric.
type Counter struct {
	name  string
	help  string
	value atomic.Uint64
}

// NewCounter creates a new counter metric.
func NewCounter(name, help string) *Counter {
	return &Counter{
		name: name,
		help: help,
	}
}

// Inc increments the counter by 1.
func (c *Counter) Inc() {
	c.value.Add(1)
}

// Add adds the given value to the counter.
func (c *Counter) Add(delta uint64) {
	c.value.Add(delta)
}

// Value returns the current counter value.
func (c *Counter) Value() uint64 {
	return c.value.Load()
}

// Name returns the metric name.
func (c *Counter) Name() string {
	return c.name
}

// Help returns the metric help text.
func (c *Counter) Help() string {
	return c.help
}

// Type returns the metric type.
func (c *Counter) Type() MetricType {
	return TypeCounter
}

// Gauge is a thread-safe gauge metric.
type Gauge struct {
	name  string
	help  string
	value atomic.Int64
}

// NewGauge creates a new gauge metric.
func NewGauge(name, help string) *Gauge {
	return &Gauge{
		name: name,
		help: help,
	}
}

// Set sets the gauge to the given value.
func (g *Gauge) Set(value int64) {
	g.value.Store(value)
}

// SetUint64 sets the gauge to the given unsigned value.
func (g *Gauge) SetUint64(value uint64) {
	g.value.Store(int64(value))
}

// SetFloat64 sets the gauge to the given float value (stored as int64).
func (g *Gauge) SetFloat64(value float64) {
	g.value.Store(int64(value))
}

// Inc increments the gauge by 1.
func (g *Gauge) Inc() {
	g.value.Add(1)
}

// Dec decrements the gauge by 1.
func (g *Gauge) Dec() {
	g.value.Add(-1)
}

// Add adds the given value to the gauge.
func (g *Gauge) Add(delta int64) {
	g.value.Add(delta)
}

// Value returns the current gauge value.
func (g *Gauge) Value() int64 {
	return g.value.Load()
}

// Name returns the metric name.
func (g *Gauge) Name() string {
	return g.name
}

// Help returns the metric help text.
func (g *Gauge) Help() string {
	return g.help
}

// Type returns the metric type.
func (g *Gauge) Type() MetricType {
	return TypeGauge
}

// Histogram is a thread-safe histogram metric.
type Histogram struct {
	mu      sync.RWMutex
	name    string
	help    string
	buckets []float64
	counts  []uint64
	sum     float64
	count   uint64
}

// DefaultHistogramBuckets are the default buckets for histograms.
var DefaultHistogramBuckets = []float64{
	0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
}

// NewHistogram creates a new histogram metric with the given buckets.
func NewHistogram(name, help string, buckets []float64) *Histogram {
	if len(buckets) == 0 {
		buckets = DefaultHistogramBuckets
	}
	// Sort buckets
	sortedBuckets := make([]float64, len(buckets))
	copy(sortedBuckets, buckets)
	sort.Float64s(sortedBuckets)

	return &Histogram{
		name:    name,
		help:    help,
		buckets: sortedBuckets,
		counts:  make([]uint64, len(sortedBuckets)),
	}
}

// Observe records a value in the histogram.
func (h *Histogram) Observe(value float64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.sum += value
	h.count++

	for i, bucket := range h.buckets {
		if value <= bucket {
			h.counts[i]++
		}
	}
}

// ObserveDuration records a duration in seconds.
func (h *Histogram) ObserveDuration(d time.Duration) {
	h.Observe(d.Seconds())
}

// Name returns the metric name.
func (h *Histogram) Name() string {
	return h.name
}

// Help returns the metric help text.
func (h *Histogram) Help() string {
	return h.help
}

// Type returns the metric type.
func (h *Histogram) Type() MetricType {
	return TypeHistogram
}

// Snapshot returns a snapshot of the histogram.
func (h *Histogram) Snapshot() HistogramSnapshot {
	h.mu.RLock()
	defer h.mu.RUnlock()

	snap := HistogramSnapshot{
		Buckets: make([]HistogramBucket, len(h.buckets)),
		Sum:     h.sum,
		Count:   h.count,
	}

	for i, bucket := range h.buckets {
		snap.Buckets[i] = HistogramBucket{
			UpperBound: bucket,
			Count:      h.counts[i],
		}
	}

	return snap
}

// HistogramSnapshot is a point-in-time snapshot of a histogram.
type HistogramSnapshot struct {
	Buckets []HistogramBucket
	Sum     float64
	Count   uint64
}

// HistogramBucket represents a single bucket in a histogram.
type HistogramBucket struct {
	UpperBound float64
	Count      uint64
}

// Metric is the interface for all metrics.
type Metric interface {
	Name() string
	Help() string
	Type() MetricType
}

// Metrics holds all metrics for the X1-Nimbus verifier.
type Metrics struct {
	mu      sync.RWMutex
	metrics map[string]Metric

	// Counters
	BlocksVerified       *Counter
	TransactionsVerified *Counter
	SignaturesVerified   *Counter
	ErrorsTotal          *Counter

	// Gauges
	CurrentSlot   *Gauge
	SlotsBehind   *Gauge
	AccountsCount *Gauge
	DBSizeBytes   *Gauge
	MemoryBytes   *Gauge
	Goroutines    *Gauge

	// Histograms
	BlockVerifyDuration *Histogram
}

// NewMetrics creates a new Metrics instance with all metrics initialized.
func NewMetrics() *Metrics {
	m := &Metrics{
		metrics: make(map[string]Metric),

		// Counters
		BlocksVerified:       NewCounter("nimbus_blocks_verified_total", "Total number of blocks verified"),
		TransactionsVerified: NewCounter("nimbus_transactions_verified_total", "Total number of transactions verified"),
		SignaturesVerified:   NewCounter("nimbus_signatures_verified_total", "Total number of signatures verified"),
		ErrorsTotal:          NewCounter("nimbus_errors_total", "Total number of errors encountered"),

		// Gauges
		CurrentSlot:   NewGauge("nimbus_current_slot", "Current verified slot number"),
		SlotsBehind:   NewGauge("nimbus_slots_behind", "Number of slots behind the network tip"),
		AccountsCount: NewGauge("nimbus_accounts_count", "Total number of accounts in the database"),
		DBSizeBytes:   NewGauge("nimbus_db_size_bytes", "Database size in bytes"),
		MemoryBytes:   NewGauge("nimbus_memory_bytes", "Memory usage in bytes"),
		Goroutines:    NewGauge("nimbus_goroutines", "Number of active goroutines"),

		// Histograms
		BlockVerifyDuration: NewHistogram(
			"nimbus_block_verify_duration_seconds",
			"Block verification duration in seconds",
			[]float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0},
		),
	}

	// Register all metrics
	m.register(m.BlocksVerified)
	m.register(m.TransactionsVerified)
	m.register(m.SignaturesVerified)
	m.register(m.ErrorsTotal)
	m.register(m.CurrentSlot)
	m.register(m.SlotsBehind)
	m.register(m.AccountsCount)
	m.register(m.DBSizeBytes)
	m.register(m.MemoryBytes)
	m.register(m.Goroutines)
	m.register(m.BlockVerifyDuration)

	return m
}

// register adds a metric to the internal registry.
func (m *Metrics) register(metric Metric) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metrics[metric.Name()] = metric
}

// Register registers all metrics (for compatibility).
func (m *Metrics) Register() {
	// All metrics are already registered in NewMetrics
}

// Get returns a metric by name.
func (m *Metrics) Get(name string) Metric {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.metrics[name]
}

// All returns all registered metrics.
func (m *Metrics) All() map[string]Metric {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string]Metric, len(m.metrics))
	for k, v := range m.metrics {
		result[k] = v
	}
	return result
}

// Format formats all metrics in Prometheus text format.
func (m *Metrics) Format() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var sb strings.Builder

	// Sort metric names for consistent output
	names := make([]string, 0, len(m.metrics))
	for name := range m.metrics {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		metric := m.metrics[name]
		sb.WriteString(formatMetric(metric))
		sb.WriteString("\n")
	}

	return sb.String()
}

// formatMetric formats a single metric in Prometheus text format.
func formatMetric(metric Metric) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# HELP %s %s\n", metric.Name(), metric.Help()))
	sb.WriteString(fmt.Sprintf("# TYPE %s %s\n", metric.Name(), metric.Type()))

	switch m := metric.(type) {
	case *Counter:
		sb.WriteString(fmt.Sprintf("%s %d\n", m.Name(), m.Value()))
	case *Gauge:
		sb.WriteString(fmt.Sprintf("%s %d\n", m.Name(), m.Value()))
	case *Histogram:
		snap := m.Snapshot()
		cumulative := uint64(0)
		for _, bucket := range snap.Buckets {
			cumulative += bucket.Count
			sb.WriteString(fmt.Sprintf("%s_bucket{le=\"%.3f\"} %d\n", m.Name(), bucket.UpperBound, cumulative))
		}
		sb.WriteString(fmt.Sprintf("%s_bucket{le=\"+Inf\"} %d\n", m.Name(), snap.Count))
		sb.WriteString(fmt.Sprintf("%s_sum %.6f\n", m.Name(), snap.Sum))
		sb.WriteString(fmt.Sprintf("%s_count %d\n", m.Name(), snap.Count))
	}

	return sb.String()
}

// RecordBlockVerification records metrics for a verified block.
func (m *Metrics) RecordBlockVerification(slot uint64, txCount uint64, sigCount uint64, duration time.Duration) {
	m.BlocksVerified.Inc()
	m.TransactionsVerified.Add(txCount)
	m.SignaturesVerified.Add(sigCount)
	m.CurrentSlot.SetUint64(slot)
	m.BlockVerifyDuration.ObserveDuration(duration)
}

// UpdateSlotsBehind updates the slots behind metric.
func (m *Metrics) UpdateSlotsBehind(networkTip uint64, currentSlot uint64) {
	if networkTip > currentSlot {
		m.SlotsBehind.SetUint64(networkTip - currentSlot)
	} else {
		m.SlotsBehind.Set(0)
	}
}

// Global default metrics instance.
var defaultMetrics *Metrics
var defaultMetricsOnce sync.Once

// DefaultMetrics returns the global default metrics instance.
func DefaultMetrics() *Metrics {
	defaultMetricsOnce.Do(func() {
		defaultMetrics = NewMetrics()
	})
	return defaultMetrics
}
