package metrics

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestCounter(t *testing.T) {
	c := NewCounter("test_counter", "Test counter")

	if c.Value() != 0 {
		t.Errorf("expected initial value 0, got %d", c.Value())
	}

	c.Inc()
	if c.Value() != 1 {
		t.Errorf("expected value 1 after Inc, got %d", c.Value())
	}

	c.Add(5)
	if c.Value() != 6 {
		t.Errorf("expected value 6 after Add(5), got %d", c.Value())
	}

	if c.Name() != "test_counter" {
		t.Errorf("expected name 'test_counter', got '%s'", c.Name())
	}

	if c.Type() != TypeCounter {
		t.Errorf("expected type counter, got %s", c.Type())
	}
}

func TestGauge(t *testing.T) {
	g := NewGauge("test_gauge", "Test gauge")

	if g.Value() != 0 {
		t.Errorf("expected initial value 0, got %d", g.Value())
	}

	g.Set(100)
	if g.Value() != 100 {
		t.Errorf("expected value 100, got %d", g.Value())
	}

	g.Inc()
	if g.Value() != 101 {
		t.Errorf("expected value 101, got %d", g.Value())
	}

	g.Dec()
	if g.Value() != 100 {
		t.Errorf("expected value 100, got %d", g.Value())
	}

	g.Add(-50)
	if g.Value() != 50 {
		t.Errorf("expected value 50, got %d", g.Value())
	}

	if g.Type() != TypeGauge {
		t.Errorf("expected type gauge, got %s", g.Type())
	}
}

func TestHistogram(t *testing.T) {
	h := NewHistogram("test_histogram", "Test histogram", []float64{0.1, 0.5, 1.0, 5.0})

	h.Observe(0.05)
	h.Observe(0.3)
	h.Observe(0.7)
	h.Observe(2.0)
	h.Observe(10.0)

	snap := h.Snapshot()

	if snap.Count != 5 {
		t.Errorf("expected count 5, got %d", snap.Count)
	}

	expectedSum := 0.05 + 0.3 + 0.7 + 2.0 + 10.0
	if snap.Sum != expectedSum {
		t.Errorf("expected sum %.2f, got %.2f", expectedSum, snap.Sum)
	}

	// Check bucket counts (cumulative)
	// 0.1 bucket: 0.05 = 1
	// 0.5 bucket: 0.05, 0.3 = 2
	// 1.0 bucket: 0.05, 0.3, 0.7 = 3
	// 5.0 bucket: 0.05, 0.3, 0.7, 2.0 = 4
	expectedBucketCounts := []uint64{1, 2, 3, 4}
	for i, expected := range expectedBucketCounts {
		if snap.Buckets[i].Count != expected {
			t.Errorf("bucket %d: expected count %d, got %d", i, expected, snap.Buckets[i].Count)
		}
	}

	if h.Type() != TypeHistogram {
		t.Errorf("expected type histogram, got %s", h.Type())
	}
}

func TestHistogramObserveDuration(t *testing.T) {
	h := NewHistogram("test_duration", "Test duration", nil)

	d := 100 * time.Millisecond
	h.ObserveDuration(d)

	snap := h.Snapshot()
	if snap.Count != 1 {
		t.Errorf("expected count 1, got %d", snap.Count)
	}

	expectedSum := d.Seconds()
	if snap.Sum != expectedSum {
		t.Errorf("expected sum %.3f, got %.3f", expectedSum, snap.Sum)
	}
}

func TestMetrics(t *testing.T) {
	m := NewMetrics()

	// Test counters
	m.BlocksVerified.Inc()
	m.TransactionsVerified.Add(10)
	m.SignaturesVerified.Add(5)

	if m.BlocksVerified.Value() != 1 {
		t.Errorf("expected blocks verified 1, got %d", m.BlocksVerified.Value())
	}

	if m.TransactionsVerified.Value() != 10 {
		t.Errorf("expected transactions verified 10, got %d", m.TransactionsVerified.Value())
	}

	// Test gauges
	m.CurrentSlot.SetUint64(12345)
	m.SlotsBehind.Set(100)

	if m.CurrentSlot.Value() != 12345 {
		t.Errorf("expected current slot 12345, got %d", m.CurrentSlot.Value())
	}

	// Test histogram
	m.BlockVerifyDuration.Observe(0.5)
	snap := m.BlockVerifyDuration.Snapshot()
	if snap.Count != 1 {
		t.Errorf("expected histogram count 1, got %d", snap.Count)
	}

	// Test format output
	output := m.Format()

	if !strings.Contains(output, "nimbus_blocks_verified_total") {
		t.Error("format output should contain nimbus_blocks_verified_total")
	}

	if !strings.Contains(output, "# HELP") {
		t.Error("format output should contain HELP comments")
	}

	if !strings.Contains(output, "# TYPE") {
		t.Error("format output should contain TYPE comments")
	}
}

func TestMetricsRecordBlockVerification(t *testing.T) {
	m := NewMetrics()

	m.RecordBlockVerification(1000, 50, 100, 500*time.Millisecond)

	if m.BlocksVerified.Value() != 1 {
		t.Errorf("expected blocks verified 1, got %d", m.BlocksVerified.Value())
	}

	if m.TransactionsVerified.Value() != 50 {
		t.Errorf("expected transactions verified 50, got %d", m.TransactionsVerified.Value())
	}

	if m.SignaturesVerified.Value() != 100 {
		t.Errorf("expected signatures verified 100, got %d", m.SignaturesVerified.Value())
	}

	if m.CurrentSlot.Value() != 1000 {
		t.Errorf("expected current slot 1000, got %d", m.CurrentSlot.Value())
	}
}

func TestMetricsUpdateSlotsBehind(t *testing.T) {
	m := NewMetrics()

	m.UpdateSlotsBehind(1000, 900)
	if m.SlotsBehind.Value() != 100 {
		t.Errorf("expected slots behind 100, got %d", m.SlotsBehind.Value())
	}

	m.UpdateSlotsBehind(1000, 1000)
	if m.SlotsBehind.Value() != 0 {
		t.Errorf("expected slots behind 0, got %d", m.SlotsBehind.Value())
	}

	m.UpdateSlotsBehind(1000, 1100)
	if m.SlotsBehind.Value() != 0 {
		t.Errorf("expected slots behind 0 when ahead, got %d", m.SlotsBehind.Value())
	}
}

func TestDefaultMetrics(t *testing.T) {
	m1 := DefaultMetrics()
	m2 := DefaultMetrics()

	if m1 != m2 {
		t.Error("DefaultMetrics should return the same instance")
	}
}

func TestServer(t *testing.T) {
	m := NewMetrics()
	m.BlocksVerified.Add(100)
	m.CurrentSlot.SetUint64(12345)

	server := NewServer(
		WithMetrics(m),
		WithAddr(":0"), // Use random port
	)

	if err := server.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer server.Stop(context.Background())

	if !server.IsRunning() {
		t.Error("server should be running")
	}

	addr := server.Addr()
	if addr == "" {
		t.Error("server should have an address")
	}

	// Test metrics endpoint
	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("failed to get metrics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/plain") {
		t.Errorf("expected content-type text/plain, got %s", contentType)
	}

	// Test health endpoint
	resp, err = http.Get("http://" + addr + "/health")
	if err != nil {
		t.Fatalf("failed to get health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	// Test ready endpoint
	resp, err = http.Get("http://" + addr + "/ready")
	if err != nil {
		t.Fatalf("failed to get ready: %v", err)
	}
	defer resp.Body.Close()

	// Note: ready might return 503 if health checker is not set up
}

func TestRuntimeCollector(t *testing.T) {
	m := NewMetrics()
	rc := NewRuntimeCollector(m, 100*time.Millisecond)

	// Collect once
	rc.Collect()

	// Memory should be > 0
	if m.MemoryBytes.Value() == 0 {
		t.Error("memory bytes should be > 0 after collection")
	}

	// Goroutines should be > 0
	if m.Goroutines.Value() == 0 {
		t.Error("goroutines should be > 0 after collection")
	}

	// Check additional metrics
	if rc.HeapAlloc.Value() == 0 {
		t.Error("heap alloc should be > 0 after collection")
	}
}

func TestDBCollector(t *testing.T) {
	m := NewMetrics()
	dc := NewDBCollector(m, nil, "", 100*time.Millisecond)

	// Collect with no provider should not panic
	dc.Collect()

	// Test with a mock provider
	mockProvider := &mockDBStatsProvider{
		accountsCount: 1000,
		dbSize:        1024 * 1024,
	}
	dc.SetProvider(mockProvider)

	dc.Collect()

	if m.AccountsCount.Value() != 1000 {
		t.Errorf("expected accounts count 1000, got %d", m.AccountsCount.Value())
	}

	if m.DBSizeBytes.Value() != 1024*1024 {
		t.Errorf("expected db size %d, got %d", 1024*1024, m.DBSizeBytes.Value())
	}
}

type mockDBStatsProvider struct {
	accountsCount uint64
	dbSize        int64
}

func (m *mockDBStatsProvider) GetAccountsCount() uint64 {
	return m.accountsCount
}

func (m *mockDBStatsProvider) GetDBSize() int64 {
	return m.dbSize
}

func TestHealthChecker(t *testing.T) {
	m := NewMetrics()
	h := NewHealthChecker(m,
		WithMaxSlotsBehind(100),
		WithMaxMemoryBytes(1024*1024*1024), // 1GB
		WithSlotFreshnessTime(30*time.Second),
	)

	// Initially should be healthy but not ready
	if !h.IsHealthy() {
		t.Error("should be healthy initially")
	}

	// Update slot time
	h.UpdateSlotTime()

	// Set ready
	h.SetReady(true)
	if !h.IsReady() {
		t.Error("should be ready after SetReady(true)")
	}

	// Run health check
	status := h.Check(context.Background())

	if status.Timestamp.IsZero() {
		t.Error("status timestamp should not be zero")
	}

	if status.Uptime == 0 {
		t.Error("status uptime should not be zero")
	}

	// Test slots behind check
	m.SlotsBehind.Set(200)
	status = h.Check(context.Background())

	if status.Healthy {
		t.Error("should be unhealthy when too many slots behind")
	}

	// Reset and test memory check
	m.SlotsBehind.Set(0)
	m.MemoryBytes.Set(2 * 1024 * 1024 * 1024) // 2GB > 1GB threshold
	status = h.Check(context.Background())

	if status.Healthy {
		t.Error("should be unhealthy when memory exceeds threshold")
	}
}

func TestHealthCheckerCustomCheck(t *testing.T) {
	m := NewMetrics()
	h := NewHealthChecker(m)

	// Register custom check
	checkCalled := false
	h.RegisterCheck("custom", func(ctx context.Context) Check {
		checkCalled = true
		return Check{
			Healthy: true,
			Message: "all good",
		}
	})

	h.Check(context.Background())

	if !checkCalled {
		t.Error("custom check should have been called")
	}

	// Test unregister
	h.UnregisterCheck("custom")
	checkCalled = false

	h.Check(context.Background())

	if checkCalled {
		t.Error("custom check should not have been called after unregister")
	}
}

func TestCollectorManager(t *testing.T) {
	m := NewMetrics()
	rc := NewRuntimeCollector(m, 50*time.Millisecond)

	cm := NewCollectorManager()
	cm.Add(rc)

	cm.Start()
	defer cm.Stop()

	// Wait for at least one collection
	time.Sleep(100 * time.Millisecond)

	if m.MemoryBytes.Value() == 0 {
		t.Error("memory should have been collected")
	}
}

func TestDashboardGeneration(t *testing.T) {
	config := DefaultDashboardConfig()
	dashboard, err := GenerateDashboard(config)

	if err != nil {
		t.Fatalf("failed to generate dashboard: %v", err)
	}

	if dashboard.UID != config.UID {
		t.Errorf("expected UID %s, got %s", config.UID, dashboard.UID)
	}

	if dashboard.Title != config.Title {
		t.Errorf("expected title %s, got %s", config.Title, dashboard.Title)
	}

	if len(dashboard.Panels) == 0 {
		t.Error("dashboard should have panels")
	}
}

func TestDashboardJSON(t *testing.T) {
	jsonStr, err := GenerateDashboardJSON(nil)

	if err != nil {
		t.Fatalf("failed to generate dashboard JSON: %v", err)
	}

	if !strings.Contains(jsonStr, "X1-Nimbus Verifier") {
		t.Error("JSON should contain dashboard title")
	}

	if !strings.Contains(jsonStr, "nimbus_blocks_verified_total") {
		t.Error("JSON should contain metric queries")
	}
}

func TestPrometheusConfig(t *testing.T) {
	config := GetPrometheusConfig("localhost:9090")

	if !strings.Contains(config, "x1-nimbus") {
		t.Error("config should contain job name")
	}

	if !strings.Contains(config, "localhost:9090") {
		t.Error("config should contain address")
	}
}

func TestAlertRules(t *testing.T) {
	rules := GetAlertRules()

	if !strings.Contains(rules, "NimbusSlotsBehind") {
		t.Error("rules should contain NimbusSlotsBehind alert")
	}

	if !strings.Contains(rules, "nimbus_slots_behind") {
		t.Error("rules should contain nimbus_slots_behind metric")
	}
}
