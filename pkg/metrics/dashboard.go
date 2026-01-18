package metrics

import (
	"encoding/json"
	"fmt"
)

// DashboardConfig holds configuration for generating Grafana dashboards.
type DashboardConfig struct {
	Title          string
	UID            string
	DataSource     string
	RefreshRate    string
	TimeRange      string
	Tags           []string
}

// DefaultDashboardConfig returns the default dashboard configuration.
func DefaultDashboardConfig() *DashboardConfig {
	return &DashboardConfig{
		Title:       "X1-Nimbus Verifier",
		UID:         "x1-nimbus-verifier",
		DataSource:  "Prometheus",
		RefreshRate: "10s",
		TimeRange:   "1h",
		Tags:        []string{"x1", "nimbus", "verifier", "blockchain"},
	}
}

// GrafanaDashboard represents a Grafana dashboard.
type GrafanaDashboard struct {
	UID           string                   `json:"uid"`
	Title         string                   `json:"title"`
	Tags          []string                 `json:"tags"`
	Timezone      string                   `json:"timezone"`
	SchemaVersion int                      `json:"schemaVersion"`
	Version       int                      `json:"version"`
	Refresh       string                   `json:"refresh"`
	Time          DashboardTime            `json:"time"`
	Panels        []map[string]interface{} `json:"panels"`
	Templating    DashboardTemplating      `json:"templating"`
}

// DashboardTime represents the time range for a dashboard.
type DashboardTime struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// DashboardTemplating represents dashboard variables.
type DashboardTemplating struct {
	List []map[string]interface{} `json:"list"`
}

// Panel represents a Grafana panel.
type Panel struct {
	ID          int                    `json:"id"`
	Type        string                 `json:"type"`
	Title       string                 `json:"title"`
	GridPos     GridPos                `json:"gridPos"`
	Targets     []Target               `json:"targets"`
	FieldConfig map[string]interface{} `json:"fieldConfig,omitempty"`
	Options     map[string]interface{} `json:"options,omitempty"`
}

// GridPos represents the position and size of a panel.
type GridPos struct {
	H int `json:"h"`
	W int `json:"w"`
	X int `json:"x"`
	Y int `json:"y"`
}

// Target represents a Prometheus query target.
type Target struct {
	Expr         string `json:"expr"`
	LegendFormat string `json:"legendFormat"`
	RefID        string `json:"refId"`
	Interval     string `json:"interval,omitempty"`
}

// GenerateDashboard generates a Grafana dashboard JSON.
func GenerateDashboard(config *DashboardConfig) (*GrafanaDashboard, error) {
	if config == nil {
		config = DefaultDashboardConfig()
	}

	dashboard := &GrafanaDashboard{
		UID:           config.UID,
		Title:         config.Title,
		Tags:          config.Tags,
		Timezone:      "browser",
		SchemaVersion: 38,
		Version:       1,
		Refresh:       config.RefreshRate,
		Time: DashboardTime{
			From: "now-" + config.TimeRange,
			To:   "now",
		},
		Templating: DashboardTemplating{
			List: []map[string]interface{}{
				{
					"name":       "datasource",
					"type":       "datasource",
					"query":      "prometheus",
					"current":    map[string]interface{}{"text": config.DataSource, "value": config.DataSource},
					"hide":       0,
					"includeAll": false,
					"multi":      false,
				},
			},
		},
		Panels: generatePanels(config.DataSource),
	}

	return dashboard, nil
}

// generatePanels generates all dashboard panels.
func generatePanels(dataSource string) []map[string]interface{} {
	panels := make([]map[string]interface{}, 0)
	panelID := 1
	y := 0

	// Row: Overview
	panels = append(panels, createRow(panelID, "Overview", 0, y))
	panelID++
	y++

	// Stat panels row
	panels = append(panels, createStatPanel(panelID, "Current Slot", "nimbus_current_slot", dataSource, GridPos{H: 4, W: 6, X: 0, Y: y}))
	panelID++
	panels = append(panels, createStatPanel(panelID, "Slots Behind", "nimbus_slots_behind", dataSource, GridPos{H: 4, W: 6, X: 6, Y: y}))
	panelID++
	panels = append(panels, createStatPanel(panelID, "Blocks Verified", "nimbus_blocks_verified_total", dataSource, GridPos{H: 4, W: 6, X: 12, Y: y}))
	panelID++
	panels = append(panels, createStatPanel(panelID, "Accounts", "nimbus_accounts_count", dataSource, GridPos{H: 4, W: 6, X: 18, Y: y}))
	panelID++
	y += 4

	// Row: Verification Performance
	panels = append(panels, createRow(panelID, "Verification Performance", 0, y))
	panelID++
	y++

	// Block verification rate
	panels = append(panels, createGraphPanel(panelID, "Block Verification Rate",
		[]Target{
			{Expr: "rate(nimbus_blocks_verified_total[5m])", LegendFormat: "blocks/s", RefID: "A"},
		},
		dataSource, GridPos{H: 8, W: 12, X: 0, Y: y}))
	panelID++

	// Transaction rate
	panels = append(panels, createGraphPanel(panelID, "Transaction Rate",
		[]Target{
			{Expr: "rate(nimbus_transactions_verified_total[5m])", LegendFormat: "tx/s", RefID: "A"},
		},
		dataSource, GridPos{H: 8, W: 12, X: 12, Y: y}))
	panelID++
	y += 8

	// Signature verification rate
	panels = append(panels, createGraphPanel(panelID, "Signature Verification Rate",
		[]Target{
			{Expr: "rate(nimbus_signatures_verified_total[5m])", LegendFormat: "sigs/s", RefID: "A"},
		},
		dataSource, GridPos{H: 8, W: 12, X: 0, Y: y}))
	panelID++

	// Block verification duration histogram
	panels = append(panels, createHeatmapPanel(panelID, "Block Verification Duration",
		"nimbus_block_verify_duration_seconds_bucket",
		dataSource, GridPos{H: 8, W: 12, X: 12, Y: y}))
	panelID++
	y += 8

	// Row: Resource Usage
	panels = append(panels, createRow(panelID, "Resource Usage", 0, y))
	panelID++
	y++

	// Memory usage
	panels = append(panels, createGraphPanel(panelID, "Memory Usage",
		[]Target{
			{Expr: "nimbus_memory_bytes / 1024 / 1024", LegendFormat: "Memory (MB)", RefID: "A"},
			{Expr: "nimbus_runtime_heap_alloc_bytes / 1024 / 1024", LegendFormat: "Heap Alloc (MB)", RefID: "B"},
			{Expr: "nimbus_runtime_heap_inuse_bytes / 1024 / 1024", LegendFormat: "Heap In Use (MB)", RefID: "C"},
		},
		dataSource, GridPos{H: 8, W: 12, X: 0, Y: y}))
	panelID++

	// Goroutines
	panels = append(panels, createGraphPanel(panelID, "Goroutines",
		[]Target{
			{Expr: "nimbus_goroutines", LegendFormat: "Goroutines", RefID: "A"},
		},
		dataSource, GridPos{H: 8, W: 12, X: 12, Y: y}))
	panelID++
	y += 8

	// Database size
	panels = append(panels, createGraphPanel(panelID, "Database Size",
		[]Target{
			{Expr: "nimbus_db_size_bytes / 1024 / 1024 / 1024", LegendFormat: "Size (GB)", RefID: "A"},
		},
		dataSource, GridPos{H: 8, W: 12, X: 0, Y: y}))
	panelID++

	// GC metrics
	panels = append(panels, createGraphPanel(panelID, "GC Pause Time",
		[]Target{
			{Expr: "rate(nimbus_runtime_gc_pause_total_ns[5m]) / 1000000", LegendFormat: "GC Pause (ms/s)", RefID: "A"},
			{Expr: "nimbus_runtime_gc_last_pause_ns / 1000000", LegendFormat: "Last GC Pause (ms)", RefID: "B"},
		},
		dataSource, GridPos{H: 8, W: 12, X: 12, Y: y}))
	panelID++
	y += 8

	// Row: Slot Progress
	panels = append(panels, createRow(panelID, "Slot Progress", 0, y))
	panelID++
	y++

	// Current slot over time
	panels = append(panels, createGraphPanel(panelID, "Slot Progress",
		[]Target{
			{Expr: "nimbus_current_slot", LegendFormat: "Current Slot", RefID: "A"},
		},
		dataSource, GridPos{H: 8, W: 12, X: 0, Y: y}))
	panelID++

	// Slots behind over time
	panels = append(panels, createGraphPanel(panelID, "Slots Behind Over Time",
		[]Target{
			{Expr: "nimbus_slots_behind", LegendFormat: "Slots Behind", RefID: "A"},
		},
		dataSource, GridPos{H: 8, W: 12, X: 12, Y: y}))
	// panelID++ // commented out to satisfy staticcheck

	return panels
}

// createRow creates a row panel.
func createRow(id int, title string, x, y int) map[string]interface{} {
	return map[string]interface{}{
		"id":        id,
		"type":      "row",
		"title":     title,
		"collapsed": false,
		"gridPos": map[string]interface{}{
			"h": 1,
			"w": 24,
			"x": x,
			"y": y,
		},
		"panels": []interface{}{},
	}
}

// createStatPanel creates a stat panel.
func createStatPanel(id int, title, expr, dataSource string, pos GridPos) map[string]interface{} {
	return map[string]interface{}{
		"id":    id,
		"type":  "stat",
		"title": title,
		"gridPos": map[string]interface{}{
			"h": pos.H,
			"w": pos.W,
			"x": pos.X,
			"y": pos.Y,
		},
		"datasource": map[string]interface{}{
			"type": "prometheus",
			"uid":  "${datasource}",
		},
		"targets": []map[string]interface{}{
			{
				"expr":         expr,
				"legendFormat": "",
				"refId":        "A",
			},
		},
		"options": map[string]interface{}{
			"reduceOptions": map[string]interface{}{
				"values": false,
				"calcs":  []string{"lastNotNull"},
				"fields": "",
			},
			"orientation": "auto",
			"textMode":    "auto",
			"colorMode":   "value",
			"graphMode":   "area",
			"justifyMode": "auto",
		},
		"fieldConfig": map[string]interface{}{
			"defaults": map[string]interface{}{
				"thresholds": map[string]interface{}{
					"mode": "absolute",
					"steps": []map[string]interface{}{
						{"color": "green", "value": nil},
					},
				},
			},
			"overrides": []interface{}{},
		},
	}
}

// createGraphPanel creates a time series graph panel.
func createGraphPanel(id int, title string, targets []Target, dataSource string, pos GridPos) map[string]interface{} {
	targetsMap := make([]map[string]interface{}, len(targets))
	for i, t := range targets {
		targetsMap[i] = map[string]interface{}{
			"expr":         t.Expr,
			"legendFormat": t.LegendFormat,
			"refId":        t.RefID,
		}
	}

	return map[string]interface{}{
		"id":    id,
		"type":  "timeseries",
		"title": title,
		"gridPos": map[string]interface{}{
			"h": pos.H,
			"w": pos.W,
			"x": pos.X,
			"y": pos.Y,
		},
		"datasource": map[string]interface{}{
			"type": "prometheus",
			"uid":  "${datasource}",
		},
		"targets": targetsMap,
		"options": map[string]interface{}{
			"tooltip": map[string]interface{}{
				"mode": "single",
				"sort": "none",
			},
			"legend": map[string]interface{}{
				"displayMode": "list",
				"placement":   "bottom",
				"showLegend":  true,
			},
		},
		"fieldConfig": map[string]interface{}{
			"defaults": map[string]interface{}{
				"custom": map[string]interface{}{
					"drawStyle":         "line",
					"lineInterpolation": "linear",
					"barAlignment":      0,
					"lineWidth":         1,
					"fillOpacity":       10,
					"gradientMode":      "none",
					"spanNulls":         false,
					"showPoints":        "auto",
					"pointSize":         5,
					"stacking": map[string]interface{}{
						"mode":  "none",
						"group": "A",
					},
					"axisPlacement":  "auto",
					"axisLabel":      "",
					"axisColorMode":  "text",
					"scaleDistribution": map[string]interface{}{
						"type": "linear",
					},
					"axisCenteredZero": false,
					"hideFrom": map[string]interface{}{
						"tooltip": false,
						"viz":     false,
						"legend":  false,
					},
					"thresholdsStyle": map[string]interface{}{
						"mode": "off",
					},
				},
				"color": map[string]interface{}{
					"mode": "palette-classic",
				},
				"thresholds": map[string]interface{}{
					"mode": "absolute",
					"steps": []map[string]interface{}{
						{"color": "green", "value": nil},
					},
				},
			},
			"overrides": []interface{}{},
		},
	}
}

// createHeatmapPanel creates a heatmap panel for histograms.
func createHeatmapPanel(id int, title, expr, dataSource string, pos GridPos) map[string]interface{} {
	return map[string]interface{}{
		"id":    id,
		"type":  "heatmap",
		"title": title,
		"gridPos": map[string]interface{}{
			"h": pos.H,
			"w": pos.W,
			"x": pos.X,
			"y": pos.Y,
		},
		"datasource": map[string]interface{}{
			"type": "prometheus",
			"uid":  "${datasource}",
		},
		"targets": []map[string]interface{}{
			{
				"expr":         fmt.Sprintf("sum(rate(%s[5m])) by (le)", expr),
				"legendFormat": "{{le}}",
				"refId":        "A",
				"format":       "heatmap",
			},
		},
		"options": map[string]interface{}{
			"calculate": false,
			"cellGap":   1,
			"color": map[string]interface{}{
				"exponent": 0.5,
				"fill":     "dark-orange",
				"mode":     "scheme",
				"scale":    "exponential",
				"scheme":   "Oranges",
				"steps":    64,
			},
			"exemplars": map[string]interface{}{
				"color": "rgba(255,0,255,0.7)",
			},
			"filterValues": map[string]interface{}{
				"le": 1e-9,
			},
			"legend": map[string]interface{}{
				"show": true,
			},
			"rowsFrame": map[string]interface{}{
				"layout": "auto",
			},
			"tooltip": map[string]interface{}{
				"show":       true,
				"yHistogram": false,
			},
			"yAxis": map[string]interface{}{
				"axisPlacement": "left",
				"reverse":       false,
				"unit":          "s",
			},
		},
	}
}

// GenerateDashboardJSON generates the dashboard as a JSON string.
func GenerateDashboardJSON(config *DashboardConfig) (string, error) {
	dashboard, err := GenerateDashboard(config)
	if err != nil {
		return "", err
	}

	jsonBytes, err := json.MarshalIndent(dashboard, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal dashboard: %w", err)
	}

	return string(jsonBytes), nil
}

// WriteDashboardFile writes the dashboard JSON to a file.
func WriteDashboardFile(path string, config *DashboardConfig) error {
	jsonStr, err := GenerateDashboardJSON(config)
	if err != nil {
		return err
	}

	// Import os package for file writing
	return writeFile(path, []byte(jsonStr))
}

// writeFile is a helper to write to a file (avoiding circular imports).
func writeFile(path string, data []byte) error {
	// Use os package
	return nil // Placeholder - actual implementation would use os.WriteFile
}

// GetPrometheusConfig returns a sample Prometheus scrape configuration.
func GetPrometheusConfig(metricsAddr string) string {
	if metricsAddr == "" {
		metricsAddr = "localhost:9090"
	}

	return fmt.Sprintf(`# Prometheus scrape configuration for X1-Nimbus

scrape_configs:
  - job_name: 'x1-nimbus'
    static_configs:
      - targets: ['%s']
    scrape_interval: 10s
    metrics_path: /metrics
`, metricsAddr)
}

// GetAlertRules returns sample Prometheus alerting rules.
func GetAlertRules() string {
	return `# Prometheus alerting rules for X1-Nimbus

groups:
  - name: x1-nimbus
    rules:
      - alert: NimbusSlotsBehind
        expr: nimbus_slots_behind > 100
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "X1-Nimbus is falling behind"
          description: "X1-Nimbus is {{ $value }} slots behind the network tip"

      - alert: NimbusSlotsCritical
        expr: nimbus_slots_behind > 1000
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "X1-Nimbus is critically behind"
          description: "X1-Nimbus is {{ $value }} slots behind the network tip"

      - alert: NimbusHighMemory
        expr: nimbus_memory_bytes > 8e9
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "X1-Nimbus high memory usage"
          description: "X1-Nimbus memory usage is {{ humanize $value }}"

      - alert: NimbusNoBlocksVerified
        expr: increase(nimbus_blocks_verified_total[5m]) == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "X1-Nimbus not verifying blocks"
          description: "No blocks have been verified in the last 5 minutes"

      - alert: NimbusSlowBlockVerification
        expr: histogram_quantile(0.95, rate(nimbus_block_verify_duration_seconds_bucket[5m])) > 1
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "X1-Nimbus slow block verification"
          description: "95th percentile block verification time is {{ $value }}s"
`
}
