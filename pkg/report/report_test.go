package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/config"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/ledger"
)

func createSampleReportData() RunReportData {
	cfg := config.DefaultConfig()
	cfg.Destination.AuthToken = "secret-splunk-hec-token-998877"

	accounting := ledger.AccountingSnapshot{
		TotalGenerated:    100000,
		TotalNormal:       95000,
		TotalSuspicious:   5000,
		TotalEnqueued:     100000,
		TotalSubmitted:    100000,
		TotalAcknowledged: 99980,
		TotalRejected:     10,
		TotalFailed:       10,
		TotalDropped:      0,
		TotalRetries:      5,
		BySourceFamily: map[string]ledger.SourceBreakdown{
			"windows": {Generated: 40000, Acknowledged: 39990},
			"linux":   {Generated: 30000, Acknowledged: 29990},
			"paloalto":{Generated: 20000, Acknowledged: 20000},
			"bind9":   {Generated: 10000, Acknowledged: 10000},
		},
		ByScenario: map[string]uint64{
			"T1110.001": 2500,
			"T1046":     1500,
			"T1071.004": 1000,
		},
	}

	return RunReportData{
		RunID:            "RUN-20261112-TEST-001",
		SimulatorVersion: "1.0.0",
		StartTime:        time.Now().Add(-10 * time.Minute),
		EndTime:          time.Now(),
		Duration:         10 * time.Minute,
		TargetEPS:        100000,
		ActualEPS:        102450.5,
		TotalEndpoints:   100,
		ConfigSnapshot:   *cfg,
		Accounting:       accounting,
	}
}

func TestGenerateHTML(t *testing.T) {
	data := createSampleReportData()
	htmlBytes, err := GenerateHTML(data)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	html := string(htmlBytes)

	// Validate title and run ID
	if !strings.Contains(html, data.RunID) {
		t.Errorf("HTML does not contain RunID %s", data.RunID)
	}
	if !strings.Contains(html, "Spectra Manual Reconciliation Worksheet") {
		t.Error("HTML missing Spectra Reconciliation Worksheet section")
	}

	// Validate KPI metrics
	if !strings.Contains(html, "100000") {
		t.Error("HTML missing TotalGenerated count")
	}
	if !strings.Contains(html, "99980") {
		t.Error("HTML missing Acknowledged count")
	}

	// Verify completely offline (no external CDN links)
	if strings.Contains(html, "<script src=\"http") || strings.Contains(html, "<link rel=\"stylesheet\" href=\"http") {
		t.Error("HTML report must not load external scripts or styles over HTTP/S")
	}
}

func TestGenerateJSON(t *testing.T) {
	data := createSampleReportData()
	jsonBytes, err := GenerateJSON(data)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("failed to unmarshal generated JSON: %v", err)
	}

	if parsed["run_id"] != data.RunID {
		t.Errorf("expected run_id %s, got %v", data.RunID, parsed["run_id"])
	}

	// Verify secret redaction
	jsonStr := string(jsonBytes)
	if strings.Contains(jsonStr, "secret-splunk-hec-token-998877") {
		t.Error("sensitive token was NOT redacted in JSON report!")
	}
	if !strings.Contains(jsonStr, "***REDACTED***") {
		t.Error("redaction marker not found in JSON report")
	}
}

func TestGenerateCSV(t *testing.T) {
	data := createSampleReportData()
	csvBytes, err := GenerateCSV(data)
	if err != nil {
		t.Fatalf("GenerateCSV failed: %v", err)
	}

	csvStr := string(csvBytes)
	if !strings.Contains(csvStr, "RunID,RUN-20261112-TEST-001") {
		t.Error("CSV missing RunID header")
	}
	if !strings.Contains(csvStr, "# Spectra Reconciliation Worksheet") {
		t.Error("CSV missing Spectra Reconciliation Worksheet section")
	}
	if !strings.Contains(csvStr, "Windows Logon / Traffic") && !strings.Contains(csvStr, "Source: windows") {
		t.Error("CSV missing source breakdown rows")
	}
}

func TestWriteReportFiles(t *testing.T) {
	data := createSampleReportData()
	tmpDir := t.TempDir()

	if err := WriteReportFiles(tmpDir, data); err != nil {
		t.Fatalf("WriteReportFiles failed: %v", err)
	}

	files := []string{"report.html", "summary.json", "breakdown.csv"}
	for _, f := range files {
		p := filepath.Join(tmpDir, f)
		info, err := os.Stat(p)
		if err != nil {
			t.Errorf("expected file %s not found: %v", f, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("file %s is empty", f)
		}
	}
}
