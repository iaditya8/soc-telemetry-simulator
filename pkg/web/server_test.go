package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/config"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/fleet"
)

func setupTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	tmpDir := t.TempDir()

	cfg := ServerConfig{
		BindAddr:   "127.0.0.1:0", // Dynamic port for testing
		ReportsDir: tmpDir,
	}

	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("failed to create test server: %v", err)
	}

	if err := s.Start(); err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}

	t.Cleanup(func() {
		_ = s.Shutdown(context.Background())
	})

	return s, tmpDir
}

func TestSecurityLoopbackBinding(t *testing.T) {
	// Attempt to bind to 0.0.0.0
	_, err := NewServer(ServerConfig{BindAddr: "0.0.0.0:8080"})
	if err == nil {
		t.Error("expected security violation error binding to 0.0.0.0, got nil")
	}

	// Attempt to bind to non-localhost IP
	_, err = NewServer(ServerConfig{BindAddr: "192.168.1.100:8080"})
	if err == nil {
		t.Error("expected security violation error binding to 192.168.1.100, got nil")
	}

	// Loopback bindings should succeed
	s, err := NewServer(ServerConfig{BindAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("expected loopback bind to succeed, got %v", err)
	}
	_ = s.Shutdown(context.Background())
}

func TestEmbeddedUIFiles(t *testing.T) {
	s, _ := setupTestServer(t)
	baseURL := s.URL()

	endpoints := []struct {
		path         string
		expectedCode int
		contains     string
	}{
		{"/", http.StatusOK, "SOC Telemetry Simulator"},
		{"/index.html", http.StatusOK, "SOC Telemetry Simulator"},
		{"/style.css", http.StatusOK, "--bg-dark"},
		{"/app.js", http.StatusOK, "DOMContentLoaded"},
	}

	for _, ep := range endpoints {
		resp, err := http.Get(baseURL + ep.path)
		if err != nil {
			t.Fatalf("GET %s failed: %v", ep.path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode != ep.expectedCode {
			t.Errorf("GET %s returned status %d, expected %d", ep.path, resp.StatusCode, ep.expectedCode)
		}
		if !strings.Contains(string(body), ep.contains) {
			t.Errorf("GET %s body does not contain %q", ep.path, ep.contains)
		}
	}
}

func TestHandleHealth(t *testing.T) {
	s, _ := setupTestServer(t)

	resp, err := http.Get(s.URL() + "/api/health")
	if err != nil {
		t.Fatalf("GET /api/health failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("failed to decode health response: %v", err)
	}

	if data["status"] != "ok" {
		t.Errorf("expected status 'ok', got %v", data["status"])
	}
	if data["run_state"] != string(StateIdle) {
		t.Errorf("expected run_state IDLE, got %v", data["run_state"])
	}
	if data["version"] != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %v", data["version"])
	}
}

func TestHandleFleet(t *testing.T) {
	s, _ := setupTestServer(t)

	// Default fleet should have endpoints
	resp, err := http.Get(s.URL() + "/api/fleet?limit=10&offset=0")
	if err != nil {
		t.Fatalf("GET /api/fleet failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var data struct {
		Total     int               `json:"total"`
		Limit     int               `json:"limit"`
		Offset    int               `json:"offset"`
		Endpoints []*fleet.Endpoint `json:"endpoints"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("failed to decode fleet response: %v", err)
	}

	if data.Total == 0 {
		t.Error("expected non-zero total endpoints")
	}
	if len(data.Endpoints) > 10 {
		t.Errorf("expected at most 10 endpoints, got %d", len(data.Endpoints))
	}
}

func TestHandleFleetBulk(t *testing.T) {
	s, _ := setupTestServer(t)

	bulkReq := BulkFleetRequest{
		Count: 25,
		Distribution: &config.EndpointDistribution{
			WindowsWorkstations: 80,
			LinuxServers:        20,
		},
		Seed: 12345,
	}
	bodyBytes, _ := json.Marshal(bulkReq)

	resp, err := http.Post(s.URL()+"/api/fleet/bulk", "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("POST /api/fleet/bulk failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	// Verify fleet count updated
	fleetResp, err := http.Get(s.URL() + "/api/fleet?limit=100")
	if err != nil {
		t.Fatalf("GET /api/fleet failed: %v", err)
	}
	defer fleetResp.Body.Close()

	var data struct {
		Total int `json:"total"`
	}
	_ = json.NewDecoder(fleetResp.Body).Decode(&data)
	if data.Total != 25 {
		t.Errorf("expected 25 endpoints after bulk creation, got %d", data.Total)
	}
}

func TestHandleCatalog(t *testing.T) {
	s, _ := setupTestServer(t)

	resp, err := http.Get(s.URL() + "/api/catalog")
	if err != nil {
		t.Fatalf("GET /api/catalog failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var catalog map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		t.Fatalf("failed to decode catalog response: %v", err)
	}

	sources, ok := catalog["sources"].([]any)
	if !ok || len(sources) < 4 {
		t.Errorf("expected at least 4 source families in catalog, got %v", len(sources))
	}

	scenarios, ok := catalog["scenarios"].([]any)
	if !ok || len(scenarios) < 4 {
		t.Errorf("expected at least 4 ATT&CK scenarios in catalog, got %v", len(scenarios))
	}
}

func TestHandleRunLifecycle(t *testing.T) {
	s, reportsDir := setupTestServer(t)

	// 1. Stop when idle should fail (400)
	respStop, err := http.Post(s.URL()+"/api/run/stop", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("POST /api/run/stop failed: %v", err)
	}
	_ = respStop.Body.Close()
	if respStop.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 stopping idle run, got %d", respStop.StatusCode)
	}

	// 2. Start run
	startCfg := config.DefaultConfig()
	startCfg.Simulation.TargetEPS = 500
	startCfg.Simulation.DurationSeconds = 60
	bodyBytes, _ := json.Marshal(startCfg)

	respStart, err := http.Post(s.URL()+"/api/run/start", "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("POST /api/run/start failed: %v", err)
	}
	defer respStart.Body.Close()

	if respStart.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 starting run, got %d", respStart.StatusCode)
	}

	// 3. Start while already running should fail (409 Conflict)
	respConflict, err := http.Post(s.URL()+"/api/run/start", "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("POST /api/run/start conflict check failed: %v", err)
	}
	_ = respConflict.Body.Close()
	if respConflict.StatusCode != http.StatusConflict {
		t.Errorf("expected status 409 starting already running simulation, got %d", respConflict.StatusCode)
	}

	// 4. Verify status is RUNNING
	healthResp, _ := http.Get(s.URL() + "/api/health")
	var healthData map[string]any
	_ = json.NewDecoder(healthResp.Body).Decode(&healthData)
	_ = healthResp.Body.Close()
	if healthData["run_state"] != string(StateRunning) {
		t.Errorf("expected run_state RUNNING, got %v", healthData["run_state"])
	}

	// Wait briefly for worker progress
	time.Sleep(250 * time.Millisecond)

	// 5. Stop run
	respStop2, err := http.Post(s.URL()+"/api/run/stop", "application/json", strings.NewReader(`{"force":false}`))
	if err != nil {
		t.Fatalf("POST /api/run/stop failed: %v", err)
	}
	defer respStop2.Body.Close()

	if respStop2.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 stopping run, got %d", respStop2.StatusCode)
	}

	// 6. Verify reports generated in reportsDir
	reportHTML := filepath.Join(reportsDir, "report.html")
	if _, err := os.Stat(reportHTML); err != nil {
		t.Errorf("expected report.html to be written to %s, got err %v", reportsDir, err)
	}
}

func TestHandlePreflight(t *testing.T) {
	s, _ := setupTestServer(t)

	// 1. Preflight on mock TCP listener (Success)
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock listener: %v", err)
	}
	defer tcpListener.Close()

	preflightReq := PreflightRequest{
		Type:      "tcp",
		Address:   tcpListener.Addr().String(),
		TimeoutMS: 1000,
	}
	body, _ := json.Marshal(preflightReq)

	resp, err := http.Post(s.URL()+"/api/preflight", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/preflight failed: %v", err)
	}
	defer resp.Body.Close()

	var resData map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&resData)
	if resData["success"] != true {
		t.Errorf("expected preflight success true, got %v", resData["success"])
	}

	// 2. Preflight on non-existent destination (Failure)
	preflightReqFail := PreflightRequest{
		Type:      "tcp",
		Address:   "127.0.0.1:54321",
		TimeoutMS: 500,
	}
	bodyFail, _ := json.Marshal(preflightReqFail)

	respFail, err := http.Post(s.URL()+"/api/preflight", "application/json", bytes.NewReader(bodyFail))
	if err != nil {
		t.Fatalf("POST /api/preflight failed: %v", err)
	}
	defer respFail.Body.Close()

	var resDataFail map[string]any
	_ = json.NewDecoder(respFail.Body).Decode(&resDataFail)
	if resDataFail["success"] != false {
		t.Errorf("expected preflight success false for closed port, got %v", resDataFail["success"])
	}
}

func TestHandleReportsAndDownload(t *testing.T) {
	s, reportsDir := setupTestServer(t)

	// Create dummy test report
	testReport := filepath.Join(reportsDir, "test_report.html")
	_ = os.WriteFile(testReport, []byte("<html><body>Audit Report</body></html>"), 0644)

	// 1. List reports
	resp, err := http.Get(s.URL() + "/api/reports")
	if err != nil {
		t.Fatalf("GET /api/reports failed: %v", err)
	}
	defer resp.Body.Close()

	var reports []ReportMeta
	if err := json.NewDecoder(resp.Body).Decode(&reports); err != nil {
		t.Fatalf("failed to decode reports response: %v", err)
	}
	if len(reports) == 0 {
		t.Fatal("expected at least 1 report in list")
	}

	// 2. Download valid report
	respDown, err := http.Get(s.URL() + "/api/reports/download?name=test_report.html")
	if err != nil {
		t.Fatalf("GET /api/reports/download failed: %v", err)
	}
	body, _ := io.ReadAll(respDown.Body)
	_ = respDown.Body.Close()

	if respDown.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", respDown.StatusCode)
	}
	if !strings.Contains(string(body), "Audit Report") {
		t.Errorf("unexpected report content: %s", string(body))
	}

	// 3. Security: Prevent directory traversal
	respTraversal, err := http.Get(s.URL() + "/api/reports/download?name=../server.go")
	if err != nil {
		t.Fatalf("GET /api/reports/download failed: %v", err)
	}
	_ = respTraversal.Body.Close()
	if respTraversal.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for path traversal attempt, got %d", respTraversal.StatusCode)
	}
}
