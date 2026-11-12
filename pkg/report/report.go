package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/config"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/ledger"
)

// RunReportData contains all metadata, configuration, and ledger metrics for post-run reporting.
type RunReportData struct {
	RunID            string                    `json:"run_id"`
	SimulatorVersion string                    `json:"simulator_version"`
	StartTime        time.Time                 `json:"start_time"`
	EndTime          time.Time                 `json:"end_time"`
	Duration         time.Duration             `json:"duration_seconds"`
	TargetEPS        int                       `json:"target_eps"`
	ActualEPS        float64                   `json:"actual_eps"`
	TotalEndpoints   int                       `json:"total_endpoints"`
	ConfigSnapshot   config.Config             `json:"config"`
	Accounting       ledger.AccountingSnapshot `json:"accounting"`
}

// WorksheetRow represents an audit row in the Spectra manual reconciliation table.
type WorksheetRow struct {
	Category       string `json:"category"`
	Metric         string `json:"metric"`
	GroundTruth    uint64 `json:"ground_truth"`
	SpectraMapping string `json:"spectra_mapping"`
	Notes          string `json:"notes"`
}

// BuildWorksheetRows generates standardized reconciliation rows for manual verification.
func BuildWorksheetRows(data RunReportData) []WorksheetRow {
	rows := []WorksheetRow{
		{
			Category:       "High-Level Intake",
			Metric:         "Total Telemetry Events",
			GroundTruth:    data.Accounting.TotalAcknowledged,
			SpectraMapping: "count() overall in index=telemetry",
			Notes:          "Total events acknowledged by Spectra forwarder",
		},
		{
			Category:       "Classification",
			Metric:         "Normal Enterprise Traffic",
			GroundTruth:    data.Accounting.TotalNormal,
			SpectraMapping: "tag=normal or class=benign",
			Notes:          "Routine user and background system activity",
		},
		{
			Category:       "Classification",
			Metric:         "Suspicious / MITRE ATT&CK Activity",
			GroundTruth:    data.Accounting.TotalSuspicious,
			SpectraMapping: "tag=suspicious or class=threat",
			Notes:          "Adversary emulation scenario telemetry",
		},
	}

	// Add Source Family rows
	for source, stats := range data.Accounting.BySourceFamily {
		rows = append(rows, WorksheetRow{
			Category:       "Source Family",
			Metric:         fmt.Sprintf("Source: %s", source),
			GroundTruth:    stats.Acknowledged,
			SpectraMapping: fmt.Sprintf("source_type=%s", source),
			Notes:          fmt.Sprintf("Confirmed receipt for %s", source),
		})
	}

	// Add MITRE ATT&CK scenario rows
	for scenario, count := range data.Accounting.ByScenario {
		rows = append(rows, WorksheetRow{
			Category:       "MITRE ATT&CK",
			Metric:         fmt.Sprintf("Scenario %s", scenario),
			GroundTruth:    count,
			SpectraMapping: fmt.Sprintf("mitre_technique=%s", scenario),
			Notes:          "Correlated multi-step attack sequence events",
		})
	}

	return rows
}

// RedactSecrets returns a sanitized copy of configuration with passwords and tokens masked.
func RedactSecrets(cfg config.Config) config.Config {
	sanitized := cfg
	if sanitized.Destination.AuthToken != "" {
		sanitized.Destination.AuthToken = "***REDACTED***"
	}
	return sanitized
}

// GenerateJSON produces an immutable machine-readable JSON summary of the run.
func GenerateJSON(data RunReportData) ([]byte, error) {
	data.ConfigSnapshot = RedactSecrets(data.ConfigSnapshot)
	return json.MarshalIndent(data, "", "  ")
}

// GenerateCSV generates a multi-section spreadsheet breakdown.
func GenerateCSV(data RunReportData) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	// Header: Run Metadata
	_ = w.Write([]string{"# SOC Telemetry Simulator Run Report"})
	_ = w.Write([]string{"RunID", data.RunID})
	_ = w.Write([]string{"Version", data.SimulatorVersion})
	_ = w.Write([]string{"StartTime", data.StartTime.Format(time.RFC3339)})
	_ = w.Write([]string{"EndTime", data.EndTime.Format(time.RFC3339)})
	_ = w.Write([]string{"DurationSec", fmt.Sprintf("%.2f", data.Duration.Seconds())})
	_ = w.Write([]string{"TargetEPS", strconv.Itoa(data.TargetEPS)})
	_ = w.Write([]string{"ActualEPS", fmt.Sprintf("%.2f", data.ActualEPS)})
	_ = w.Write([]string{""})

	// Section: Delivery State Accounting
	_ = w.Write([]string{"# Delivery State Accounting", "Count"})
	_ = w.Write([]string{"Generated", strconv.FormatUint(data.Accounting.TotalGenerated, 10)})
	_ = w.Write([]string{"Normal", strconv.FormatUint(data.Accounting.TotalNormal, 10)})
	_ = w.Write([]string{"Suspicious", strconv.FormatUint(data.Accounting.TotalSuspicious, 10)})
	_ = w.Write([]string{"Enqueued", strconv.FormatUint(data.Accounting.TotalEnqueued, 10)})
	_ = w.Write([]string{"Submitted", strconv.FormatUint(data.Accounting.TotalSubmitted, 10)})
	_ = w.Write([]string{"Acknowledged", strconv.FormatUint(data.Accounting.TotalAcknowledged, 10)})
	_ = w.Write([]string{"Rejected", strconv.FormatUint(data.Accounting.TotalRejected, 10)})
	_ = w.Write([]string{"Failed", strconv.FormatUint(data.Accounting.TotalFailed, 10)})
	_ = w.Write([]string{"Dropped", strconv.FormatUint(data.Accounting.TotalDropped, 10)})
	_ = w.Write([]string{"Retries", strconv.FormatUint(data.Accounting.TotalRetries, 10)})
	_ = w.Write([]string{""})

	// Section: Spectra Reconciliation Worksheet
	_ = w.Write([]string{"# Spectra Reconciliation Worksheet"})
	_ = w.Write([]string{"Category", "Metric", "GroundTruth", "SpectraObserved", "Discrepancy", "SpectraMapping", "Notes"})

	rows := BuildWorksheetRows(data)
	for _, r := range rows {
		_ = w.Write([]string{
			r.Category,
			r.Metric,
			strconv.FormatUint(r.GroundTruth, 10),
			"", // Blank for operator manual entry
			"", // Blank for calculated discrepancy
			r.SpectraMapping,
			r.Notes,
		})
	}

	w.Flush()
	return buf.Bytes(), w.Error()
}

// HTMLReportTemplate is a self-contained, responsive, offline-ready HTML report.
const HTMLReportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Simulation Report & Spectra Reconciliation — {{.RunID}}</title>
<style>
  :root {
    --bg: #0f172a;
    --card-bg: #1e293b;
    --card-border: #334155;
    --text-primary: #f8fafc;
    --text-secondary: #94a3b8;
    --accent: #38bdf8;
    --green: #22c55e;
    --yellow: #eab308;
    --red: #ef4444;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  body { background: var(--bg); color: var(--text-primary); padding: 30px 20px; line-height: 1.5; }
  .container { max-width: 1200px; margin: 0 auto; }
  header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid var(--card-border); padding-bottom: 20px; margin-bottom: 30px; }
  .logo h1 { font-size: 24px; color: var(--text-primary); }
  .logo p { font-size: 13px; color: var(--text-secondary); }
  .badge { padding: 4px 12px; border-radius: 9999px; font-size: 12px; font-weight: 600; text-transform: uppercase; background: rgba(34, 197, 94, 0.2); color: var(--green); border: 1px solid var(--green); }
  
  .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 20px; margin-bottom: 30px; }
  .kpi-card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 8px; padding: 20px; }
  .kpi-title { font-size: 13px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px; }
  .kpi-value { font-size: 32px; font-weight: 700; color: var(--text-primary); }
  .kpi-sub { font-size: 12px; color: var(--accent); margin-top: 4px; }
  
  .section { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 8px; padding: 24px; margin-bottom: 30px; }
  .section h2 { font-size: 18px; margin-bottom: 16px; border-bottom: 1px solid var(--card-border); padding-bottom: 8px; color: var(--accent); }
  
  table { width: 100%; border-collapse: collapse; font-size: 14px; text-align: left; }
  th { background: rgba(51, 65, 85, 0.5); padding: 12px 14px; color: var(--text-secondary); font-weight: 600; }
  td { padding: 12px 14px; border-bottom: 1px solid var(--card-border); }
  tr:last-child td { border-bottom: none; }
  
  .input-spectra { background: #0f172a; border: 1px solid var(--card-border); color: #fff; padding: 6px 10px; border-radius: 4px; width: 130px; font-size: 14px; font-weight: 600; }
  .input-spectra:focus { border-color: var(--accent); outline: none; }
  .delta-pill { font-weight: 700; padding: 2px 8px; border-radius: 4px; font-size: 12px; }
  .match { background: rgba(34, 197, 94, 0.15); color: var(--green); }
  .discrepancy { background: rgba(239, 68, 68, 0.15); color: var(--red); }
  .pending { color: var(--text-secondary); }
  
  .footer-note { font-size: 12px; color: var(--text-secondary); text-align: center; margin-top: 40px; }
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="logo">
      <h1>SOC Telemetry Simulator</h1>
      <p>Post-Run Audit & Spectra SIEM Manual Reconciliation Worksheet | Run ID: {{.RunID}}</p>
    </div>
    <div class="badge">Run Completed</div>
  </header>

  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-title">Total Generated</div>
      <div class="kpi-value">{{.Accounting.TotalGenerated}}</div>
      <div class="kpi-sub">Exact simulator ground truth</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">Acknowledged by Spectra</div>
      <div class="kpi-value">{{.Accounting.TotalAcknowledged}}</div>
      <div class="kpi-sub">{{.Accounting.TotalSubmitted}} submitted to wire</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">Observed Throughput</div>
      <div class="kpi-value">{{printf "%.0f" .ActualEPS}} EPS</div>
      <div class="kpi-sub">Target: {{.TargetEPS}} EPS</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">Adversary Activity</div>
      <div class="kpi-value">{{.Accounting.TotalSuspicious}}</div>
      <div class="kpi-sub">MITRE ATT&CK scenarios</div>
    </div>
  </div>

  <div class="section">
    <h2>1. Delivery Lifecycle State Accounting</h2>
    <table>
      <thead>
        <tr><th>Lifecycle State</th><th>Count</th><th>Ratio</th><th>Description</th></tr>
      </thead>
      <tbody>
        <tr><td>Generated</td><td>{{.Accounting.TotalGenerated}}</td><td>100.0%</td><td>Total raw events generated by fleet</td></tr>
        <tr><td>Normal Traffic</td><td>{{.Accounting.TotalNormal}}</td><td>{{printf "%.1f" (ratio .Accounting.TotalNormal .Accounting.TotalGenerated)}}%</td><td>Benign enterprise background logs</td></tr>
        <tr><td>Suspicious / Threat</td><td>{{.Accounting.TotalSuspicious}}</td><td>{{printf "%.1f" (ratio .Accounting.TotalSuspicious .Accounting.TotalGenerated)}}%</td><td>ATT&CK scenario traffic</td></tr>
        <tr><td>Enqueued</td><td>{{.Accounting.TotalEnqueued}}</td><td>{{printf "%.1f" (ratio .Accounting.TotalEnqueued .Accounting.TotalGenerated)}}%</td><td>Events buffered in transmission queue</td></tr>
        <tr><td>Submitted</td><td>{{.Accounting.TotalSubmitted}}</td><td>{{printf "%.1f" (ratio .Accounting.TotalSubmitted .Accounting.TotalGenerated)}}%</td><td>Events transmitted over network wire</td></tr>
        <tr><td>Acknowledged</td><td>{{.Accounting.TotalAcknowledged}}</td><td>{{printf "%.1f" (ratio .Accounting.TotalAcknowledged .Accounting.TotalGenerated)}}%</td><td>Confirmed received by Spectra (HTTP 200 / TCP ACK)</td></tr>
        <tr><td>Rejected</td><td>{{.Accounting.TotalRejected}}</td><td>{{printf "%.1f" (ratio .Accounting.TotalRejected .Accounting.TotalGenerated)}}%</td><td>Rejected by receiver (HTTP 4xx / auth failure)</td></tr>
        <tr><td>Failed</td><td>{{.Accounting.TotalFailed}}</td><td>{{printf "%.1f" (ratio .Accounting.TotalFailed .Accounting.TotalGenerated)}}%</td><td>Transmission failures (HTTP 5xx / socket drop)</td></tr>
        <tr><td>Dropped</td><td>{{.Accounting.TotalDropped}}</td><td>{{printf "%.1f" (ratio .Accounting.TotalDropped .Accounting.TotalGenerated)}}%</td><td>Evicted locally under backpressure saturation</td></tr>
        <tr><td>Retries</td><td>{{.Accounting.TotalRetries}}</td><td>N/A</td><td>Network retry attempts (does not inflate generated count)</td></tr>
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>2. Spectra Manual Reconciliation Worksheet</h2>
    <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 16px;">
      Query Spectra using the suggested filter queries below, enter the observed event count into each box, and verify ground truth matches.
    </p>
    <table id="worksheet">
      <thead>
        <tr>
          <th>Category</th>
          <th>Metric / Description</th>
          <th>Simulator Ground Truth</th>
          <th>Spectra Observed Count</th>
          <th>Discrepancy (Δ)</th>
          <th>Spectra Query / Field Mapping</th>
        </tr>
      </thead>
      <tbody>
        {{range $i, $row := .WorksheetRows}}
        <tr>
          <td><span style="font-weight: 600; color: var(--text-secondary);">{{$row.Category}}</span></td>
          <td>{{$row.Metric}}</td>
          <td id="gt-{{$i}}" style="font-weight: 700; color: var(--accent);">{{$row.GroundTruth}}</td>
          <td>
            <input type="number" class="input-spectra" id="input-{{$i}}" placeholder="Enter count..." oninput="reconcile({{$i}}, {{$row.GroundTruth}})">
          </td>
          <td>
            <span class="delta-pill pending" id="delta-{{$i}}">— Pending</span>
          </td>
          <td style="font-family: monospace; font-size: 12px; color: #cbd5e1;">{{$row.SpectraMapping}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
  </div>

  <div class="footer-note">
    SOC Telemetry Simulator v{{.SimulatorVersion}} | Report Generated: {{.EndTime.Format "2006-01-02 15:04:05 MST"}} | Zero External Dependencies
  </div>
</div>

<script>
function reconcile(idx, groundTruth) {
  const input = document.getElementById('input-' + idx);
  const pill = document.getElementById('delta-' + idx);
  if (!input.value || input.value.trim() === '') {
    pill.className = 'delta-pill pending';
    pill.innerText = '— Pending';
    return;
  }
  const observed = parseInt(input.value, 10);
  const delta = observed - groundTruth;
  if (delta === 0) {
    pill.className = 'delta-pill match';
    pill.innerText = '✓ Exact Match';
  } else if (delta > 0) {
    pill.className = 'delta-pill discrepancy';
    pill.innerText = '+' + delta + ' (Over-count)';
  } else {
    pill.className = 'delta-pill discrepancy';
    pill.innerText = delta + ' (Missing events)';
  }
}
</script>
</body>
</html>
`

// GenerateHTML renders the interactive self-contained HTML report.
func GenerateHTML(data RunReportData) ([]byte, error) {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"ratio": func(val, total uint64) float64 {
			if total == 0 {
				return 0
			}
			return (float64(val) / float64(total)) * 100.0
		},
	}).Parse(HTMLReportTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML template: %w", err)
	}

	worksheetRows := BuildWorksheetRows(data)

	type templateContext struct {
		RunReportData
		WorksheetRows []WorksheetRow
	}

	ctx := templateContext{
		RunReportData: data,
		WorksheetRows: worksheetRows,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ctx); err != nil {
		return nil, fmt.Errorf("failed to execute HTML template: %w", err)
	}

	return buf.Bytes(), nil
}

// WriteReportFiles exports all three artifact formats (report.html, summary.json, breakdown.csv) to disk.
func WriteReportFiles(outputDir string, data RunReportData) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create report output dir: %w", err)
	}

	// 1. Write HTML
	htmlBytes, err := GenerateHTML(data)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outputDir, "report.html"), htmlBytes, 0644); err != nil {
		return err
	}

	// 2. Write JSON
	jsonBytes, err := GenerateJSON(data)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outputDir, "summary.json"), jsonBytes, 0644); err != nil {
		return err
	}

	// 3. Write CSV
	csvBytes, err := GenerateCSV(data)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outputDir, "breakdown.csv"), csvBytes, 0644)
}
