package formatter

import (
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/buffer"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/fleet"
)

func sampleFirewallEndpoint() *fleet.Endpoint {
	return &fleet.Endpoint{
		ID:         "EP-FW-PERIM-0001",
		Hostname:   "pa-perim-fw01",
		Domain:     "corp.local",
		IP:         net.ParseIP("192.168.1.1"),
		IPStr:      "192.168.1.1",
		Role:       fleet.RoleFirewall,
		OSFamily:   "PAN-OS",
		OSVersion:  "11.0",
		Department: "Network Security",
	}
}

func sampleDNSEndpoint() *fleet.Endpoint {
	return &fleet.Endpoint{
		ID:         "EP-DNS-CORE-0001",
		Hostname:   "ns01.corp.local",
		Domain:     "corp.local",
		IP:         net.ParseIP("10.200.10.1"),
		IPStr:      "10.200.10.1",
		Role:       fleet.RoleDNSServer,
		OSFamily:   "Linux",
		OSVersion:  "Debian 12",
		Department: "Infrastructure",
	}
}

func TestPaloAltoTrafficCSV54Columns(t *testing.T) {
	formatter := NewPaloAltoFormatter()
	ep := sampleFirewallEndpoint()
	now := time.Date(2026, 11, 12, 4, 30, 0, 0, time.UTC)

	buf := buffer.GetBuffer()
	defer buf.Release()

	formatter.FormatTraffic(buf, ep, PaloAltoTrafficParams{
		Action:          "allow",
		SourceIP:        "10.100.1.15",
		DestinationIP:   "172.16.10.15",
		SourcePort:      54120,
		DestinationPort: 443,
		Application:     "ssl",
		SourceZone:      "trust",
		DestinationZone: "untrust",
		RuleName:        "Allow-Web-Outbound",
		BytesSent:       1000,
		BytesReceived:   5000,
		PacketsSent:     8,
		PacketsReceived: 12,
	}, 1082910, now)

	line := strings.TrimRight(buf.String(), "\n")
	cols := strings.Split(line, ",")

	if len(cols) != 54 {
		t.Fatalf("expected 54 CSV columns per PAN-OS specification, got %d\nLine:\n%s", len(cols), line)
	}

	// Validate key column indexes per Palo Alto specification
	if cols[0] != "1" {
		t.Errorf("col 0 (marker): expected '1', got '%s'", cols[0])
	}
	if cols[3] != "TRAFFIC" {
		t.Errorf("col 3 (type): expected 'TRAFFIC', got '%s'", cols[3])
	}
	if cols[4] != "allow" {
		t.Errorf("col 4 (subtype): expected 'allow', got '%s'", cols[4])
	}
	if cols[7] != "10.100.1.15" {
		t.Errorf("col 7 (src IP): expected '10.100.1.15', got '%s'", cols[7])
	}
	if cols[8] != "172.16.10.15" {
		t.Errorf("col 8 (dst IP): expected '172.16.10.15', got '%s'", cols[8])
	}
	if cols[11] != "Allow-Web-Outbound" {
		t.Errorf("col 11 (rule): expected 'Allow-Web-Outbound', got '%s'", cols[11])
	}
	if cols[14] != "ssl" {
		t.Errorf("col 14 (app): expected 'ssl', got '%s'", cols[14])
	}
	if cols[16] != "trust" {
		t.Errorf("col 16 (src zone): expected 'trust', got '%s'", cols[16])
	}
	if cols[17] != "untrust" {
		t.Errorf("col 17 (dst zone): expected 'untrust', got '%s'", cols[17])
	}
	if cols[24] != "54120" {
		t.Errorf("col 24 (src port): expected '54120', got '%s'", cols[24])
	}
	if cols[25] != "443" {
		t.Errorf("col 25 (dst port): expected '443', got '%s'", cols[25])
	}
	if cols[30] != "allow" {
		t.Errorf("col 30 (action): expected 'allow', got '%s'", cols[30])
	}
	if cols[31] != "6000" { // 1000 + 5000 total bytes
		t.Errorf("col 31 (total bytes): expected '6000', got '%s'", cols[31])
	}
	if cols[39] != "1082910" {
		t.Errorf("col 39 (seq): expected '1082910', got '%s'", cols[39])
	}
	if cols[52] != ep.Hostname {
		t.Errorf("col 52 (device name): expected '%s', got '%s'", ep.Hostname, cols[52])
	}
}

func TestPaloAltoThreatCSV(t *testing.T) {
	formatter := NewPaloAltoFormatter()
	ep := sampleFirewallEndpoint()
	now := time.Date(2026, 11, 12, 4, 30, 0, 0, time.UTC)

	buf := buffer.GetBuffer()
	defer buf.Release()

	formatter.FormatThreat(buf, ep, PaloAltoThreatParams{
		ThreatType:      "scan",
		ThreatID:        "99999(Port Scan detected)",
		Severity:        "medium",
		SourceIP:        "192.168.1.200",
		DestinationIP:   "10.200.10.15",
		SourcePort:      44123,
		DestinationPort: 80,
	}, 1082911, now)

	line := buf.String()
	if !strings.Contains(line, ",THREAT,") {
		t.Errorf("expected THREAT record, got: %s", line)
	}
	if !strings.Contains(line, "99999(Port Scan detected)") {
		t.Errorf("expected ThreatID in line, got: %s", line)
	}
	if !strings.Contains(line, ",medium,") {
		t.Errorf("expected medium severity, got: %s", line)
	}
}

func TestBIND9QueryFormat(t *testing.T) {
	formatter := NewBIND9Formatter()
	ep := sampleDNSEndpoint()
	now := time.Date(2026, 11, 12, 4, 30, 0, 123000000, time.UTC)

	// Standard Query
	buf := buffer.GetBuffer()
	formatter.FormatQuery(buf, ep, DNSQueryParams{
		ClientIP:   "10.100.1.15",
		ClientPort: 51920,
		Domain:     "portal.corp.local",
		RecordType: "A",
		ServerIP:   "10.200.10.1",
		Status:     "OK",
	}, now)

	line := buf.String()
	buf.Release()

	expected := "12-Nov-2026 04:30:00.123 client @0x7f481014a000 10.100.1.15#51920 (portal.corp.local): query: portal.corp.local IN A + (10.200.10.1)\n"
	if line != expected {
		t.Fatalf("expected:\n%s\ngot:\n%s", expected, line)
	}

	// NXDOMAIN
	buf = buffer.GetBuffer()
	formatter.FormatQuery(buf, ep, DNSQueryParams{
		ClientIP:   "10.100.1.15",
		ClientPort: 51920,
		Domain:     "invalid.corp.local",
		RecordType: "A",
		ServerIP:   "10.200.10.1",
		Status:     "NXDOMAIN",
	}, now)

	line = buf.String()
	buf.Release()

	expectedSub := "12-Nov-2026 04:30:00.123 client @0x7f481014a000 10.100.1.15#51920 (invalid.corp.local): query failed (NXDOMAIN) for invalid.corp.local/IN/A at 10.200.10.1\n"
	if line != expectedSub {
		t.Fatalf("expected:\n%s\ngot:\n%s", expectedSub, line)
	}
}

func TestRandomFirewallAndDNS(t *testing.T) {
	fwFmt := NewPaloAltoFormatter()
	dnsFmt := NewBIND9Formatter()
	fwEP := sampleFirewallEndpoint()
	dnsEP := sampleDNSEndpoint()
	now := time.Now().UTC()
	rng := rand.New(rand.NewSource(112233))

	for i := 0; i < 200; i++ {
		buf := buffer.GetBuffer()
		fwFmt.FormatRandomFirewallEvent(buf, fwEP, uint64(i+1), now, rng)
		if buf.Len() == 0 {
			t.Fatalf("empty firewall record on run %d", i)
		}
		buf.Release()

		buf = buffer.GetBuffer()
		dnsFmt.FormatRandomDNSQuery(buf, dnsEP, now, rng)
		if buf.Len() == 0 {
			t.Fatalf("empty DNS record on run %d", i)
		}
		buf.Release()
	}
}

func BenchmarkPaloAltoTrafficCSV(b *testing.B) {
	formatter := NewPaloAltoFormatter()
	ep := sampleFirewallEndpoint()
	now := time.Now().UTC()
	params := PaloAltoTrafficParams{
		Action:          "allow",
		SourceIP:        "10.100.1.15",
		DestinationIP:   "172.16.10.15",
		SourcePort:      54120,
		DestinationPort: 443,
		Application:     "ssl",
		SourceZone:      "trust",
		DestinationZone: "untrust",
		RuleName:        "Allow-Web-Outbound",
		BytesSent:       1000,
		BytesReceived:   5000,
		PacketsSent:     8,
		PacketsReceived: 12,
	}

	var i uint64
	for b.Loop() {
		buf := buffer.GetBuffer()
		formatter.FormatTraffic(buf, ep, params, i, now)
		buf.Release()
		i++
	}
}

func BenchmarkBIND9Query(b *testing.B) {
	formatter := NewBIND9Formatter()
	ep := sampleDNSEndpoint()
	now := time.Now().UTC()
	params := DNSQueryParams{
		ClientIP:   "10.100.1.15",
		ClientPort: 51920,
		Domain:     "portal.corp.local",
		RecordType: "A",
		ServerIP:   "10.200.10.1",
		Status:     "OK",
	}

	for b.Loop() {
		buf := buffer.GetBuffer()
		formatter.FormatQuery(buf, ep, params, now)
		buf.Release()
	}
}
